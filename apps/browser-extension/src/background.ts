// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// Service Worker：持有与 Keevo 的加密会话（spec/ipc.md）。
//
// - 协议逻辑全部在 WASM 中（crates/keevo-wasm，与桌面应用共用同一份 Rust 实现），配对码的词表也在其中；
// - 这里只负责收发 Native Messaging 帧、保存扩展静态密钥与服务公钥、响应弹窗的请求；
// - 填充与复制时，页面与帧的网址取自 Chrome（tabs API 与消息的 sender），不采信页面或弹窗的自述；
// - 凭据只发给发起填充的那个帧（frameId），由内容脚本（content.js）核对来源后填入；
// - 复制的秘密在 90 秒后清除，且只在剪贴板仍是 Keevo 写入的值时才清除（docs/ux.md §5）；
// - 页内菜单（menu.html）只拿到条目概要；
// - 协议 v2（spec/ipc.md §5.5）：用户提交登录表单后，在保存栏（bar.html）中询问保存或更新。
//   提交的密码只留在这里的内存中（不写入 chrome.storage），3 分钟后丢弃；
// - 协议 v3（spec/ipc.md §5.6）：弹窗搜索全部条目、在 Keevo 中打开、请求解锁。Keevo 中允许搜索或解锁后会回到浏览器，
//   这里随之重新打开弹窗；Keevo 不支持某个版本时逐级退回。

import { t } from "./i18n.js";
import init, { KeevoClient, generatePassword } from "./wasm/keevo_wasm.js";
import type {
  BarRequest,
  BarResponse,
  Candidate,
  ContentRequest,
  MenuInit,
  MenuRequest,
  MenuResponse,
  OffscreenRequest,
  PopupRequest,
  PopupResponse,
  Recipe,
  SasWord,
  Secret,
  ServerMessage,
  ViewState,
} from "./types.js";

const NATIVE_HOST = "io.github.xiaoowen.keevo";
const REQUEST_TIMEOUT_MS = 10_000;
/** fill 第一次在某个网站上使用某个条目时，要等用户在 Keevo 中确认（最长 60 秒，spec/ipc.md §5.2）。 */
const FILL_TIMEOUT_MS = 70_000;
/** 这个浏览器在 Keevo 中的默认显示名。 */
const DEFAULT_NAME = "Chrome";
/** 复制的秘密在剪贴板中保留的时间（docs/ux.md §5）。 */
const CLIPBOARD_CLEAR_MS = 90_000;
const CLEAR_ALARM = "keevo-clear-clipboard";
/** 标准模式需要的网站权限：在输入框旁显示图标与页内菜单（可选权限，用户在弹窗中开启）。 */
const SITE_ORIGINS = ["https://*/*", "http://*/*"];
const CONTENT_SCRIPT_ID = "keevo-inline";

interface Stored {
  extKey?: string;
  servicePublic?: string;
  name?: string;
}

let state: ViewState = { status: "idle" };
let port: chrome.runtime.Port | null = null;
let client: KeevoClient | null = null;
/** 协商用的协议版本：默认最新；Keevo 回答 unsupported_version 时逐级退回（Service Worker 重启后重新尝试）。 */
let protocolVersion: number | undefined;
/** 弹窗关闭后，在 Keevo 中完成解锁或搜索允许时重新打开弹窗的时限。 */
const REOPEN_WINDOW_MS = 2 * 60_000;
const pending = new Map<number, (m: ServerMessage | null) => void>();
const ready = init({ module_or_path: chrome.runtime.getURL("wasm/keevo_wasm_bg.wasm") });

async function stored(): Promise<Stored> {
  return (await chrome.storage.local.get(["extKey", "servicePublic", "name"])) as Stored;
}

function send(frame: string): void {
  port?.postMessage(JSON.parse(frame));
}

function teardown(next: ViewState): void {
  port?.disconnect();
  port = null;
  client?.free();
  client = null;
  for (const resolve of pending.values()) resolve(null);
  pending.clear();
  state = next;
}

async function connect(mode: "pair" | "session"): Promise<void> {
  await ready;
  teardown({ status: "connecting" });
  const { extKey, servicePublic, name } = await stored();
  if (mode === "session" && !servicePublic) {
    state = { status: "unpaired" };
    return;
  }
  const c = new KeevoClient(extKey, `chrome-extension://${chrome.runtime.id}/`, name ?? DEFAULT_NAME, protocolVersion);
  if (!extKey) await chrome.storage.local.set({ extKey: c.privateKeyHex() });
  client = c;

  const p = chrome.runtime.connectNative(NATIVE_HOST);
  port = p;
  p.onMessage.addListener((msg: unknown) => onFrame(p, msg));
  p.onDisconnect.addListener(() => {
    if (port !== p) return;
    const reason = chrome.runtime.lastError?.message;
    teardown(
      state.status === "error"
        ? state
        : { status: "error", error: reason?.includes("not found") ? "host_not_installed" : "disconnected" },
    );
  });

  send(c.hello());
  if (mode === "pair") {
    state = { status: "pairing" };
    send(c.startPairing());
  } else {
    send(c.startSession(servicePublic ?? ""));
  }
}

function onFrame(p: chrome.runtime.Port, msg: unknown): void {
  if (port !== p || !client) return;
  let out: { frames: string[]; events: ClientEventJson[] };
  try {
    out = JSON.parse(client.onFrame(JSON.stringify(msg))) as typeof out;
  } catch {
    teardown({ status: "error", error: "protocol" });
    return;
  }
  for (const f of out.frames) send(f);
  for (const e of out.events) void onEvent(e);
}

type ClientEventJson =
  | { type: "show_sas"; sas: string; words: SasWord[] }
  | { type: "paired"; service_public: string }
  | { type: "established" }
  | { type: "message"; message: ServerMessage }
  | { type: "error"; code: string };

async function onEvent(e: ClientEventJson): Promise<void> {
  switch (e.type) {
    case "show_sas":
      state = { status: "awaiting_confirm", words: e.words };
      break;
    case "paired":
      await chrome.storage.local.set({ servicePublic: e.service_public });
      state = { status: "connected", locked: false };
      break;
    case "established":
      state = { status: "connected", locked: false };
      void refreshStatus();
      break;
    case "message": {
      const m = e.message;
      if ("event" in m) {
        if (m.event === "locked" || m.event === "unlocked") {
          const touchId = state.status === "connected" ? state.touchId : undefined;
          state = { status: "connected", locked: m.event === "locked", touchId };
          // 锁定后能否用 Touch ID 可能变化（例如需要定期输入主密码）
          void refreshStatus();
          if (m.event === "unlocked") void reopenPopup("unlockRequestedAt");
        }
      } else {
        pending.get(m.id)?.(m);
        pending.delete(m.id);
      }
      break;
    }
    case "error": {
      // 旧版 Keevo 不支持这个版本：退回低一个的版本重新连接（spec/ipc.md §5.5）。v1 中没有保存与更新，v2 中没有搜索、打开与解锁
      const mode = state.status === "pairing" ? "pair" : "session";
      if (e.code === "unsupported_version" && client && client.version() > 1) {
        protocolVersion = client.version() - 1;
        teardown({ status: "connecting" });
        // 配对需要用户重新发起（扩展不得自动重试配对，§4.2 第 8 步）
        if (mode === "session") await connect("session");
        else state = { status: "unpaired" };
        break;
      }
      // 配对记录已被撤销或服务换了密钥：清除服务公钥，让用户重新配对
      if (e.code === "not_paired") await chrome.storage.local.remove("servicePublic");
      teardown({ status: "error", error: e.code });
      break;
    }
  }
}

function request(call: object, timeoutMs = REQUEST_TIMEOUT_MS): Promise<ServerMessage | null> {
  if (!client || state.status !== "connected") return Promise.resolve(null);
  const { id, frame } = JSON.parse(client.request(JSON.stringify(call))) as { id: number; frame: string };
  return new Promise((resolve) => {
    pending.set(id, resolve);
    send(frame);
    setTimeout(() => {
      if (pending.delete(id)) resolve(null);
    }, timeoutMs);
  });
}

async function refreshStatus(): Promise<void> {
  const m = await request({ method: "status" });
  if (m && "result" in m && "locked" in m.result) applyStatus(m.result);
}

function applyStatus(r: { locked: boolean; touch_id?: boolean }): void {
  state = { status: "connected", locked: r.locked, touchId: r.touch_id };
}

/**
 * 请 Keevo 解锁之后，等它解锁：Vault Service 目前不推送 `locked` / `unlocked` 事件，这里每秒查询一次状态，
 * 最多 2 分钟。解锁后重新打开弹窗。
 */
let unlockWatch: ReturnType<typeof setInterval> | undefined;
function watchUnlock(): void {
  clearInterval(unlockWatch);
  const started = Date.now();
  unlockWatch = setInterval(() => {
    if (Date.now() - started > REOPEN_WINDOW_MS || state.status !== "connected") {
      clearInterval(unlockWatch);
      return;
    }
    void refreshStatus().then(() => {
      if (state.status === "connected" && !state.locked) {
        clearInterval(unlockWatch);
        void reopenPopup("unlockRequestedAt");
      }
    });
  }, 1000);
}

/**
 * 用户在弹窗里点了"解锁"或"在全部条目中搜索"，Keevo 来到前台、弹窗随之关闭；Keevo 中完成后回到浏览器，
 * 这里重新打开弹窗（spec/ipc.md §5.6）。只在 2 分钟内、且确实由弹窗发起时打开，失败时（例如浏览器还没回到前台）稍后再试一次。
 */
async function reopenPopup(key: "unlockRequestedAt" | "searchAllowedAt"): Promise<boolean> {
  const at = (await chrome.storage.session.get(key))[key] as number | undefined;
  if (at === undefined || Date.now() - at > REOPEN_WINDOW_MS) return false;
  await chrome.storage.session.remove(key);
  for (const delay of [300, 1200]) {
    await new Promise((r) => setTimeout(r, delay));
    try {
      await chrome.action.openPopup();
      return true;
    } catch {
      // 浏览器窗口还没有成为前台，或弹窗已经打开
    }
  }
  return false;
}

/** 当前活动标签页。网址由浏览器提供（activeTab 在用户点开弹窗时授予），不采信页面自述。 */
async function activeTab(): Promise<{ id: number; url: string } | null> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id !== undefined && tab.url ? { id: tab.id, url: tab.url } : null;
}

/** 为当前标签页的网址取用条目的凭据（`fill`）：Keevo 再次核对网址，并按站点授权（spec/ipc.md §5.2）。 */
async function fetchSecret(itemId: string, url: string): Promise<{ secret?: Secret; error?: string }> {
  const m = await request({ method: "fill", params: { item_id: itemId, url } }, FILL_TIMEOUT_MS);
  if (m && "result" in m && "password" in m.result) return { secret: m.result };
  if (m && "error" in m && m.error.code === "locked") state = { status: "connected", locked: true };
  return { error: m && "error" in m ? m.error.code : "failed" };
}

/** 需要时建立会话：已配对就用 IK 会话重新连接（弹窗与页内菜单打开时调用）。 */
async function ensureConnected(): Promise<void> {
  if (state.status === "idle" || (state.status === "error" && state.error === "disconnected")) {
    const { servicePublic } = await stored();
    if (servicePublic) await connect("session");
    else state = { status: "unpaired" };
  }
}

/** 等连接建立（IK 握手只需一个来回），最多等 3 秒。 */
async function settled(): Promise<void> {
  for (let i = 0; i < 30 && (state.status === "connecting" || state.status === "idle"); i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
}

type FillOutcome = "filled" | "origin_changed" | "no_password_field" | "no_field";

/**
 * 把凭据交给某个帧中的内容脚本填入。内容脚本先核对自己的来源仍是 `origin`。
 * 最小权限模式下内容脚本可能还没注入：此时（弹窗或快捷键授予了 activeTab）先注入顶层帧。
 */
async function deliver(
  tabId: number,
  frameId: number,
  message: { origin: string; secret: Secret; anchored: boolean; kind: "login" | "otp" },
): Promise<FillOutcome | "failed"> {
  const payload = {
    type: "fill",
    origin: message.origin,
    username: message.secret.username,
    password: message.secret.password,
    totp: message.secret.totp,
    anchored: message.anchored,
    kind: message.kind,
  };
  let outcome: FillOutcome | "failed";
  try {
    outcome = (await chrome.tabs.sendMessage(tabId, payload, { frameId })) as FillOutcome;
  } catch {
    if (frameId !== 0) return "failed";
    await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ["content.js"] });
    outcome = (await chrome.tabs.sendMessage(tabId, payload, { frameId: 0 })) as FillOutcome;
  }
  // 记下刚填入的密码（只存哈希）：用户随后提交同一个密码时，不提示保存或更新
  if (outcome === "filled") filled.set(tabId, { hash: await sha256Hex(message.secret.password), at: Date.now() });
  return outcome;
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function displayName(raw: string): Promise<string> {
  await ready;
  return KeevoClient.displayName(raw);
}

/** 把生成的密码交给当前标签页顶层帧的内容脚本，填入新密码框；最小权限模式下先注入。 */
async function deliverGenerated(tabId: number, origin: string, password: string): Promise<string> {
  const payload = { type: "fill_new_password", origin, password };
  try {
    return (await chrome.tabs.sendMessage(tabId, payload, { frameId: 0 })) as string;
  } catch {
    await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ["content.js"] });
    return (await chrome.tabs.sendMessage(tabId, payload, { frameId: 0 })) as string;
  }
}

function errorOf(m: ServerMessage | null): string {
  return m && "error" in m ? m.error.code : "failed";
}

async function handle(req: PopupRequest): Promise<PopupResponse> {
  switch (req.type) {
    case "state": {
      await ensureConnected();
      // 锁定时每次都向 Keevo 核对：用户可能已经在 Keevo 中解锁（服务不推送解锁事件）
      if (state.status === "connected" && state.locked) await refreshStatus();
      const tab = await activeTab();
      const blocked = tab ? (await chrome.storage.session.get(`blocked:${tab.id}`))[`blocked:${tab.id}`] === true : false;
      const { searchResume } = (await chrome.storage.session.get("searchResume")) as { searchResume?: { query: string; at: number } };
      const resume = searchResume && Date.now() - searchResume.at < REOPEN_WINDOW_MS ? { query: searchResume.query } : undefined;
      if (searchResume) await chrome.storage.session.remove("searchResume");
      return {
        state,
        name: await displayName((await stored()).name ?? DEFAULT_NAME),
        inline: await chrome.permissions.contains({ origins: SITE_ORIGINS }),
        blocked,
        version: client?.version(),
        ...(resume ? { resume } : {}),
      };
    }
    case "search": {
      const query = req.query.trim().slice(0, 128);
      if (!query || !client || client.version() < 3) return { state, error: "unsupported" };
      // 第一次需要用户在 Keevo 中允许（最长 60 秒）。Keevo 来到前台时弹窗会关闭：记下搜索词，允许后重新打开弹窗时恢复
      if (req.ask) await chrome.storage.session.set({ searchAllowedAt: Date.now(), searchResume: { query, at: Date.now() } });
      const m = await request({ method: "search", params: { query, ask: req.ask } }, req.ask ? FILL_TIMEOUT_MS : REQUEST_TIMEOUT_MS);
      if (m && "result" in m && "items" in m.result) {
        // 弹窗已关闭时重新打开，由它取走恢复记录；弹窗还开着时结果直接交给它（打开会失败），恢复记录随之作废
        if (req.ask) {
          void reopenPopup("searchAllowedAt").then((opened) => {
            if (!opened) void chrome.storage.session.remove("searchResume");
          });
        }
        return { state, results: m.result.items };
      }
      if (req.ask) await chrome.storage.session.remove(["searchAllowedAt", "searchResume"]);
      if (errorOf(m) === "locked") state = { status: "connected", locked: true };
      return { state, error: errorOf(m) };
    }
    case "open": {
      if (!client || client.version() < 3) return { state, error: "unsupported" };
      const m = await request({ method: "open", params: req.itemId ? { item_id: req.itemId } : {} });
      if (m && "result" in m && "locked" in m.result) applyStatus(m.result);
      return m && "result" in m ? { state } : { state, error: errorOf(m) };
    }
    case "unlock": {
      if (!client || client.version() < 3) return { state, error: "unsupported" };
      await chrome.storage.session.set({ unlockRequestedAt: Date.now() });
      const m = await request({ method: "unlock" });
      if (m && "result" in m && "locked" in m.result) applyStatus(m.result);
      if (state.status === "connected" && state.locked) watchUnlock();
      return m && "result" in m ? { state } : { state, error: errorOf(m) };
    }
    case "generate": {
      await ready;
      try {
        const g = JSON.parse(generatePassword(JSON.stringify(req.recipe satisfies Recipe))) as { value: string; entropy_bits: number };
        return { state, generated: { value: g.value, entropy: g.entropy_bits } };
      } catch {
        return { state, error: "failed" };
      }
    }
    case "fill_generated": {
      const tab = await activeTab();
      if (!tab || !/^https?:/.test(tab.url)) return { state, fill: "no_tab" };
      return { state, fill: await deliverGenerated(tab.id, new URL(tab.url).origin, req.password) };
    }
    case "save_login": {
      const tab = await activeTab();
      if (!tab || !/^https?:/.test(tab.url)) return { state, error: "no_tab" };
      if (!client || client.version() < 2) return { state, error: "unsupported" };
      const m = await request({
        method: "save",
        params: { url: tab.url, username: req.username.slice(0, 1024), password: req.password.slice(0, 4096) },
      });
      if (m && "result" in m && "item_id" in m.result) return { state, saved: m.result.item_id };
      if (errorOf(m) === "locked") state = { status: "connected", locked: true };
      return { state, error: errorOf(m) };
    }
    case "display_name":
      return { state, name: await displayName(req.name) };
    case "pair": {
      // 空名称按默认名称处理；名称只是标签，两端核对的是配对码（spec/ipc.md §4.2）
      const name = (await displayName(req.name)).trim() ? req.name : DEFAULT_NAME;
      await chrome.storage.local.set({ name });
      await connect("pair");
      return { state, name: await displayName(name) };
    }
    case "candidates": {
      const tab = await activeTab();
      if (!tab) return { state, candidates: [] };
      const m = await request({ method: "candidates", params: { url: tab.url } });
      const candidates: Candidate[] = m && "result" in m && "items" in m.result ? m.result.items : [];
      const error = m && "error" in m ? m.error.code : undefined;
      if (error === "locked") state = { status: "connected", locked: true };
      // 查询过于频繁时 Keevo 拒绝回答（spec/ipc.md §5.2）：如实告诉用户，不显示成"没有匹配"
      const limited = error === "not_authorized" ? "queries_limited" : undefined;
      return { state, candidates, origin: new URL(tab.url).origin, ...(limited ? { error: limited } : {}) };
    }
    case "fill": {
      const tab = await activeTab();
      if (!tab) return { state, fill: "no_tab" };
      const { secret, error } = await fetchSecret(req.itemId, tab.url);
      if (!secret) return { state, fill: error ?? "failed" };
      // 弹窗填充顶层帧中第一个可见的登录表单
      const fill = await deliver(tab.id, 0, { origin: new URL(tab.url).origin, secret, anchored: false, kind: "login" });
      if (fill === "filled") await clearBlocked(tab.id);
      return { state, fill };
    }
    case "secret": {
      // 复制与查看验证码：同样经过网址核对与按站点授权，只是不注入页面
      const tab = await activeTab();
      if (!tab) return { state, error: "no_tab" };
      const r = await fetchSecret(req.itemId, tab.url);
      return r.secret ? { state, secret: r.secret } : { state, error: r.error ?? "failed" };
    }
    case "copied":
      await scheduleClear(req.hash);
      return { state };
  }
}

// ---- 剪贴板清除

/** 记下写入值的哈希（只在内存中，浏览器重启即丢弃），90 秒后核对并清除。重复复制时以最后一次为准。 */
async function scheduleClear(hash: string): Promise<void> {
  if (!/^[0-9a-f]{64}$/.test(hash)) return;
  await chrome.storage.session.set({ clipboardHash: hash });
  await chrome.alarms.create(CLEAR_ALARM, { when: Date.now() + CLIPBOARD_CLEAR_MS });
}

async function clearClipboard(): Promise<void> {
  const { clipboardHash } = (await chrome.storage.session.get("clipboardHash")) as { clipboardHash?: string };
  await chrome.storage.session.remove("clipboardHash");
  if (!clipboardHash) return;
  // 读取剪贴板需要用户在第一次复制秘密时授予的可选权限；没有时什么也不做
  if (!(await chrome.permissions.contains({ permissions: ["clipboardRead", "clipboardWrite"] }))) return;
  if (!(await chrome.offscreen.hasDocument())) {
    await chrome.offscreen.createDocument({
      url: "offscreen.html",
      reasons: [chrome.offscreen.Reason.CLIPBOARD],
      justification: t("90 秒后清除 Keevo 写入剪贴板的密码或验证码"),
    });
  }
  const msg: OffscreenRequest = { target: "offscreen", type: "clear_if", hash: clipboardHash };
  try {
    await chrome.runtime.sendMessage(msg);
  } finally {
    await chrome.offscreen.closeDocument();
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === CLEAR_ALARM) void clearClipboard();
});

// ---- 页内菜单（docs/security.md §12）

/** 一次页内菜单：由某个帧中的内容脚本在可信的用户手势后发起。网址与来源来自 Chrome 提供的 sender。 */
interface InlineSession {
  tabId: number;
  frameId: number;
  url: string;
  origin: string;
  topOrigin: string | null;
  kind: "login" | "otp";
}

// Service Worker 可能在菜单打开期间被回收：会话存在 storage.session（只在内存中，不落盘）
async function getSession(tabId: number): Promise<InlineSession | undefined> {
  return (await chrome.storage.session.get(`inline:${tabId}`))[`inline:${tabId}`] as InlineSession | undefined;
}

function originOf(url: string | undefined): string | null {
  try {
    return url ? new URL(url).origin : null;
  } catch {
    return null;
  }
}

// ---- 保存与更新（协议 v2，spec/ipc.md §5.5）

/** 一次待用户决定的保存或更新。密码只在这里的内存中（Service Worker 被回收时随之丢弃）。 */
interface Offer {
  kind: "save" | "update";
  url: string;
  host: string;
  username: string;
  password: string;
  itemId?: string;
  title: string;
  at: number;
}

const OFFER_TTL_MS = 3 * 60_000;
const offers = new Map<number, Offer>();
const filled = new Map<number, { hash: string; at: number }>();
const usernames = new Map<number, { username: string; at: number }>();

function liveOffer(tabId: number): Offer | undefined {
  const o = offers.get(tabId);
  if (o && Date.now() - o.at > OFFER_TTL_MS) {
    offers.delete(tabId);
    return undefined;
  }
  return o;
}

async function neverSaveSites(): Promise<string[]> {
  return ((await chrome.storage.local.get("neverSave")) as { neverSave?: string[] }).neverSave ?? [];
}

/**
 * 用户提交了登录表单：决定是否提示保存或更新。
 * - 刚由 Keevo 填入、没有改动的密码：不提示；
 * - 当前网站没有同一用户名的条目：提示保存；
 * - 修改密码的表单，且有同一用户名的条目：提示更新。普通登录表单不提示更新——扩展拿不到已保存的密码，
 *   无从判断是否改过；也不为此向 Keevo 询问"密码对不对"，那会成为冒充者的猜测接口。
 */
async function onSubmitted(tabId: number, url: string, username: string, password: string, change: boolean): Promise<void> {
  if (!/^https?:/.test(url) || password === "") return;
  const host = new URL(url).host;
  if ((await neverSaveSites()).includes(new URL(url).origin)) return;
  const f = filled.get(tabId);
  if (f && Date.now() - f.at < OFFER_TTL_MS && f.hash === (await sha256Hex(password))) return;
  const step = usernames.get(tabId);
  if (!username && step && Date.now() - step.at < OFFER_TTL_MS) username = step.username;
  await ensureConnected();
  await settled();
  if (state.status !== "connected" || state.locked || !client || client.version() < 2) return;
  const m = await request({ method: "candidates", params: { url } });
  const candidates: Candidate[] = m && "result" in m && "items" in m.result ? m.result.items : [];
  const same = candidates.find((c) => username !== "" && c.subtitle.toLocaleLowerCase() === username.toLocaleLowerCase());
  const target = same ?? (username === "" && candidates.length === 1 ? candidates[0] : undefined);
  let offer: Offer;
  if (target) {
    if (!change) return;
    offer = { kind: "update", url, host, username: target.subtitle, password, itemId: target.item_id, title: target.title, at: Date.now() };
  } else {
    offer = { kind: "save", url, host, username, password, title: host.replace(/^www\./, ""), at: Date.now() };
  }
  offers.set(tabId, offer);
  // 单页应用不跳转：立即显示；跳转的页面在加载时会来询问（offer_query）
  await chrome.tabs.sendMessage(tabId, { type: "show_bar" }, { frameId: 0 }).catch(() => undefined);
}

async function handleBar(req: BarRequest, sender: chrome.runtime.MessageSender): Promise<BarResponse> {
  const tabId = sender.tab?.id;
  if (tabId === undefined) return { error: "failed" };
  const offer = liveOffer(tabId);
  const close = async (): Promise<void> => {
    offers.delete(tabId);
    await chrome.tabs.sendMessage(tabId, { type: "close_bar" }, { frameId: 0 }).catch(() => undefined);
  };
  switch (req.type) {
    case "bar_init":
      return offer ? { init: { kind: offer.kind, host: offer.host, username: offer.username, title: offer.title } } : {};
    case "bar_save": {
      if (!offer) return { error: "expired" };
      if (!client || client.version() < 2) return { error: "unsupported" };
      const call =
        offer.kind === "update" && offer.itemId
          ? { method: "update", params: { item_id: offer.itemId, url: offer.url, password: offer.password } }
          : { method: "save", params: { url: offer.url, username: offer.username, password: offer.password } };
      // 更新要等用户在 Keevo 中确认（最长 60 秒）
      const m = await request(call, FILL_TIMEOUT_MS);
      if (m && "result" in m && "item_id" in m.result) {
        offers.delete(tabId);
        return { ok: true };
      }
      return { error: m && "error" in m ? m.error.code : "failed" };
    }
    case "bar_never":
      if (offer) {
        const sites = await neverSaveSites();
        const origin = new URL(offer.url).origin;
        if (!sites.includes(origin)) await chrome.storage.local.set({ neverSave: [...sites, origin] });
      }
      await close();
      return {};
    case "bar_dismiss":
    case "bar_close":
      await close();
      return {};
  }
}

async function handleContent(req: ContentRequest, sender: chrome.runtime.MessageSender): Promise<unknown> {
  const tabId = sender.tab?.id;
  const frameId = sender.frameId;
  const url = sender.url;
  if (tabId === undefined || frameId === undefined || !url) return { ok: false };
  switch (req.type) {
    case "submitted":
      if (typeof req.password !== "string" || typeof req.username !== "string") return {};
      await onSubmitted(tabId, url, req.username.slice(0, 1024), req.password.slice(0, 4096), req.change === true);
      return {};
    case "username_step":
      if (typeof req.username === "string" && req.username) {
        usernames.set(tabId, { username: req.username.slice(0, 1024), at: Date.now() });
      }
      return {};
    case "offer_query":
      return { show: frameId === 0 && liveOffer(tabId) !== undefined };
    case "inline_open": {
      const origin = originOf(url);
      if (!origin || !/^https?:$/.test(new URL(url).protocol)) return { ok: false };
      const session: InlineSession = {
        tabId,
        frameId,
        url,
        origin,
        // 顶层帧的网址同样来自 Chrome；拿不到时按跨域处理（要求确认）
        topOrigin: frameId === 0 ? origin : originOf(sender.tab?.url),
        kind: req.kind === "otp" ? "otp" : "login",
      };
      await chrome.storage.session.set({ [`inline:${tabId}`]: session });
      return { ok: true };
    }
    case "inline_close": {
      const s = await getSession(tabId);
      if (s && s.frameId === frameId) await chrome.storage.session.remove(`inline:${tabId}`);
      return { ok: true };
    }
  }
}

async function menuInit(session: InlineSession | undefined): Promise<MenuInit> {
  if (!session) return { origin: "", topOrigin: null, kind: "login", candidates: [], message: "no_session" };
  const base = { origin: session.origin, topOrigin: session.topOrigin, kind: session.kind, candidates: [] };
  await ensureConnected();
  await settled();
  if (state.status === "unpaired") return { ...base, message: "unpaired" };
  if (state.status !== "connected") return { ...base, message: state.status === "error" ? "error" : "connecting" };
  if (state.locked) return { ...base, message: "locked" };
  const m = await request({ method: "candidates", params: { url: session.url } });
  if (m && "error" in m && m.error.code === "locked") return { ...base, message: "locked" };
  if (m && "error" in m && m.error.code === "not_authorized") return { ...base, message: "limited" };
  const candidates: Candidate[] = m && "result" in m && "items" in m.result ? m.result.items : [];
  return { ...base, candidates };
}

async function handleMenu(req: MenuRequest, sender: chrome.runtime.MessageSender): Promise<MenuResponse> {
  const tabId = sender.tab?.id;
  if (tabId === undefined) return { error: "failed" };
  const session = await getSession(tabId);
  switch (req.type) {
    case "menu_init":
      return { init: await menuInit(session) };
    case "menu_fill": {
      if (!session) return { error: "failed" };
      // 跨域 iframe 中的输入框需要用户在菜单中再确认一次
      if (session.topOrigin !== session.origin && !req.confirmed) return { error: "failed" };
      const { secret, error } = await fetchSecret(req.itemId, session.url);
      if (!secret) return { error: error ?? "failed" };
      if (session.kind === "otp" && !secret.totp) return { error: "no_totp" };
      const fill = await deliver(session.tabId, session.frameId, {
        origin: session.origin,
        secret,
        anchored: true,
        kind: session.kind,
      });
      if (fill === "filled") await chrome.storage.session.remove(`inline:${tabId}`);
      return { fill };
    }
    case "menu_close":
      if (session) await chrome.tabs.sendMessage(session.tabId, { type: "close_menu" }, { frameId: session.frameId }).catch(() => {});
      return {};
    case "menu_size":
      if (session && Number.isFinite(req.height)) {
        await chrome.tabs
          .sendMessage(session.tabId, { type: "menu_size", height: req.height }, { frameId: session.frameId })
          .catch(() => {});
      }
      return {};
    case "menu_blocked":
      // 菜单在不可见时被点击：可能是点击劫持。关闭菜单，改用工具栏中的弹窗（降级为弹窗内确认）
      if (session) {
        await chrome.tabs.sendMessage(session.tabId, { type: "close_menu" }, { frameId: session.frameId }).catch(() => {});
        await chrome.storage.session.remove(`inline:${tabId}`);
      }
      await chrome.storage.session.set({ [`blocked:${tabId}`]: true });
      await chrome.action.setBadgeText({ tabId, text: "!" });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: "#b45309" });
      return {};
  }
}

async function clearBlocked(tabId: number): Promise<void> {
  await chrome.storage.session.remove(`blocked:${tabId}`);
  await chrome.action.setBadgeText({ tabId, text: "" });
}

chrome.tabs.onRemoved.addListener((tabId) => {
  void chrome.storage.session.remove([`inline:${tabId}`, `blocked:${tabId}`]);
  offers.delete(tabId);
  filled.delete(tabId);
  usernames.delete(tabId);
});

// ---- 标准模式：有网站权限时注册内容脚本（所有帧），权限撤销时注销

async function syncContentScripts(): Promise<void> {
  const granted = await chrome.permissions.contains({ origins: SITE_ORIGINS });
  const registered = await chrome.scripting.getRegisteredContentScripts({ ids: [CONTENT_SCRIPT_ID] });
  if (granted && registered.length === 0) {
    await chrome.scripting.registerContentScripts([
      { id: CONTENT_SCRIPT_ID, js: ["content.js"], matches: SITE_ORIGINS, allFrames: true, runAt: "document_idle" },
    ]);
  } else if (!granted && registered.length > 0) {
    await chrome.scripting.unregisterContentScripts({ ids: [CONTENT_SCRIPT_ID] });
  }
}

chrome.permissions.onAdded.addListener(() => void syncContentScripts());
chrome.permissions.onRemoved.addListener(() => void syncContentScripts());
void syncContentScripts();

// ---- 快捷键：在焦点所在的输入框打开页内菜单。快捷键授予 activeTab，最小权限模式下先注入顶层帧

chrome.commands.onCommand.addListener((command, tab) => {
  if (command !== "open-inline-menu" || tab?.id === undefined) return;
  const tabId = tab.id;
  void (async () => {
    try {
      await chrome.tabs.sendMessage(tabId, { type: "open_menu" });
    } catch {
      await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ["content.js"] });
      await chrome.tabs.sendMessage(tabId, { type: "open_menu" }, { frameId: 0 });
    }
  })();
});

// ---- 消息分流：按发送方区分弹窗、页内菜单与内容脚本，各自只接受自己的消息类型

const POPUP_TYPES = new Set([
  "state",
  "display_name",
  "pair",
  "candidates",
  "fill",
  "secret",
  "copied",
  "search",
  "open",
  "unlock",
  "generate",
  "fill_generated",
  "save_login",
]);
const MENU_TYPES = new Set(["menu_init", "menu_fill", "menu_close", "menu_size", "menu_blocked"]);
const CONTENT_TYPES = new Set(["inline_open", "inline_close", "submitted", "username_step", "offer_query"]);
const BAR_TYPES = new Set(["bar_init", "bar_save", "bar_dismiss", "bar_never", "bar_close"]);

chrome.runtime.onMessage.addListener((req: { type?: string; target?: string }, sender, sendResponse) => {
  // 网页无法给扩展发消息（没有 externally_connectable）；这里再核对发送方是本扩展。发给离屏文档的消息不在这里处理
  if (sender.id !== chrome.runtime.id || req?.target !== undefined || typeof req?.type !== "string") return false;
  const url = sender.url ?? "";
  let work: Promise<unknown> | null = null;
  // popup.html 不是可被网页访问的资源，网页既不能嵌入也不能打开它：按网址识别即可（作为标签页打开时 sender.tab 有值）
  if (url === chrome.runtime.getURL("popup.html") && POPUP_TYPES.has(req.type)) {
    work = handle(req as PopupRequest).catch(() => ({ state: { status: "error", error: "internal" } }));
  } else if (sender.tab && url.startsWith("chrome-extension://") && new URL(url).pathname === "/menu.html" && MENU_TYPES.has(req.type)) {
    work = handleMenu(req as MenuRequest, sender).catch(() => ({ error: "failed" }));
  } else if (sender.tab && url.startsWith("chrome-extension://") && new URL(url).pathname === "/bar.html" && BAR_TYPES.has(req.type)) {
    work = handleBar(req as BarRequest, sender).catch(() => ({ error: "failed" }));
  } else if (sender.tab && /^https?:/.test(url) && CONTENT_TYPES.has(req.type)) {
    work = handleContent(req as ContentRequest, sender).catch(() => ({ ok: false }));
  }
  if (!work) return false;
  void work.then(sendResponse);
  return true;
});
