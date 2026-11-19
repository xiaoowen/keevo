// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// Service Worker：持有与 Keevo 的加密会话（spec/ipc.md）。
//
// - 协议逻辑全部在 WASM 中（crates/keevo-wasm，与桌面应用共用同一份 Rust 实现），配对码的词表也在其中；
// - 这里只负责收发 Native Messaging 帧、保存扩展静态密钥与服务公钥、响应弹窗的请求；
// - 填充与复制时，页面与帧的网址取自 Chrome（tabs API 与消息的 sender），不采信页面或弹窗的自述；
// - 凭据只发给发起填充的那个帧（frameId），由内容脚本（content.js）核对来源后填入；
// - 复制的秘密在 90 秒后清除，且只在剪贴板仍是 Keevo 写入的值时才清除（docs/ux.md §5）；
// - 页内菜单（menu.html）只拿到条目概要。

import init, { KeevoClient } from "./wasm/keevo_wasm.js";
import type {
  Candidate,
  ContentRequest,
  MenuInit,
  MenuRequest,
  MenuResponse,
  OffscreenRequest,
  PopupRequest,
  PopupResponse,
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
  const c = new KeevoClient(extKey, `chrome-extension://${chrome.runtime.id}/`, name ?? DEFAULT_NAME);
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

  send(KeevoClient.hello());
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
        if (m.event === "locked" || m.event === "unlocked") state = { status: "connected", locked: m.event === "locked" };
      } else {
        pending.get(m.id)?.(m);
        pending.delete(m.id);
      }
      break;
    }
    case "error":
      // 配对记录已被撤销或服务换了密钥：清除服务公钥，让用户重新配对
      if (e.code === "not_paired") await chrome.storage.local.remove("servicePublic");
      teardown({ status: "error", error: e.code });
      break;
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
  if (m && "result" in m && "locked" in m.result) state = { status: "connected", locked: m.result.locked };
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
  try {
    return (await chrome.tabs.sendMessage(tabId, payload, { frameId })) as FillOutcome;
  } catch {
    if (frameId !== 0) return "failed";
    await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ["content.js"] });
    return (await chrome.tabs.sendMessage(tabId, payload, { frameId: 0 })) as FillOutcome;
  }
}

async function displayName(raw: string): Promise<string> {
  await ready;
  return KeevoClient.displayName(raw);
}

async function handle(req: PopupRequest): Promise<PopupResponse> {
  switch (req.type) {
    case "state": {
      await ensureConnected();
      const tab = await activeTab();
      const blocked = tab ? (await chrome.storage.session.get(`blocked:${tab.id}`))[`blocked:${tab.id}`] === true : false;
      return {
        state,
        name: await displayName((await stored()).name ?? DEFAULT_NAME),
        inline: await chrome.permissions.contains({ origins: SITE_ORIGINS }),
        blocked,
      };
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
      return { state, candidates, origin: new URL(tab.url).origin };
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
      justification: "90 秒后清除 Keevo 写入剪贴板的密码或验证码",
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

async function handleContent(req: ContentRequest, sender: chrome.runtime.MessageSender): Promise<unknown> {
  const tabId = sender.tab?.id;
  const frameId = sender.frameId;
  const url = sender.url;
  if (tabId === undefined || frameId === undefined || !url) return { ok: false };
  switch (req.type) {
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

const POPUP_TYPES = new Set(["state", "display_name", "pair", "candidates", "fill", "secret", "copied"]);
const MENU_TYPES = new Set(["menu_init", "menu_fill", "menu_close", "menu_size", "menu_blocked"]);
const CONTENT_TYPES = new Set(["inline_open", "inline_close"]);

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
  } else if (sender.tab && /^https?:/.test(url) && CONTENT_TYPES.has(req.type)) {
    work = handleContent(req as ContentRequest, sender).catch(() => ({ ok: false }));
  }
  if (!work) return false;
  void work.then(sendResponse);
  return true;
});
