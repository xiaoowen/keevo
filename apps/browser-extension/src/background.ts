// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// Service Worker：持有与 Keevo 的加密会话（spec/ipc.md）。
//
// - 协议逻辑全部在 WASM 中（crates/keevo-wasm，与桌面应用共用同一份 Rust 实现），配对码的词表也在其中；
// - 这里只负责收发 Native Messaging 帧、保存扩展静态密钥与服务公钥、响应弹窗的请求；
// - 填充与复制时，页面网址由这里通过 tabs API 独立获取，不采信页面或弹窗的自述；
// - 复制的秘密在 90 秒后清除，且只在剪贴板仍是 Keevo 写入的值时才清除（docs/ux.md §5）。

import init, { KeevoClient } from "./wasm/keevo_wasm.js";
import { fillPage, type FillOutcome } from "./fill.js";
import type {
  Candidate,
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

async function displayName(raw: string): Promise<string> {
  await ready;
  return KeevoClient.displayName(raw);
}

async function handle(req: PopupRequest): Promise<PopupResponse> {
  switch (req.type) {
    case "state": {
      if (state.status === "idle" || (state.status === "error" && state.error === "disconnected")) {
        const { servicePublic } = await stored();
        if (servicePublic) await connect("session");
        else state = { status: "unpaired" };
      }
      return { state, name: await displayName((await stored()).name ?? DEFAULT_NAME) };
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
      const [result] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: fillPage,
        args: [secret.username, secret.password, new URL(tab.url).origin],
      });
      return { state, fill: (result?.result as FillOutcome | undefined) ?? "failed" };
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

chrome.runtime.onMessage.addListener((req: PopupRequest | OffscreenRequest, sender, sendResponse) => {
  // 只接受扩展自己的页面（弹窗），拒绝任何来自网页上下文的消息；发给离屏文档的消息不在这里处理
  if (sender.id !== chrome.runtime.id || sender.tab || "target" in req) return false;
  handle(req).then(sendResponse, () => sendResponse({ state: { status: "error", error: "internal" } }));
  return true;
});
