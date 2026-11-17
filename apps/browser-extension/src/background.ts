// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// Service Worker：持有与 Keevo 的加密会话（spec/ipc.md）。
//
// - 协议逻辑全部在 WASM 中（crates/keevo-wasm，与桌面应用共用同一份 Rust 实现）；
// - 这里只负责收发 Native Messaging 帧、保存扩展静态密钥与服务公钥、响应弹窗的请求；
// - 填充时，页面网址由这里通过 tabs API 独立获取，不采信页面或弹窗的自述。

import init, { KeevoClient } from "./wasm/keevo_wasm.js";
import { fillPage, type FillOutcome } from "./fill.js";
import type { Candidate, PopupRequest, PopupResponse, ServerMessage, ViewState } from "./types.js";

const NATIVE_HOST = "app.keevo.native_host";
const REQUEST_TIMEOUT_MS = 10_000;

interface Stored {
  extKey?: string;
  servicePublic?: string;
}

let state: ViewState = { status: "idle" };
let port: chrome.runtime.Port | null = null;
let client: KeevoClient | null = null;
const pending = new Map<number, (m: ServerMessage | null) => void>();
const ready = init({ module_or_path: chrome.runtime.getURL("wasm/keevo_wasm_bg.wasm") });

async function stored(): Promise<Stored> {
  return (await chrome.storage.local.get(["extKey", "servicePublic"])) as Stored;
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
  const { extKey, servicePublic } = await stored();
  if (mode === "session" && !servicePublic) {
    state = { status: "unpaired" };
    return;
  }
  const c = new KeevoClient(extKey, `chrome-extension://${chrome.runtime.id}/`, "Chrome");
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
  | { type: "show_sas"; sas: string }
  | { type: "paired"; service_public: string }
  | { type: "established" }
  | { type: "message"; message: ServerMessage }
  | { type: "error"; code: string };

async function onEvent(e: ClientEventJson): Promise<void> {
  switch (e.type) {
    case "show_sas":
      state = { status: "awaiting_confirm", sas: e.sas };
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

function request(call: object): Promise<ServerMessage | null> {
  if (!client || state.status !== "connected") return Promise.resolve(null);
  const { id, frame } = JSON.parse(client.request(JSON.stringify(call))) as { id: number; frame: string };
  return new Promise((resolve) => {
    pending.set(id, resolve);
    send(frame);
    setTimeout(() => {
      if (pending.delete(id)) resolve(null);
    }, REQUEST_TIMEOUT_MS);
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

async function handle(req: PopupRequest): Promise<PopupResponse> {
  switch (req.type) {
    case "state": {
      if (state.status === "idle" || (state.status === "error" && state.error === "disconnected")) {
        const { servicePublic } = await stored();
        if (servicePublic) await connect("session");
        else state = { status: "unpaired" };
      }
      return { state };
    }
    case "pair":
      await connect("pair");
      return { state };
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
      const m = await request({ method: "fill", params: { item_id: req.itemId, url: tab.url } });
      if (!m || !("result" in m) || !("password" in m.result)) {
        return { state, fill: m && "error" in m ? m.error.code : "failed" };
      }
      const { username, password } = m.result;
      const [result] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: fillPage,
        args: [username, password, new URL(tab.url).origin],
      });
      return { state, fill: (result?.result as FillOutcome | undefined) ?? "failed" };
    }
  }
}

chrome.runtime.onMessage.addListener((req: PopupRequest, sender, sendResponse) => {
  // 只接受扩展自己的页面（弹窗），拒绝任何来自网页上下文的消息
  if (sender.id !== chrome.runtime.id || sender.tab) return false;
  handle(req).then(sendResponse, () => sendResponse({ state: { status: "error", error: "internal" } }));
  return true;
});
