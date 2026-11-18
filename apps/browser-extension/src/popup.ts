// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 弹窗：显示连接状态、配对验证码，以及当前网站的候选条目。弹窗本身不持有任何密钥。

import type { Candidate, PopupRequest, PopupResponse, ViewState } from "./types.js";

const root = document.getElementById("app") as HTMLElement;
let lastKey = "";

function ask(req: PopupRequest): Promise<PopupResponse> {
  return chrome.runtime.sendMessage(req) as Promise<PopupResponse>;
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, cls?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

const SITE_COLORS = 8;

/**
 * 网站图标：首字母 + 按域名选取的颜色，与 macOS 应用共用同一算法（design/README.md「网站图标」）：
 * key = 去掉 www. 的小写主机名，index = FNV-1a-32(UTF-8(key)) mod 8。
 */
function siteIcon(title: string, origin: string): HTMLElement {
  let key = title;
  try {
    const host = new URL(origin).hostname.toLowerCase();
    key = host.startsWith("www.") ? host.slice(4) : host;
  } catch {
    // 没有网址时按标题取色
  }
  let hash = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(key)) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  const source = title.trim() || key;
  const [first] = new Intl.Segmenter().segment(source);
  const icon = el("div", (first?.segment ?? "?").toUpperCase(), "site-icon");
  icon.style.background = `var(--kv-site-${(hash % SITE_COLORS) + 1})`;
  icon.setAttribute("aria-hidden", "true");
  return icon;
}

const ERRORS: Record<string, string> = {
  host_not_installed: "没有找到 Keevo 的本机组件。请先运行 scripts/install-native-host-dev.sh。",
  service_unavailable: "未能连接 Keevo。请确认开发服务正在运行。",
  disconnected: "与 Keevo 的连接已断开。",
  not_paired: "Keevo 不认识这个浏览器了，请重新配对。",
  pairing_rejected: "配对已被拒绝或超时。",
  pairing_limited: "Keevo 正在处理另一个配对，或配对尝试过于频繁，请稍后再试。",
  bad_request: "通信出错，请重试。",
  protocol: "通信出错，请重试。",
};

function render(state: ViewState, candidates: Candidate[] = [], origin = "", note = ""): void {
  root.replaceChildren();
  const header = el("header");
  header.append(el("h1", "Keevo"), el("span", "开发版", "badge"));
  root.append(header);

  switch (state.status) {
    case "idle":
    case "connecting":
    case "pairing":
      root.append(el("p", "正在连接 Keevo…", "muted"));
      break;
    case "unpaired": {
      root.append(el("p", "这个浏览器还没有与 Keevo 配对。"));
      const b = el("button", "与 Keevo 配对");
      b.onclick = () => void ask({ type: "pair" }).then(update);
      root.append(b);
      break;
    }
    case "awaiting_confirm": {
      root.append(el("p", "请确认 Keevo 中显示的验证码与下方一致，并在 Keevo 中确认："));
      const sas = el("div", undefined, "sas");
      sas.setAttribute("aria-label", `验证码 ${state.sas.match(/../g)?.join(" ") ?? state.sas}`);
      for (const group of state.sas.match(/../g) ?? [state.sas]) sas.append(el("span", group));
      root.append(sas);
      break;
    }
    case "error": {
      root.append(el("div", ERRORS[state.error] ?? `出错了（${state.error}）`, "banner danger"));
      const b = el("button", "重新配对");
      b.onclick = () => void ask({ type: "pair" }).then(update);
      root.append(b);
      break;
    }
    case "connected":
      if (state.locked) {
        root.append(el("p", "Keevo 已锁定，请在应用中解锁。", "muted"));
        break;
      }
      if (origin) root.append(el("p", origin, "origin"));
      if (candidates.length === 0) root.append(el("p", "当前网站没有匹配的登录。", "muted"));
      for (const c of candidates) {
        const row = el("div", undefined, "item");
        const text = el("div", undefined, "text");
        text.append(el("div", c.title, "title"), el("div", c.subtitle, "subtitle"));
        const b = el("button", "填充");
        b.onclick = async () => {
          const r = await ask({ type: "fill", itemId: c.item_id });
          const done: Record<string, string> = {
            filled: "已填充。",
            no_password_field: "页面上没有找到可见的密码框。",
            origin_changed: "页面已跳转到其他网站，已取消填充。",
            url_mismatch: "这个条目与当前网站不匹配，已拒绝填充。",
          };
          if (r.fill === "filled") window.close();
          else render(r.state, candidates, origin, done[r.fill ?? ""] ?? "填充失败。");
        };
        row.append(siteIcon(c.title, origin), text, b);
        root.append(row);
      }
      break;
  }
  if (note) root.append(el("div", note, "banner warning"));
}

async function update(): Promise<void> {
  const { state } = await ask({ type: "state" });
  const key = JSON.stringify(state);
  if (key === lastKey) return;
  lastKey = key;
  if (state.status === "connected" && !state.locked) {
    const r = await ask({ type: "candidates" });
    render(r.state, r.candidates, r.origin);
  } else {
    render(state);
  }
}

void update();
// 配对确认与锁定状态变化需要轮询；弹窗关闭时随之停止
setInterval(() => void update(), 500);
