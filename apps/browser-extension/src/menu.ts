// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 页内菜单（扩展源的 iframe，由内容脚本挂在输入框下方）：列出与这个帧的网站匹配的条目，用户选择后填充。
//
// 点击劫持防护（docs/security.md §12）：
// - 用 IntersectionObserver v2（trackVisibility）判断菜单是否真的可见：被遮挡、透明、加滤镜或变形都算不可见；
// - 连续可见满 500 毫秒后才接受点击，防止页面在用户点击的瞬间把菜单移到光标下；
// - 只接受可信事件；持续不可见（超过 1 秒）时被点击，关闭菜单并改用工具栏中的 Keevo 弹窗（降级为弹窗内确认）。
//   菜单改变大小或位置时可能短暂判定为不可见，这时的点击同样不填充，但不关闭菜单；
// - 菜单只拿到条目概要；凭据由 Service Worker 直接发给发起菜单的那个帧，不经过这里。

import type { Candidate, MenuInit, MenuRequest, MenuResponse } from "./types.js";

const root = document.getElementById("app") as HTMLElement;
const MIN_VISIBLE_MS = 500;
/** 持续不可见超过这个时间还被点击，判定为被遮挡或透明（可能是点击劫持）。 */
const BLOCKED_AFTER_MS = 1000;

function ask(req: MenuRequest): Promise<MenuResponse> {
  return chrome.runtime.sendMessage(req) as Promise<MenuResponse>;
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, cls?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

// ---- 可见性

let visibleSince: number | null = null;
/** 最近一次变为不可见的时刻（从未可见过时为页面加载时刻）。 */
let hiddenSince = performance.now();

/** 已连续可见足够久，可以接受点击。 */
function ready(): boolean {
  return visibleSince !== null && performance.now() - visibleSince >= MIN_VISIBLE_MS;
}

function updateReady(): void {
  document.body.classList.toggle("armed", ready());
}

const observer = new IntersectionObserver(
  (entries) => {
    for (const e of entries) {
      const v = (e as IntersectionObserverEntry & { isVisible?: boolean }).isVisible === true;
      if (v && visibleSince === null) {
        visibleSince = performance.now();
        setTimeout(updateReady, MIN_VISIBLE_MS + 10);
      } else if (!v && visibleSince !== null) {
        visibleSince = null;
        hiddenSince = performance.now();
      }
      updateReady();
    }
  },
  // trackVisibility 与 delay 是 v2 的选项（lib.dom 尚未收录）
  { threshold: [1], trackVisibility: true, delay: 100 } as IntersectionObserverInit,
);
observer.observe(document.body);

/** 点击前的检查。不通过、且菜单已持续不可见一段时间时，关闭菜单并请用户改用弹窗。 */
function guard(e: Event): boolean {
  if (!e.isTrusted) return false;
  if (ready()) return true;
  if (visibleSince === null && performance.now() - hiddenSince >= BLOCKED_AFTER_MS) void ask({ type: "menu_blocked" });
  return false;
}

// ---- 渲染

const MESSAGES: Record<string, string> = {
  unpaired: "这个浏览器还没有与 Keevo 配对。请点击工具栏中的 Keevo 图标完成配对。",
  locked: "Keevo 已锁定，请在 Keevo 中解锁。",
  connecting: "正在连接 Keevo…",
  error: "暂时无法连接 Keevo。请点击工具栏中的 Keevo 图标查看。",
  no_session: "菜单已过期，请重新点击输入框旁的图标。",
};

const ERRORS: Record<string, string> = {
  not_authorized: "没有得到授权：在 Keevo 中被拒绝或超时，或者这个浏览器的填充已被暂停。",
  url_mismatch: "这个条目与当前网站不匹配，已拒绝。",
  not_found: "这个条目已不存在。",
  locked: "Keevo 已锁定，请在 Keevo 中解锁。",
  origin_changed: "页面已跳转到其他网站，已取消填充。",
  no_password_field: "没有找到可以填充的密码框。",
  no_field: "没有找到可以填入的输入框。",
  no_totp: "这个条目没有一次性密码。",
  failed: "填充没有完成，请重试。",
};

let init: MenuInit | null = null;
let pendingConfirm: string | null = null;
let busy = false;

function host(origin: string): string {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
}

function render(note?: { kind: "info" | "danger"; text: string }): void {
  root.replaceChildren();
  if (!init) return;
  const head = el("div", undefined, "head");
  head.append(el("span", init.kind === "otp" ? "填入一次性密码到" : "填充到", "label"), el("span", host(init.origin), "site"));
  root.append(head);
  if (init.message) {
    root.append(el("p", MESSAGES[init.message] ?? MESSAGES.error, "muted"));
  } else {
    if (init.topOrigin !== init.origin) {
      const warn = el(
        "p",
        `这个输入框嵌在 ${init.topOrigin ? host(init.topOrigin) : "另一个网站"} 的页面中，来自 ${host(init.origin)}。确认这是你要登录的网站再填充。`,
        "banner warning",
      );
      root.append(warn);
    }
    const items = init.candidates;
    if (items.length === 0) {
      root.append(el("p", "这个网站没有匹配的登录。", "muted"));
      root.append(
        el("p", "Keevo 只在条目中保存的网站上填充。如果这是你常用的网站，网址却对不上，可能是仿冒网站。", "hint"),
      );
    }
    const list = el("div", undefined, "list");
    list.setAttribute("role", "listbox");
    items.forEach((c) => list.append(row(c)));
    root.append(list);
  }
  if (note) root.append(el("p", note.text, `banner ${note.kind}`));
  updateReady();
  // body 的高度就是内容的高度；documentElement.scrollHeight 不会小于 iframe 当前的高度，菜单只会变高不会变矮
  void ask({ type: "menu_size", height: Math.ceil(document.body.getBoundingClientRect().height) });
}

function row(c: Candidate): HTMLElement {
  const b = el("button", undefined, "item");
  b.type = "button";
  b.setAttribute("role", "option");
  b.disabled = busy;
  const text = el("span", undefined, "text");
  text.append(el("span", c.title, "title"), el("span", c.subtitle, "subtitle"));
  b.append(text);
  if (pendingConfirm === c.item_id) b.append(el("span", "再次点击确认", "confirm"));
  b.addEventListener("click", (e) => {
    if (!guard(e) || busy) return;
    void choose(c);
  });
  return b;
}

async function choose(c: Candidate): Promise<void> {
  if (!init) return;
  // 跨域 iframe 中的输入框：第一次点击只要求确认（docs/security.md §12）
  if (init.topOrigin !== init.origin && pendingConfirm !== c.item_id) {
    pendingConfirm = c.item_id;
    render({ kind: "info", text: `再次点击「${c.title}」，确认填充到 ${host(init.origin)}。` });
    return;
  }
  busy = true;
  render({ kind: "info", text: "正在向 Keevo 取用。第一次在这个网站上使用这个条目时，请在 Keevo 中确认。" });
  const r = await ask({ type: "menu_fill", itemId: c.item_id, confirmed: pendingConfirm === c.item_id });
  busy = false;
  pendingConfirm = null;
  // 成功时内容脚本会关闭菜单；走到这里说明没有填上
  if (r.fill !== "filled") render({ kind: "danger", text: ERRORS[r.error ?? r.fill ?? "failed"] ?? ERRORS.failed ?? "" });
}

// ---- 键盘：↑↓ 移动，回车选择（按钮的默认行为），Esc 关闭

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    void ask({ type: "menu_close" });
    return;
  }
  if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
  const buttons = Array.from(document.querySelectorAll<HTMLButtonElement>("button.item"));
  if (buttons.length === 0) return;
  e.preventDefault();
  const i = buttons.indexOf(document.activeElement as HTMLButtonElement);
  const next = e.key === "ArrowDown" ? (i + 1) % buttons.length : (i - 1 + buttons.length) % buttons.length;
  buttons[next]?.focus();
});
addEventListener("focus", () => {
  if (document.activeElement === document.body) document.querySelector<HTMLButtonElement>("button.item")?.focus();
});

void ask({ type: "menu_init" }).then((r) => {
  init = r.init ?? null;
  render();
  document.querySelector<HTMLButtonElement>("button.item")?.focus();
});
