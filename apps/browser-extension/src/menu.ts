// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 页内菜单（扩展源的 iframe，由内容脚本挂在输入框下方）：列出与这个帧的网站匹配的条目，用户选择后填充。
//
// 点击劫持防护见 guard.ts（docs/security.md §12）。
// - 菜单只拿到条目概要；凭据由 Service Worker 直接发给发起菜单的那个帧，不经过这里。

import { t } from "./i18n.js";
import { logoMark, siteIcon } from "./brand.js";
import { createGuard } from "./guard.js";
import type { Candidate, MenuInit, MenuRequest, MenuResponse } from "./types.js";

const root = document.getElementById("app") as HTMLElement;

function ask(req: MenuRequest): Promise<MenuResponse> {
  return chrome.runtime.sendMessage(req) as Promise<MenuResponse>;
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, cls?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

// ---- 可见性（点击劫持防护，见 guard.ts）

const guard = createGuard(document.body, () => void ask({ type: "menu_blocked" }));

function updateReady(): void {
  document.body.classList.toggle("armed", guard.ready());
}

// ---- 渲染

const MESSAGES: Record<string, string> = {
  unpaired: t("这个浏览器还没有与 Keevo 配对。请点击工具栏中的 Keevo 图标完成配对。"),
  locked: t("Keevo 已锁定，请在 Keevo 中解锁。"),
  connecting: t("正在连接 Keevo…"),
  error: t("暂时无法连接 Keevo。请点击工具栏中的 Keevo 图标查看。"),
  no_session: t("菜单已过期，请重新点击输入框旁的图标。"),
  limited: t("这个浏览器短时间内查询了太多网站，Keevo 暂时停止回答。请在 Keevo 中查看。"),
};

const ERRORS: Record<string, string> = {
  not_authorized: t("没有得到授权：在 Keevo 中被拒绝或超时，或者这个浏览器的填充已被暂停。"),
  url_mismatch: t("这个条目与当前网站不匹配，已拒绝。"),
  not_found: t("这个条目已不存在。"),
  locked: t("Keevo 已锁定，请在 Keevo 中解锁。"),
  origin_changed: t("页面已跳转到其他网站，已取消填充。"),
  no_password_field: t("没有找到可以填充的密码框。"),
  no_field: t("没有找到可以填入的输入框。"),
  no_totp: t("这个条目没有一次性密码。"),
  failed: t("填充没有完成，请重试。"),
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
  head.append(
    logoMark(16),
    el("span", init.kind === "otp" ? t("Keevo · 一次性密码填入") : t("Keevo · 填充到"), "label"),
    el("span", host(init.origin), "site"),
  );
  root.append(head);
  if (init.message) {
    root.append(el("p", MESSAGES[init.message] ?? MESSAGES.error, "muted"));
  } else {
    if (init.crossSite) {
      const warn = el(
        "p",
        t("嵌在 {} 的页面中", String(init.topOrigin ? host(init.topOrigin) : t("另一个网站"))),
        "banner warning",
      );
      root.append(warn);
    }
    const items = init.candidates;
    if (items.length === 0) {
      // 没有匹配时提醒仿冒网站的可能（设计稿"钓鱼网站"）：用警示样式，而不是普通的灰字
      const warn = el("div", undefined, "banner warning");
      warn.append(
        el("strong", t("这个网站没有匹配的登录。")),
        document.createTextNode(t("如果这是你常用的网站，网址却对不上，可能是仿冒网站。")),
      );
      root.append(warn);
    }
    const list = el("div", undefined, "list");
    list.setAttribute("role", "listbox");
    items.forEach((c) => list.append(row(c)));
    root.append(list);
    if (items.length > 0) root.append(el("p", t("↑↓ 选择 · ↩ 填充 · Esc 关闭"), "keys"));
  }
  if (note) root.append(el("p", note.text, `banner ${note.kind}`));
  updateReady();
  // 报告内容本身（main）的高度：body 与菜单窗口一样大，scrollHeight 也不会小于窗口，用它们菜单只会变高不会变矮
  void ask({ type: "menu_size", height: Math.ceil(root.getBoundingClientRect().height) });
}

function row(c: Candidate): HTMLElement {
  const b = el("button", undefined, "item");
  b.type = "button";
  b.setAttribute("role", "option");
  b.disabled = busy;
  const text = el("span", undefined, "text");
  text.append(el("span", c.title, "title"), el("span", c.subtitle, "subtitle"));
  b.append(siteIcon(c.title, init?.origin ?? ""), text);
  if (pendingConfirm !== c.item_id) {
    const enter = el("span", "↩", "enter");
    enter.setAttribute("aria-hidden", "true");
    b.append(enter);
  }
  if (pendingConfirm === c.item_id) b.append(el("span", t("再次点击确认"), "confirm"));
  b.addEventListener("click", (e) => {
    if (!guard.check(e) || busy) return;
    void choose(c);
  });
  return b;
}

async function choose(c: Candidate): Promise<void> {
  if (!init) return;
  // 跨站 iframe 中的输入框：第一次点击只要求确认（docs/security.md §12）；同站的 iframe 与顶层一样
  if (init.crossSite && pendingConfirm !== c.item_id) {
    pendingConfirm = c.item_id;
    render({ kind: "info", text: t("再点一次「{}」填充", String(c.title)) });
    return;
  }
  busy = true;
  render({ kind: "info", text: t("正在向 Keevo 取用。第一次在这个网站使用时，请在 Keevo 中确认") });
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
