// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 保存栏（扩展源的 iframe，由内容脚本挂在页面顶部）：用户提交登录表单后，询问是否保存到 Keevo，
// 或更新已有条目的密码（协议 v2，spec/ipc.md §5.5）。
//
// - 只拿到要保存的站点、用户名与条目标题，不拿到密码：密码留在 Service Worker 的内存中，3 分钟后丢弃；
// - 点击劫持防护与页内菜单相同（guard.ts）；
// - 更新会覆盖已有数据，Keevo.app 还会再请用户确认一次。

import { createGuard } from "./guard.js";
import type { BarInit, BarRequest, BarResponse } from "./types.js";

const root = document.getElementById("app") as HTMLElement;

function ask(req: BarRequest): Promise<BarResponse> {
  return chrome.runtime.sendMessage(req) as Promise<BarResponse>;
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, cls?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

const guard = createGuard(document.body, () => void ask({ type: "bar_close" }));

const ERRORS: Record<string, string> = {
  not_authorized: "没有保存：在 Keevo 中被拒绝或超时，或者短时间内保存了太多条目。",
  locked: "Keevo 已锁定，请解锁后再试。",
  url_mismatch: "这个条目与当前网站不匹配，没有更新。",
  not_found: "这个条目已不存在。",
  expired: "这次提交已过期。",
  unsupported: "这个版本的 Keevo 还不能从浏览器保存，请更新 Keevo。",
  failed: "没有保存成功，请重试。",
};

let init: BarInit | null = null;
let busy = false;

function action(text: string, cls: string, onClick: () => void): HTMLButtonElement {
  const b = el("button", text, cls);
  b.type = "button";
  b.disabled = busy;
  b.addEventListener("click", (e) => {
    if (!guard.check(e) || busy) return;
    onClick();
  });
  return b;
}

function render(note?: { kind: "info" | "danger" | "success"; text: string }): void {
  root.replaceChildren();
  if (!init) {
    root.append(el("p", ERRORS.expired ?? "", "muted"));
    return;
  }
  const text = el("div", undefined, "text");
  const what = init.kind === "update" ? `更新 Keevo 中「${init.title}」的密码？` : "保存这个登录到 Keevo？";
  const detail = [init.host, init.username].filter(Boolean).join(" · ");
  text.append(el("div", what, "title"), el("div", note?.text ?? detail, note ? `subtitle ${note.kind}` : "subtitle"));
  const buttons = el("div", undefined, "buttons");
  if (note?.kind !== "success") {
    buttons.append(
      action(init.kind === "update" ? "更新" : "保存", "primary", () => void save()),
      action(init.kind === "update" ? "不更新" : "不保存", "secondary", () => void ask({ type: "bar_dismiss" })),
    );
    if (init.kind === "save") {
      buttons.append(action("此网站不再提示", "link", () => void ask({ type: "bar_never" })));
    }
  }
  root.append(text, buttons);
  document.body.classList.toggle("armed", guard.ready());
}

async function save(): Promise<void> {
  if (!init) return;
  busy = true;
  render({
    kind: "info",
    text: init.kind === "update" ? "请在 Keevo 中确认更新…" : "正在保存…",
  });
  const r = await ask({ type: "bar_save" });
  busy = false;
  if (r.ok) {
    render({ kind: "success", text: init.kind === "update" ? "密码已更新。" : "已保存到 Keevo。" });
    setTimeout(() => void ask({ type: "bar_close" }), 2000);
  } else {
    render({ kind: "danger", text: ERRORS[r.error ?? "failed"] ?? ERRORS.failed ?? "" });
  }
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") void ask({ type: "bar_dismiss" });
});

void ask({ type: "bar_init" }).then((r) => {
  init = r.init ?? null;
  render();
});
