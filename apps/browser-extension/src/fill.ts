// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 在页面中填充凭据。通过 chrome.scripting.executeScript 注入，运行在扩展的隔离环境中。
// 函数会被序列化后注入，因此必须自包含：不能引用本文件以外的任何东西。

export type FillOutcome = "filled" | "origin_changed" | "no_password_field";

export function fillPage(username: string, password: string, expectedOrigin: string): FillOutcome {
  // 用户点击填充之后、注入之前，页面可能已经跳转到其他网站
  if (location.origin !== expectedOrigin) return "origin_changed";

  // 只填充真正可见的字段：防止隐藏表单批量窃取凭据（docs/security.md §12）
  const visible = (el: HTMLElement): boolean => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 1 && r.height > 1 && s.visibility !== "hidden" && s.display !== "none" && Number(s.opacity) > 0.1;
  };

  const password_field = Array.from(document.querySelectorAll<HTMLInputElement>('input[type="password"]')).find(visible);
  if (!password_field) return "no_password_field";

  const scope: ParentNode = password_field.form ?? document;
  const before = Array.from(
    scope.querySelectorAll<HTMLInputElement>('input[type="email"], input[type="text"], input[type="tel"], input:not([type])'),
  ).filter((el) => visible(el) && (el.compareDocumentPosition(password_field) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0);
  const username_field = before.at(-1);

  // 用原型上的 setter 赋值，React 等框架受控的输入框才能感知变化
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  const set = (el: HTMLInputElement, value: string): void => {
    setter?.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  if (username_field && username) set(username_field, username);
  set(password_field, password);
  return "filled";
}
