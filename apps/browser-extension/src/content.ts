// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 内容脚本（隔离环境，所有帧）：识别登录字段、在输入框旁显示 Keevo 图标、打开页内菜单、执行填充；
// 检测登录表单的提交，在顶层帧显示保存栏（协议 v2，spec/ipc.md §5.5）。
//
// - 只在可信的用户手势后打开菜单（event.isTrusted），从不在页面加载时自动填充（docs/security.md §12）；
// - 图标与菜单挂在封闭的 shadow root 中，并用 popover 置于顶层；菜单本身是扩展源的 iframe（menu.html），
//   页面读不到其中的内容；样式全部用 CSSOM 设置，不受页面 CSP 的 style-src 限制；
// - 这里不持有任何密钥：凭据只在填充的瞬间经过，填完即丢弃；
// - 由 manifest 动态注册（标准模式），或在弹窗与快捷键时由 Service Worker 注入（最小权限模式），
//   因此必须是普通脚本、不能 import，并且重复注入时只初始化一次。

(() => {
  const FLAG = "__keevoContent";
  const scope = globalThis as unknown as Record<string, unknown>;
  if (scope[FLAG]) return;
  scope[FLAG] = true;

  type Kind = "login" | "otp";
  type FillOutcome = "filled" | "origin_changed" | "no_password_field" | "no_field";

  interface FillMessage {
    type: "fill";
    origin: string;
    username: string;
    password: string;
    totp?: string;
    /** 填入页内菜单的锚点字段（菜单发起时），否则自动寻找页面中的登录表单（弹窗发起时）。 */
    anchored: boolean;
    kind: Kind;
  }
  type Incoming =
    | FillMessage
    | { type: "close_menu" }
    | { type: "menu_size"; height: number }
    | { type: "open_menu" }
    | { type: "show_bar" }
    | { type: "close_bar" };

  const ICON_SIZE = 20;
  const MENU_WIDTH = 320;

  let anchor: HTMLInputElement | null = null;
  let anchorKind: Kind = "login";
  let icon: { host: HTMLElement; button: HTMLButtonElement } | null = null;
  let menu: { host: HTMLElement; frame: HTMLIFrameElement; above: boolean | null; raises: number } | null = null;
  let bar: { host: HTMLElement; raises: number } | null = null;
  /** 页面在菜单之后打开顶层元素时，最多把菜单重新放到最上面几次（防止与页面无休止地互相抢）。 */
  const MAX_RAISES = 3;

  // ---- 字段识别

  /** 真正可见的字段：防止隐藏表单批量窃取凭据（docs/security.md §12）。 */
  function visible(el: HTMLElement): boolean {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 1 && r.height > 1 && s.visibility !== "hidden" && s.display !== "none" && Number(s.opacity) > 0.1;
  }

  const TEXTUAL = new Set(["text", "email", "tel", ""]);
  const USER_HINT = /user|login|email|account|mail|phone|账号|帐号|用户|邮箱|手机/i;

  function autocomplete(el: HTMLInputElement): string[] {
    return (el.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/);
  }

  /** 在 root 中查询，并递归进入开放的 shadow root（网页组件中的登录表单）。封闭的 shadow root 读不到。 */
  function deepQuery<T extends Element>(root: ParentNode, selector: string): T[] {
    const out = Array.from(root.querySelectorAll<T>(selector));
    for (const el of Array.from(root.querySelectorAll("*"))) {
      if (el.shadowRoot) out.push(...deepQuery<T>(el.shadowRoot, selector));
    }
    return out;
  }

  /** 字段所在的范围：表单，否则是它所在的文档或 shadow root。 */
  function scopeOfField(el: HTMLInputElement): ParentNode {
    return el.form ?? (el.getRootNode() as Document | ShadowRoot);
  }

  /** 可以填写的字段：可见、没有禁用、不是只读。 */
  function editable(el: HTMLInputElement): boolean {
    return !el.disabled && !el.readOnly && visible(el);
  }

  function passwordFields(root: ParentNode): HTMLInputElement[] {
    const all = deepQuery<HTMLInputElement>(root, 'input[type="password"]').filter(editable);
    // 注册页的"新密码"留给保存与生成功能；只有它们时才退而使用
    const current = all.filter((el) => !autocomplete(el).includes("new-password"));
    return current.length > 0 ? current : all;
  }

  /** 位于密码框之前的最后一个可见文本框：通常就是用户名。 */
  function usernameBefore(password: HTMLInputElement): HTMLInputElement | undefined {
    return deepQuery<HTMLInputElement>(
      scopeOfField(password),
      'input[type="email"], input[type="text"], input[type="tel"], input:not([type])',
    )
      .filter((el) => editable(el) && (el.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0)
      .at(-1);
  }

  /** 没有 autocomplete 标注的验证码框：名称或提示看起来像一次性密码。 */
  const OTP_HINT = /one.?time|otp|totp|2fa|mfa|two.?factor|verification.?code|auth.?code|security.?code|验证码|动态码|校验码/i;

  function classify(target: EventTarget | null): Kind | null {
    if (!(target instanceof HTMLInputElement) || target.disabled || target.readOnly) return null;
    const ac = autocomplete(target);
    if (ac.includes("one-time-code")) return "otp";
    if (target.type === "password") return ac.includes("new-password") ? null : "login";
    if (!TEXTUAL.has(target.type) && target.type !== "number") return null;
    if (ac.includes("username")) return "login";
    const hint = [target.name, target.id, target.placeholder, target.getAttribute("aria-label") ?? ""].join(" ");
    // 验证码框常标为数字输入、最多 8 位
    const short = target.maxLength > 0 && target.maxLength <= 8;
    if (OTP_HINT.test(hint) && (short || target.inputMode === "numeric" || target.type === "number" || target.type === "tel")) {
      return "otp";
    }
    if (target.type === "number") return null;
    // 与密码框同在一个表单中、看起来像用户名的文本框，或密码框之前的那个文本框
    const password = passwordFields(scopeOfField(target))[0];
    if (!password) return null;
    return USER_HINT.test(hint) || ac.includes("email") || usernameBefore(password) === target ? "login" : null;
  }

  // ---- 顶层宿主

  /** 一个置于顶层（popover）的宿主元素，内容在封闭的 shadow root 中。样式用 CSSOM 设置并标为 important。 */
  function topLayerHost(width: number, height: number): { host: HTMLElement; root: ShadowRoot } {
    const host = document.createElement("div");
    host.setAttribute("popover", "manual");
    const style: Record<string, string> = {
      position: "fixed",
      inset: "auto",
      margin: "0",
      padding: "0",
      border: "0",
      background: "transparent",
      overflow: "visible",
      width: `${width}px`,
      height: `${height}px`,
      opacity: "1",
      transform: "none",
      filter: "none",
      "pointer-events": "auto",
      "color-scheme": "normal",
    };
    for (const [k, v] of Object.entries(style)) host.style.setProperty(k, v, "important");
    const root = host.attachShadow({ mode: "closed" });
    document.documentElement.append(host);
    host.showPopover();
    return { host, root };
  }

  function place(host: HTMLElement, left: number, top: number): void {
    host.style.setProperty("left", `${Math.round(left)}px`, "important");
    host.style.setProperty("top", `${Math.round(top)}px`, "important");
  }

  // ---- 图标

  /** Keevo 标志中的盾形（与 brand.ts 的 SHIELD_PATH 相同；内容脚本不是模块，不能导入）。 */
  function shieldGlyph(): SVGSVGElement {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 20 20");
    svg.setAttribute("width", "13");
    svg.setAttribute("height", "13");
    svg.setAttribute("aria-hidden", "true");
    const path = document.createElementNS(ns, "path");
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", "currentColor");
    path.setAttribute("stroke-width", "2");
    path.setAttribute("stroke-linejoin", "round");
    path.setAttribute("d", "M10 2.6 4.4 4.8v4.4c0 3.6 2.4 6.6 5.6 7.8 3.2-1.2 5.6-4.2 5.6-7.8V4.8L10 2.6Z");
    svg.append(path);
    return svg;
  }

  function showIcon(field: HTMLInputElement): void {
    const label = anchorKind === "otp" ? "用 Keevo 填入一次性密码" : "用 Keevo 填充";
    if (icon) {
      icon.button.setAttribute("aria-label", label);
      icon.button.title = label;
    }
    if (!icon) {
      const { host, root } = topLayerHost(ICON_SIZE, ICON_SIZE);
      const button = document.createElement("button");
      button.type = "button";
      button.setAttribute("aria-label", label);
      button.title = label;
      const s: Record<string, string> = {
        all: "initial",
        width: `${ICON_SIZE}px`,
        height: `${ICON_SIZE}px`,
        display: "grid",
        "place-items": "center",
        border: "0",
        "border-radius": "6px",
        // 设计令牌 accent.fill（内容脚本运行在网页中，不能引用 tokens.css）
        background: "#127F71",
        color: "#ffffff",
        cursor: "pointer",
        "box-shadow": "0 1px 2px rgba(0,0,0,.25)",
      };
      for (const [k, v] of Object.entries(s)) button.style.setProperty(k, v);
      button.append(shieldGlyph());
      // 按下时阻止默认行为，避免输入框失去焦点、图标随之消失
      button.addEventListener("mousedown", (e) => e.preventDefault());
      button.addEventListener("click", (e) => {
        if (!e.isTrusted) return;
        if (menu) closeMenu(true);
        else void openMenu();
      });
      root.append(button);
      icon = { host, button };
    }
    positionIcon(field);
  }

  function positionIcon(field: HTMLInputElement): void {
    if (!icon) return;
    const r = field.getBoundingClientRect();
    place(icon.host, r.right - ICON_SIZE - 6, r.top + (r.height - ICON_SIZE) / 2);
  }

  function hideIcon(): void {
    icon?.host.remove();
    icon = null;
  }

  // ---- 页内菜单

  async function openMenu(): Promise<void> {
    if (!anchor || menu) return;
    const field = anchor;
    const r = (await chrome.runtime.sendMessage({ type: "inline_open", kind: anchorKind })) as { ok?: boolean } | undefined;
    if (!r?.ok || anchor !== field) return;
    const { host, root } = topLayerHost(MENU_WIDTH, 120);
    const frame = document.createElement("iframe");
    frame.src = chrome.runtime.getURL("menu.html");
    frame.title = "Keevo";
    frame.setAttribute("allow", "");
    for (const [k, v] of Object.entries({
      all: "initial",
      display: "block",
      width: "100%",
      height: "100%",
      border: "0",
      "border-radius": "10px",
      "box-shadow": "0 8px 24px rgba(0,0,0,.18), 0 0 0 1px rgba(0,0,0,.08)",
      "color-scheme": "normal",
      background: "transparent",
    })) {
      frame.style.setProperty(k, v);
    }
    root.append(frame);
    menu = { host, frame, above: null, raises: 0 };
    positionMenu(120);
    frame.addEventListener("load", () => frame.contentWindow?.focus(), { once: true });
  }

  function positionMenu(height: number): void {
    if (!menu || !anchor) return;
    const r = anchor.getBoundingClientRect();
    const left = Math.min(Math.max(8, r.left), Math.max(8, innerWidth - MENU_WIDTH - 8));
    // 第一次摆放时决定放在输入框下方还是上方，之后改变高度也不再翻转（避免菜单在用户眼前跳动）
    menu.above ??= r.bottom + 4 + height > innerHeight - 8 && r.top - height - 4 > 8;
    const top = menu.above ? r.top - height - 4 : r.bottom + 4;
    menu.host.style.setProperty("height", `${height}px`, "important");
    place(menu.host, left, top);
  }

  function closeMenu(refocus: boolean): void {
    if (!menu) return;
    menu.host.remove();
    menu = null;
    void chrome.runtime.sendMessage({ type: "inline_close" });
    if (refocus) anchor?.focus();
  }

  // ---- 填充

  function setValue(el: HTMLInputElement, value: string): void {
    // 用原型上的 setter 赋值，React 等框架受控的输入框才能感知变化
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function fill(m: FillMessage): FillOutcome {
    // 用户选择条目之后、凭据送达之前，页面可能已经跳转到其他网站
    if (location.origin !== m.origin) return "origin_changed";
    if (m.kind === "otp") {
      if (!m.anchored || !anchor || !editable(anchor) || !m.totp) return "no_field";
      setValue(anchor, m.totp);
      return "filled";
    }
    let password: HTMLInputElement | undefined;
    let username: HTMLInputElement | undefined;
    if (m.anchored && anchor && editable(anchor)) {
      if (anchor.type === "password") password = anchor;
      else username = anchor;
      password ??= passwordFields(scopeOfField(anchor))[0];
      if (password && !username) username = usernameBefore(password);
    } else {
      password = passwordFields(document)[0];
      if (password) username = usernameBefore(password);
    }
    // 分步登录（先输入用户名，下一页再输入密码）：这一步只填用户名
    if (!password && !(m.anchored && username)) return "no_password_field";
    if (username && m.username) setValue(username, m.username);
    if (password) setValue(password, m.password);
    return "filled";
  }

  // ---- 保存：检测登录表单的提交（只在标准模式下有内容脚本时工作）

  /** 提交时表单中的凭据。修改密码的表单取新密码。 */
  function captured(root: ParentNode): { username: string; password: string; change: boolean } | null {
    const all = deepQuery<HTMLInputElement>(root, 'input[type="password"]').filter((el) => el.value !== "");
    if (all.length === 0) return null;
    const fresh = all.filter((el) => autocomplete(el).includes("new-password"));
    const change = fresh.length > 0 || all.length >= 2;
    // 注册表单常有"确认密码"，修改密码表单是"当前 / 新 / 确认"：取新密码
    let password = all[0];
    if (fresh.length > 0) password = fresh[0];
    else if (all.length >= 3) password = all[1];
    else if (all.length === 2) password = all[all.length - 1];
    if (!password) return null;
    const first = all[0] as HTMLInputElement;
    const named = deepQuery<HTMLInputElement>(root, "input").find(
      (el) => autocomplete(el).includes("username") && el.value !== "",
    );
    const user = named ?? usernameBefore(first);
    return { username: user?.value.trim() ?? "", password: password.value, change };
  }

  let lastSubmit = "";
  function submitted(root: ParentNode): void {
    const creds = captured(root);
    if (!creds) {
      // 分步登录的第一步：只有用户名
      const user = Array.from(root.querySelectorAll<HTMLInputElement>("input")).find(
        (el) =>
          TEXTUAL.has(el.type) &&
          (autocomplete(el).includes("username") || autocomplete(el).includes("email") || el.type === "email") &&
          el.value !== "",
      );
      if (user) void chrome.runtime.sendMessage({ type: "username_step", username: user.value.trim() });
      return;
    }
    // 同一次提交可能同时触发点击、回车与 submit 事件
    const key = `${creds.username}\u0000${creds.password}`;
    if (key === lastSubmit) return;
    lastSubmit = key;
    setTimeout(() => {
      if (lastSubmit === key) lastSubmit = "";
    }, 2000);
    void chrome.runtime.sendMessage({ type: "submitted", ...creds });
  }

  function scopeOf(el: Element): ParentNode {
    return el.closest("form") ?? document;
  }

  document.addEventListener(
    "submit",
    (e) => {
      if (e.target instanceof HTMLFormElement) submitted(e.target);
    },
    true,
  );
  // 不用 <form> 的单页应用：点击提交按钮、在密码框中按回车
  const SUBMIT_TEXT = /登录|登入|注册|继续|下一步|提交|保存|log\s*in|sign\s*(in|up)|continue|next|submit|save/i;
  document.addEventListener(
    "click",
    (e) => {
      if (!e.isTrusted) return;
      const target = e.composedPath()[0];
      if (!(target instanceof Element)) return;
      const button = target.closest<HTMLElement>('button, input[type="submit"], [role="button"]');
      if (!button) return;
      const isSubmit =
        (button instanceof HTMLButtonElement && button.type === "submit" && button.form !== null) ||
        (button instanceof HTMLInputElement && button.type === "submit") ||
        SUBMIT_TEXT.test(button.textContent ?? (button instanceof HTMLInputElement ? button.value : ""));
      if (isSubmit) submitted(scopeOf(button));
    },
    true,
  );
  document.addEventListener(
    "keydown",
    (e) => {
      if (!e.isTrusted || e.key !== "Enter" || !(e.target instanceof HTMLInputElement)) return;
      if (e.target.type === "password" || classify(e.target) === "login") submitted(scopeOf(e.target));
    },
    true,
  );

  // ---- 保存栏（顶层帧）

  function showBar(): void {
    if (bar || window !== window.top) return;
    const width = Math.min(460, innerWidth - 16);
    const { host, root } = topLayerHost(width, 56);
    const frame = document.createElement("iframe");
    frame.src = chrome.runtime.getURL("bar.html");
    frame.title = "Keevo";
    for (const [k, v] of Object.entries({
      all: "initial",
      display: "block",
      width: "100%",
      height: "100%",
      border: "0",
      "border-radius": "10px",
      "box-shadow": "0 8px 24px rgba(0,0,0,.18), 0 0 0 1px rgba(0,0,0,.08)",
      "color-scheme": "normal",
    })) {
      frame.style.setProperty(k, v);
    }
    root.append(frame);
    place(host, (innerWidth - width) / 2, 12);
    bar = { host, raises: 0 };
  }

  function closeBar(): void {
    bar?.host.remove();
    bar = null;
  }

  // 提交后页面跳转：新页面加载时询问是否有待显示的保存栏
  if (window === window.top) {
    void chrome.runtime.sendMessage({ type: "offer_query" }).then(
      (r: { show?: boolean } | undefined) => {
        if (r?.show) showBar();
      },
      () => undefined,
    );
  }

  /** 当前获得焦点的元素，进入开放的 shadow root。 */
  function deepActive(): Element | null {
    let el = document.activeElement;
    while (el?.shadowRoot?.activeElement) el = el.shadowRoot.activeElement;
    return el;
  }

  // ---- 事件

  document.addEventListener(
    "focusin",
    (e) => {
      // 焦点在开放的 shadow root 中时，e.target 被改写为宿主元素：取事件路径上的第一个元素
      const target = e.composedPath()[0] ?? e.target;
      const kind = classify(target);
      if (!kind) return;
      if (menu && target !== anchor) closeMenu(false);
      anchor = target as HTMLInputElement;
      anchorKind = kind;
      if (visible(anchor)) showIcon(anchor);
    },
    true,
  );
  document.addEventListener(
    "focusout",
    () => {
      // 焦点进入菜单（iframe）时保留图标；稍后再判断，等新的焦点落定
      setTimeout(() => {
        if (!menu && deepActive() !== anchor) hideIcon();
      }, 150);
    },
    true,
  );
  // 页面中的按下都在菜单之外（菜单内的事件留在扩展的 iframe 中）；图标自己处理开关
  document.addEventListener(
    "pointerdown",
    (e) => {
      if (!menu || !e.isTrusted || (icon && e.composedPath().includes(icon.host))) return;
      closeMenu(false);
    },
    true,
  );
  document.addEventListener(
    "keydown",
    (e) => {
      if (!e.isTrusted || !anchor || e.composedPath()[0] !== anchor) return;
      if (e.key === "Escape" && menu) closeMenu(true);
      // 在字段中按 ↓：菜单已打开时把焦点移入菜单；字段为空时打开菜单。
      // 字段有内容时不拦截，留给浏览器自带的自动填充下拉
      if (e.key === "ArrowDown" && icon && (menu || anchor.value === "")) {
        e.preventDefault();
        if (menu) menu.frame.contentWindow?.focus();
        else void openMenu();
      }
    },
    true,
  );
  // 页面在菜单之后打开自己的顶层元素（popover、模态对话框）时，即使不重叠，它铺满视口的 ::backdrop
  // 也会让菜单被判为不可见（IntersectionObserver v2 不区分透明）。把菜单重新放到顶层最上面；
  // 页面反复抢回顶层时停止，菜单保持不可用，点击不会填充。toggle 不冒泡，但捕获阶段能收到。
  document.addEventListener(
    "toggle",
    (e) => {
      if ((e as ToggleEvent).newState !== "open") return;
      if (e.target === menu?.host || e.target === icon?.host || e.target === bar?.host) return;
      for (const surface of [bar, menu]) {
        if (!surface || surface.raises >= MAX_RAISES) continue;
        surface.raises += 1;
        surface.host.hidePopover();
        surface.host.showPopover();
      }
      if (menu && document.activeElement === menu.host) menu.frame.contentWindow?.focus();
    },
    true,
  );

  const reposition = (): void => {
    if (anchor && icon) positionIcon(anchor);
    if (menu) closeMenu(false);
  };
  addEventListener("scroll", reposition, true);
  addEventListener("resize", reposition);

  chrome.runtime.onMessage.addListener((m: Incoming, sender, sendResponse) => {
    // 只接受本扩展的 Service Worker
    if (sender.id !== chrome.runtime.id || sender.tab) return false;
    switch (m.type) {
      case "fill": {
        const outcome = fill(m);
        if (outcome === "filled") closeMenu(false);
        sendResponse(outcome);
        return false;
      }
      case "close_menu":
        closeMenu(true);
        return false;
      case "menu_size":
        positionMenu(Math.min(Math.max(Math.round(m.height), 60), 360));
        return false;
      case "show_bar":
        showBar();
        return false;
      case "close_bar":
        closeBar();
        return false;
      case "open_menu": {
        // 快捷键：用户按下快捷键时焦点所在的字段
        const focused = deepActive();
        const kind = document.hasFocus() ? classify(focused) : null;
        if (kind) {
          anchor = focused as HTMLInputElement;
          anchorKind = kind;
          showIcon(anchor);
          void openMenu();
        }
        sendResponse(kind !== null);
        return false;
      }
    }
    return false;
  });
})();
