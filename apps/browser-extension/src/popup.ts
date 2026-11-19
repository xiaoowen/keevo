// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 弹窗：配对（名称与 6 个词的配对码）、当前网站的候选条目（搜索、填充、复制、一次性密码）。
// 弹窗本身不持有任何密钥；秘密只在用户操作时向 Service Worker 取用，用完即丢弃。
//
// 键盘：搜索框中 ↑↓ 选择条目，回车填充，Esc 关闭弹窗。

import type { Candidate, PopupRequest, PopupResponse, SasWord, ViewState } from "./types.js";

const root = document.getElementById("app") as HTMLElement;

function ask(req: PopupRequest): Promise<PopupResponse> {
  return chrome.runtime.sendMessage(req) as Promise<PopupResponse>;
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, cls?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function button(text: string, onClick: () => void, cls?: string): HTMLButtonElement {
  const b = el("button", text, cls);
  b.type = "button";
  b.onclick = onClick;
  return b;
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
  host_not_installed: "没有找到 Keevo 的本机组件。请在 Keevo 的「设置 → 浏览器」中安装 Chrome 支持。",
  service_unavailable: "未能连接 Keevo。请确认 Keevo 正在运行。",
  disconnected: "与 Keevo 的连接已断开。",
  not_paired: "Keevo 不认识这个浏览器了，请重新配对。",
  pairing_rejected: "配对已被拒绝或超时。",
  pairing_limited: "Keevo 正在处理另一个配对，或配对尝试过于频繁，请稍后再试。",
  locked: "Keevo 已锁定。请先在 Keevo 中解锁。",
  not_authorized: "没有得到授权：在 Keevo 中被拒绝或超时，或者这个浏览器的填充已被暂停。",
  not_found: "这个条目已不存在。",
  url_mismatch: "这个条目与当前网站不匹配，已拒绝。",
  response_too_large: "这个条目的内容太长，无法自动填充。请在 Keevo 中复制。",
  no_tab: "没有找到当前标签页。",
  queries_limited: "这个浏览器短时间内查询了太多网站，Keevo 暂时停止回答。请在 Keevo 中查看。",
  bad_request: "通信出错，请重试。",
  protocol: "通信出错，请重试。",
  failed: "操作没有完成，请重试。",
};

const FILL_RESULTS: Record<string, string> = {
  no_password_field: "页面上没有找到可见的密码框。",
  origin_changed: "页面已跳转到其他网站，已取消填充。",
};

type NoteKind = "info" | "warning" | "danger" | "success";

interface View {
  state: ViewState;
  /** 这个浏览器在 Keevo 中的显示名（清洗后）。 */
  name: string;
  candidates: Candidate[];
  origin: string;
  query: string;
  selected: number;
  note: { kind: NoteKind; text: string } | null;
  /** 正在等待 Keevo（可能在等用户确认授权）。 */
  busy: boolean;
  /** 显示中的一次性密码。30 秒后自动隐藏（docs/ux.md §5）。 */
  totp: { itemId: string; code: string } | null;
  /** 用户点了"重新配对"：显示配对表单。 */
  repairing: boolean;
  /** 页内菜单已启用（已授予网站权限）。 */
  inline: boolean;
  /** 这个标签页的页内菜单因为被遮挡或变透明而关闭过。 */
  blocked: boolean;
}

const view: View = {
  state: { status: "idle" },
  name: "",
  candidates: [],
  origin: "",
  query: "",
  selected: 0,
  note: null,
  busy: false,
  totp: null,
  repairing: false,
  inline: false,
  blocked: false,
};
const SITE_ORIGINS = ["https://*/*", "http://*/*"];
let lastKey = "";
let totpTimer: ReturnType<typeof setTimeout> | undefined;

function filtered(): Candidate[] {
  const q = view.query.trim().toLocaleLowerCase();
  if (!q) return view.candidates;
  return view.candidates.filter(
    (c) => c.title.toLocaleLowerCase().includes(q) || c.subtitle.toLocaleLowerCase().includes(q),
  );
}

function setNote(kind: NoteKind, text: string): void {
  view.note = { kind, text };
}

// ---- 渲染

function render(): void {
  const searchFocused = document.activeElement?.id === "search";
  root.replaceChildren();
  const header = el("header");
  header.append(el("h1", "Keevo"), el("span", "开发版", "badge"));
  root.append(header);

  const s = view.state;
  if (view.repairing || s.status === "unpaired") renderPairForm();
  else {
    switch (s.status) {
      case "idle":
      case "connecting":
      case "pairing":
        root.append(el("p", "正在连接 Keevo…", "muted"));
        break;
      case "awaiting_confirm":
        renderSas(s.words);
        break;
      case "error":
        root.append(el("div", ERRORS[s.error] ?? `出错了（${s.error}）`, "banner danger"));
        root.append(
          button("重新配对", () => {
            view.repairing = true;
            render();
          }),
        );
        break;
      case "connected":
        if (s.locked) root.append(el("p", "Keevo 已锁定，请在 Keevo 中解锁。", "muted"));
        else renderItems(searchFocused);
        break;
    }
  }
  if (view.note) {
    const note = el("div", view.note.text, `banner ${view.note.kind}`);
    note.setAttribute("role", "status");
    root.append(note);
  }
}

function renderPairForm(): void {
  root.append(el("p", "这个浏览器还没有与 Keevo 配对。配对需要 Keevo 正在运行并已解锁。"));
  const label = el("label", "在 Keevo 中显示的名称", "field-label");
  const input = el("input");
  input.id = "pair-name";
  input.maxLength = 64;
  input.value = view.name || "Chrome";
  input.placeholder = "Chrome";
  label.htmlFor = input.id;
  const preview = el("p", "", "note");
  const showPreview = async (): Promise<void> => {
    const r = await ask({ type: "display_name", name: input.value });
    preview.textContent = r.name?.trim() ? `Keevo 中将显示为「${r.name}」` : "名称为空时显示为「Chrome」";
  };
  input.oninput = () => void showPreview();
  void showPreview();
  const go = button("与 Keevo 配对", () => {
    view.repairing = false;
    view.note = null;
    void ask({ type: "pair", name: input.value }).then((r) => {
      if (r.name) view.name = r.name;
      apply(r.state);
    });
  });
  input.onkeydown = (e) => {
    if (e.key === "Enter") go.click();
  };
  root.append(label, input, preview, go);
  input.focus();
  input.select();
}

/** 配对码：6 个词，与 Keevo.app 中显示的完全一致（spec/ipc.md §4.2，spec/sas-wordlist-v1.tsv）。 */
function renderSas(words: SasWord[]): void {
  root.append(el("p", "请在 Keevo 中逐个核对下面 6 个词，顺序也要一致，然后在 Keevo 中确认："));
  const grid = el("ol", undefined, "sas");
  grid.setAttribute("aria-label", `配对码：${words.map((w) => w.zh).join("、")}`);
  words.forEach((w, i) => {
    const cell = el("li");
    cell.append(el("span", String(i + 1), "sas-index"), el("span", w.zh, "sas-zh"), el("span", w.en, "sas-en"));
    grid.append(cell);
  });
  root.append(grid);
  if (view.name) root.append(el("p", `这个浏览器在 Keevo 中显示为「${view.name}」。`, "note"));
  root.append(
    el(
      "p",
      "Keevo 中会弹出确认窗口。如果没有出现，说明有程序在冒充 Keevo，请关闭这个弹窗，不要继续；如果词不一致，请在 Keevo 中选择「不一致」。",
      "note",
    ),
  );
}

function renderItems(refocus: boolean): void {
  const search = el("input");
  search.id = "search";
  search.type = "search";
  search.placeholder = "搜索当前网站的登录";
  search.setAttribute("aria-label", "搜索当前网站的登录");
  search.value = view.query;
  search.autocomplete = "off";
  const list = el("div", undefined, "list");
  list.setAttribute("role", "listbox");
  list.setAttribute("aria-label", "当前网站的登录");
  search.oninput = () => {
    view.query = search.value;
    view.selected = 0;
    renderList(list);
  };
  search.onkeydown = (e) => {
    const items = filtered();
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (items.length === 0) return;
      view.selected = (view.selected + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length;
      renderList(list);
    } else if (e.key === "Enter") {
      const c = items[view.selected];
      if (c && !view.busy) void fill(c);
    }
  };
  root.append(search);
  if (view.blocked) {
    root.append(
      el("div", "这个页面上的 Keevo 菜单被遮挡或变得透明，为了安全已经关闭。请在这里选择要填充的登录。", "banner warning"),
    );
  }
  if (view.origin) root.append(el("p", view.origin, "origin"));
  root.append(list);
  renderList(list);
  root.append(inlineSetting());
  if (view.name) root.append(el("p", `这个浏览器在 Keevo 中显示为「${view.name}」`, "footer"));
  if (refocus || !document.activeElement || document.activeElement === document.body) search.focus();
}

function renderList(list: HTMLElement): void {
  list.replaceChildren();
  const items = filtered();
  if (view.candidates.length === 0) list.append(el("p", "当前网站没有匹配的登录。", "muted"));
  else if (items.length === 0) list.append(el("p", "没有符合搜索的登录。", "muted"));
  items.forEach((c, i) => {
    const selected = i === view.selected;
    const row = el("div", undefined, selected ? "item selected" : "item");
    row.setAttribute("role", "option");
    row.setAttribute("aria-selected", String(selected));
    const main = el("div", undefined, "item-main");
    const text = el("div", undefined, "text");
    text.append(el("div", c.title, "title"), el("div", c.subtitle, "subtitle"));
    const fillButton = button("填充", () => void fill(c));
    fillButton.disabled = view.busy;
    main.append(siteIcon(c.title, view.origin), text, fillButton);
    main.onclick = (e) => {
      if (e.target === fillButton) return;
      view.selected = i;
      renderList(list);
    };
    row.append(main);
    if (selected) row.append(actions(c));
    list.append(row);
  });
}

/**
 * 标准模式开关：在输入框旁显示 Keevo 图标需要"读取和更改网站数据"的权限，默认不申请（最小权限模式），
 * 由用户在这里开启（docs/ux.md §4.5）。关闭后仍可用弹窗或快捷键填充。
 */
function inlineSetting(): HTMLElement {
  const row = el("div", undefined, "setting");
  const text = el("div", undefined, "text");
  text.append(
    el("div", "在输入框旁显示 Keevo 图标", "setting-title"),
    el("div", view.inline ? "已开启。刷新页面后生效。" : "需要读取和更改网站数据的权限。不开启时可用快捷键或这个弹窗填充。", "subtitle"),
  );
  const toggle = button(view.inline ? "关闭" : "开启", () => {
    // 权限请求必须是点击之后的第一个异步操作
    const change = view.inline
      ? chrome.permissions.remove({ origins: SITE_ORIGINS })
      : chrome.permissions.request({ origins: SITE_ORIGINS });
    void change.then(
      async () => {
        view.inline = await chrome.permissions.contains({ origins: SITE_ORIGINS });
        render();
      },
      () => undefined,
    );
  }, "secondary");
  row.append(text, toggle);
  return row;
}

/** 选中条目的更多操作：复制用户名、复制密码、一次性密码。 */
function actions(c: Candidate): HTMLElement {
  const bar = el("div", undefined, "actions");
  const copyUser = button("复制用户名", () => void copyUsername(c), "secondary");
  const copyPass = button("复制密码", () => void copySecret(c, "password"), "secondary");
  const otp = button("一次性密码", () => void showTotp(c), "secondary");
  for (const b of [copyUser, copyPass, otp]) b.disabled = view.busy;
  bar.append(copyUser, copyPass, otp);
  if (view.totp?.itemId === c.item_id) {
    const code = view.totp.code;
    const box = el("div", undefined, "totp");
    const digits = el("span", code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code, "totp-code");
    digits.setAttribute("aria-label", `一次性密码 ${code.split("").join(" ")}`);
    box.append(digits, button("复制", () => void copySecret(c, "totp"), "secondary"));
    bar.append(box);
  }
  return bar;
}

// ---- 操作

/** 等待 Keevo 期间的提示：第一次在某个网站上使用某个条目时，Keevo 会请用户确认（spec/ipc.md §5.2）。 */
function waiting(): void {
  view.busy = true;
  setNote("info", "正在向 Keevo 取用。第一次在这个网站上使用这个条目时，请在 Keevo 中确认。");
  render();
}

function failed(code: string | undefined): void {
  setNote("danger", ERRORS[code ?? "failed"] ?? `出错了（${code}）`);
}

async function fill(c: Candidate): Promise<void> {
  waiting();
  const r = await ask({ type: "fill", itemId: c.item_id });
  view.busy = false;
  view.state = r.state;
  if (r.fill === "filled") {
    window.close();
    return;
  }
  if (r.fill && FILL_RESULTS[r.fill]) setNote("warning", FILL_RESULTS[r.fill] ?? "");
  else failed(r.fill);
  render();
}

async function fetchSecret(c: Candidate): Promise<PopupResponse> {
  waiting();
  const r = await ask({ type: "secret", itemId: c.item_id });
  view.busy = false;
  view.state = r.state;
  return r;
}

async function copyUsername(c: Candidate): Promise<void> {
  const r = await fetchSecret(c);
  if (!r.secret) failed(r.error);
  else if (!r.secret.username) setNote("warning", "这个条目没有用户名。");
  else {
    await navigator.clipboard.writeText(r.secret.username);
    setNote("success", "已复制用户名。");
  }
  render();
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * 复制密码或一次性密码，90 秒后清除。为了只清除 Keevo 自己写入的值，需要读取剪贴板，这是可选权限：
 * 第一次复制时才请求，用户拒绝就不复制（仍可以直接填充）。
 * 权限请求必须是点击之后的第一个异步操作，否则会失去用户手势。
 */
async function copySecret(c: Candidate, field: "password" | "totp"): Promise<void> {
  let granted = false;
  try {
    granted = await chrome.permissions.request({ permissions: ["clipboardRead", "clipboardWrite"] });
  } catch {
    granted = false;
  }
  if (!granted) {
    setNote("warning", "没有得到剪贴板权限，Keevo 无法在 90 秒后只清除自己写入的内容，所以没有复制。你仍可以直接填充。");
    render();
    return;
  }
  const r = await fetchSecret(c);
  const value = r.secret ? (field === "password" ? r.secret.password : r.secret.totp) : undefined;
  if (!r.secret) failed(r.error);
  else if (!value) setNote("warning", field === "totp" ? "这个条目没有一次性密码。" : "这个条目没有密码。");
  else {
    await navigator.clipboard.writeText(value);
    await ask({ type: "copied", hash: await sha256Hex(value) });
    setNote("success", `已复制${field === "totp" ? "一次性密码" : "密码"}，90 秒后从剪贴板清除。`);
  }
  render();
}

async function showTotp(c: Candidate): Promise<void> {
  const r = await fetchSecret(c);
  if (!r.secret) failed(r.error);
  else if (!r.secret.totp) setNote("warning", "这个条目没有一次性密码。");
  else {
    view.totp = { itemId: c.item_id, code: r.secret.totp };
    view.note = null;
    clearTimeout(totpTimer);
    totpTimer = setTimeout(() => {
      view.totp = null;
      render();
    }, 30_000);
  }
  render();
}

// ---- 状态

function apply(state: ViewState): void {
  view.state = state;
  const key = JSON.stringify(state);
  if (key === lastKey) return;
  lastKey = key;
  if (state.status === "connected" && !state.locked) void loadCandidates();
  else render();
}

async function loadCandidates(): Promise<void> {
  const r = await ask({ type: "candidates" });
  view.candidates = r.candidates ?? [];
  view.origin = r.origin ?? "";
  if (r.error) setNote("warning", ERRORS[r.error] ?? r.error);
  view.selected = Math.min(view.selected, Math.max(0, view.candidates.length - 1));
  view.state = r.state;
  render();
}

async function update(): Promise<void> {
  // 操作进行中、或用户正在填写配对表单时不打断
  if (view.busy || view.repairing) return;
  const r = await ask({ type: "state" });
  if (r.name) view.name = r.name;
  const extra = r.inline !== view.inline || r.blocked !== view.blocked;
  view.inline = r.inline === true;
  view.blocked = r.blocked === true;
  apply(r.state);
  if (extra && lastKey === JSON.stringify(r.state)) render();
}

void update();
// 配对确认与锁定状态变化需要轮询；弹窗关闭时随之停止
setInterval(() => void update(), 500);
