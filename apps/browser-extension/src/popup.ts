// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 弹窗（设计稿"扩展 · 弹窗的三种状态"与"扩展 · 弹窗：搜索、生成密码、新建登录与解锁"）：
// - 配对（名称与 6 个词的配对码）；
// - 当前网站的候选条目（搜索、填充、复制、一次性密码）；v3 起搜索框也搜索其他网站的条目（第一次需要在 Keevo 中允许），
//   那些条目只能在 Keevo 中打开；
// - 生成密码（在扩展内的 WASM 中进行）、新建登录（v2 `save`）、在 Keevo 中打开；
// - 锁定时请 Keevo 解锁（v3 `unlock`），解锁后弹窗由 Service Worker 重新打开。
// 弹窗本身不持有任何密钥；秘密只在用户操作时向 Service Worker 取用，用完即丢弃。
//
// 键盘：搜索框中 ↑↓ 选择当前网站的条目，回车填充，Esc 关闭弹窗。

import { LANG, t } from "./i18n.js";
import { glyph, lockGlyph, logoMark, siteIcon } from "./brand.js";
import type { Candidate, PopupRequest, PopupResponse, Recipe, SasWord, ViewState } from "./types.js";

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

/** 只有图标的按钮，必须给出可读的名称。 */
function iconButton(icon: SVGSVGElement, label: string, onClick: () => void): HTMLButtonElement {
  const b = button("", onClick, "icon-button");
  b.setAttribute("aria-label", label);
  b.title = label;
  b.append(icon);
  return b;
}

const ERRORS: Record<string, string> = {
  host_not_installed: t("没有找到 Keevo 的本机组件。请在 Keevo 的「设置 → 浏览器」中安装 Chrome 支持。"),
  service_unavailable: t("未能连接 Keevo。请确认 Keevo 正在运行。"),
  disconnected: t("与 Keevo 的连接已断开。"),
  not_paired: t("Keevo 不认识这个浏览器了，请重新配对。"),
  pairing_rejected: t("配对已被拒绝或超时。"),
  pairing_limited: t("Keevo 正在处理另一个配对，或配对尝试过于频繁，请稍后再试。"),
  locked: t("Keevo 已锁定。请先在 Keevo 中解锁。"),
  not_authorized: t("没有得到授权：在 Keevo 中被拒绝或超时，或者这个浏览器的填充已被暂停。"),
  not_found: t("这个条目已不存在。"),
  url_mismatch: t("这个条目与当前网站不匹配，已拒绝。"),
  response_too_large: t("这个条目的内容太长，无法自动填充。请在 Keevo 中复制。"),
  no_tab: t("没有找到当前标签页。"),
  queries_limited: t("这个浏览器短时间内查询了太多网站，Keevo 暂时停止回答。请在 Keevo 中查看。"),
  unsupported: t("这个版本的 Keevo 不支持这项操作，请更新 Keevo。"),
  bad_request: t("通信出错，请重试。"),
  protocol: t("通信出错，请重试。"),
  failed: t("操作没有完成，请重试。"),
};

const FILL_RESULTS: Record<string, string> = {
  no_password_field: t("页面上没有找到可见的密码框。"),
  origin_changed: t("页面已跳转到其他网站，已取消填充。"),
};

type NoteKind = "info" | "warning" | "danger" | "success";
type Page = "list" | "generator" | "new_login";

/** 搜索其他网站的条目（v3 `search`）。 */
interface SearchState {
  /** 这些结果对应的搜索词。 */
  query: string;
  status: "idle" | "searching" | "results" | "needs_permission" | "waiting" | "error";
  results: Candidate[];
}

/** 生成密码的设置，与 Keevo.app 的生成器默认值一致。 */
interface GeneratorSettings {
  kind: "password" | "passphrase";
  length: number;
  digits: boolean;
  symbols: boolean;
  words: number;
  capitalize: boolean;
  number: boolean;
}

interface View {
  state: ViewState;
  /** 这个浏览器在 Keevo 中的显示名（清洗后）。 */
  name: string;
  /** 会话协商出的协议版本。 */
  version: number;
  page: Page;
  candidates: Candidate[];
  origin: string;
  query: string;
  selected: number;
  search: SearchState;
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
  /** 点了"解锁"的时间：之后 60 秒内显示"正在等待 Keevo"。 */
  unlocking: number;
  gen: GeneratorSettings;
  generated: { value: string; entropy: number } | null;
  form: { username: string; password: string; generated: string; reveal: boolean };
}

const DEFAULT_GENERATOR: GeneratorSettings = {
  kind: "password",
  length: 20,
  digits: true,
  symbols: true,
  words: 5,
  capitalize: false,
  number: true,
};

function loadGenerator(): GeneratorSettings {
  try {
    const saved = JSON.parse(localStorage.getItem("generator") ?? "{}") as Partial<GeneratorSettings>;
    return { ...DEFAULT_GENERATOR, ...saved };
  } catch {
    return { ...DEFAULT_GENERATOR };
  }
}

function saveGenerator(): void {
  try {
    localStorage.setItem("generator", JSON.stringify(view.gen));
  } catch {
    // 只是记住偏好，失败无妨
  }
}

const view: View = {
  state: { status: "idle" },
  name: "",
  version: 1,
  page: "list",
  candidates: [],
  origin: "",
  query: "",
  selected: 0,
  search: { query: "", status: "idle", results: [] },
  note: null,
  busy: false,
  totp: null,
  repairing: false,
  inline: false,
  blocked: false,
  unlocking: 0,
  gen: loadGenerator(),
  generated: null,
  form: { username: "", password: "", generated: "", reveal: false },
};
const SITE_ORIGINS = ["https://*/*", "http://*/*"];
const UNLOCK_WAIT_MS = 60_000;
let lastKey = "";
let totpTimer: ReturnType<typeof setTimeout> | undefined;
let searchTimer: ReturnType<typeof setTimeout> | undefined;

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

/** 当前网页是普通网站（可以新建登录、填入生成的密码）。 */
function onWebsite(): boolean {
  return /^https?:/.test(view.origin);
}

function host(): string {
  try {
    return new URL(view.origin).host;
  } catch {
    return view.origin;
  }
}

// ---- 渲染

function header(): HTMLElement {
  const h = el("header");
  const s = view.state;
  if (view.page === "generator" || (view.page === "new_login" && s.status === "connected" && !s.locked)) {
    h.append(
      iconButton(glyph("back", 13, 2.4), t("返回"), () => {
        view.page = "list";
        view.note = null;
        render();
      }),
      el("h1", view.page === "generator" ? t("生成密码") : t("新建登录")),
    );
    return h;
  }
  h.append(logoMark(20), el("h1", "Keevo"), el("span", t("开发版"), "badge"));
  if (s.status === "connected" && !view.repairing) {
    h.append(el("span", s.locked ? t("已锁定") : t("已连接"), s.locked ? "status" : "status ok"));
  }
  return h;
}

function render(): void {
  const focusedId = document.activeElement?.id ?? "";
  root.replaceChildren();
  const s = view.state;
  // 锁定或断开时回到列表页（生成密码不需要连接，但新建登录需要）
  if (s.status !== "connected" || s.locked) {
    if (view.page === "new_login") view.page = "list";
  }
  root.append(header());

  if (view.repairing || s.status === "unpaired") renderPairForm();
  else if (view.page === "generator") renderGenerator();
  else {
    switch (s.status) {
      case "idle":
      case "connecting":
      case "pairing":
        root.append(el("p", t("正在连接 Keevo…"), "muted"));
        break;
      case "awaiting_confirm":
        renderSas(s.words);
        break;
      case "error":
        root.append(el("div", ERRORS[s.error] ?? t("出错了（{}）", String(s.error)), "banner danger"));
        root.append(
          button(t("重新配对"), () => {
            view.repairing = true;
            render();
          }),
        );
        break;
      case "connected":
        if (s.locked) renderLocked(s.touchId === true);
        else if (view.page === "new_login") renderNewLogin();
        else renderItems();
        break;
    }
  }
  if (view.note) {
    const note = el("div", view.note.text, `banner ${view.note.kind}`);
    note.setAttribute("role", "status");
    root.append(note);
  }
  const again = focusedId ? document.getElementById(focusedId) : null;
  if (again) again.focus();
  else if (view.page === "list") document.getElementById("search")?.focus();
}

/**
 * 锁定（设计稿"Keevo 已锁定"）：解锁只在 Keevo 中进行，扩展不接触主密码。v3 起可以请 Keevo 解锁：
 * 可以用 Touch ID 时 Keevo 直接请求验证，否则在 Keevo 中输入主密码；解锁后 Keevo 回到浏览器，弹窗重新打开。
 */
function renderLocked(touchId: boolean): void {
  const box = el("div", undefined, "locked");
  const icon = el("div", undefined, "locked-icon");
  icon.append(lockGlyph(22));
  box.append(icon, el("h2", t("Keevo 已锁定")));
  root.append(box);
  if (view.version < 3) {
    box.append(el("p", t("请在 Keevo 应用中解锁。解锁只在 Keevo 中进行，扩展从不接触你的主密码。"), "muted"));
    return;
  }
  if (Date.now() - view.unlocking < UNLOCK_WAIT_MS) {
    box.append(
      el(
        "p",
        touchId ? t("请在弹出的 Touch ID 窗口中验证指纹。解锁后会回到这里。") : t("请在 Keevo 中输入主密码。解锁后会回到这里。"),
        "muted",
      ),
    );
    const waiting = button(t("正在等待 Keevo…"), () => undefined, "wide");
    waiting.disabled = true;
    waiting.prepend(el("span", undefined, "spinner"));
    box.append(waiting);
    const hint = el("p", touchId ? t("没有看到 Touch ID 窗口？") : t("没有看到 Keevo？"), "note");
    hint.append(button(t("切换到 Keevo"), () => void ask({ type: "open" }), "link"));
    box.append(hint);
    return;
  }
  box.append(
    el(
      "p",
      touchId
        ? t("解锁在 Keevo 应用中完成，扩展从不接触你的主密码。")
        : t("这次解锁需要在 Keevo 中输入主密码。扩展从不接触你的主密码。"),
      "muted",
    ),
  );
  const go = button(touchId ? t("用 Touch ID 解锁") : t("在 Keevo 中解锁"), () => void unlock(), "wide");
  if (touchId) go.prepend(glyph("touchid", 15, 1.9));
  box.append(go);
}

async function unlock(): Promise<void> {
  view.unlocking = Date.now();
  view.note = null;
  render();
  const r = await ask({ type: "unlock" });
  view.state = r.state;
  if (r.error) {
    view.unlocking = 0;
    setNote("danger", ERRORS[r.error] ?? r.error);
  }
  render();
}

function renderPairForm(): void {
  root.append(el("p", t("这个浏览器还没有与 Keevo 配对。配对需要 Keevo 正在运行并已解锁。")));
  const label = el("label", t("在 Keevo 中显示的名称"), "field-label");
  const input = el("input");
  input.id = "pair-name";
  input.maxLength = 64;
  input.value = view.name || "Chrome";
  input.placeholder = "Chrome";
  label.htmlFor = input.id;
  const preview = el("p", "", "note");
  const showPreview = async (): Promise<void> => {
    const r = await ask({ type: "display_name", name: input.value });
    preview.textContent = r.name?.trim() ? t("Keevo 中将显示为「{}」", String(r.name)) : t("名称为空时显示为「Chrome」");
  };
  input.oninput = () => void showPreview();
  void showPreview();
  const go = button(t("与 Keevo 配对"), () => {
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
  root.append(el("p", t("请在 Keevo 中逐个核对下面 6 个词，顺序也要一致，然后在 Keevo 中确认：")));
  const grid = el("ol", undefined, "sas");
  grid.setAttribute("aria-label", t("配对码：{}", String(words.map((w) => (LANG === "en" ? w.en : w.zh)).join(t("、")))));
  words.forEach((w, i) => {
    const cell = el("li");
    cell.append(el("span", String(i + 1), "sas-index"), el("span", w.zh, "sas-zh"), el("span", w.en, "sas-en"));
    grid.append(cell);
  });
  root.append(grid);
  if (view.name) root.append(el("p", t("这个浏览器在 Keevo 中显示为「{}」。", String(view.name)), "note"));
  root.append(
    el(
      "div",
      t("Keevo 中会弹出确认窗口。如果没有出现，说明有程序在冒充 Keevo，请关闭这个弹窗，不要继续；如果词不一致，请在 Keevo 中选择「不一致」。"),
      "banner info",
    ),
  );
}

// ---- 列表与搜索

function renderItems(): void {
  const all = view.version >= 3;
  const search = el("input");
  search.id = "search";
  search.type = "search";
  search.placeholder = all ? t("搜索全部条目") : t("搜索当前网站的登录");
  search.setAttribute("aria-label", search.placeholder);
  search.value = view.query;
  search.autocomplete = "off";
  const list = el("div", undefined, "list");
  search.oninput = () => {
    view.query = search.value;
    view.selected = 0;
    scheduleSearch();
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
  const searchBox = el("div", undefined, "search");
  searchBox.append(search);
  root.append(searchBox);
  if (view.blocked) {
    root.append(
      el("div", t("这个页面上的 Keevo 菜单被遮挡或变得透明，为了安全已经关闭。请在这里选择要填充的登录。"), "banner warning"),
    );
  }
  root.append(list);
  renderList(list);
  root.append(links());
  root.append(inlineSetting());
  if (view.name) root.append(el("p", t("这个浏览器在 Keevo 中显示为「{}」", String(view.name)), "footer"));
}

function renderList(list: HTMLElement): void {
  list.replaceChildren();
  const items = filtered();
  const searching = view.query.trim() !== "" && view.version >= 3;
  if (searching) list.append(el("div", t("当前网站 · {}", String(host() || "—")), "section-label"));
  else if (view.origin) list.append(el("p", view.origin, view.origin.startsWith("https:") ? "origin secure" : "origin"));
  const current = el("div", undefined, "rows");
  current.setAttribute("role", "listbox");
  current.setAttribute("aria-label", t("当前网站的登录"));
  if (view.candidates.length === 0) current.append(el("p", t("当前网站没有匹配的登录。"), "muted"));
  else if (items.length === 0) current.append(el("p", t("当前网站没有符合搜索的登录。"), "muted"));
  items.forEach((c, i) => {
    const selected = i === view.selected;
    const row = el("div", undefined, selected ? "item selected" : "item");
    row.setAttribute("role", "option");
    row.setAttribute("aria-selected", String(selected));
    const main = el("div", undefined, "item-main");
    const text = el("div", undefined, "text");
    text.append(highlighted(c.title, "title"), el("div", c.subtitle, "subtitle"));
    const fillButton = button(t("填充"), () => void fill(c), "fill");
    fillButton.disabled = view.busy;
    main.append(siteIcon(c.title, view.origin), text, fillButton);
    main.onclick = (e) => {
      if (e.target === fillButton) return;
      view.selected = i;
      renderList(list);
    };
    row.append(main);
    if (selected) row.append(actions(c));
    current.append(row);
  });
  list.append(current);
  if (searching) list.append(otherSites());
}

/** 重新渲染当前的列表。弹窗可能在异步操作期间整体重新渲染过，不能沿用之前取到的元素。 */
function refreshList(): void {
  const list = root.querySelector<HTMLElement>(".list");
  if (list) renderList(list);
}

/** 标题中与搜索词相同的部分加上标记（不区分大小写，只标第一处）。 */
function highlighted(text: string, cls: string): HTMLElement {
  const box = el("div", undefined, cls);
  const q = view.query.trim();
  const at = q ? text.toLocaleLowerCase().indexOf(q.toLocaleLowerCase()) : -1;
  if (at < 0) {
    box.textContent = text;
    return box;
  }
  box.append(text.slice(0, at), el("mark", text.slice(at, at + q.length)), text.slice(at + q.length));
  return box;
}

/** 其他网站的条目（v3 `search`）：只能在 Keevo 中打开。 */
function otherSites(): HTMLElement {
  const box = el("div", undefined, "others");
  const q = view.query.trim();
  const s = view.search;
  if (s.status === "needs_permission" || (s.status === "error" && s.query === q)) {
    const go = button("", () => void searchAll(true), "bordered wide");
    go.append(glyph("search", 14, 2.2), document.createTextNode(t("在全部条目中搜索「{}」", String(q))));
    box.append(go);
    box.append(el("p", t("第一次需要在 Keevo 中允许，之后到 Keevo 下次锁定前不再询问。搜索结果只有标题与用户名。"), "note"));
    return box;
  }
  if (s.status === "waiting") {
    box.append(el("p", t("请在 Keevo 中允许这次搜索。允许后会回到这里。"), "note"));
    return box;
  }
  box.append(el("div", t("其他网站"), "section-label"));
  const ids = new Set(view.candidates.map((c) => c.item_id));
  const others = s.query === q ? s.results.filter((c) => !ids.has(c.item_id)) : [];
  if (s.status !== "results" || s.query !== q) {
    box.append(el("p", t("正在搜索…"), "muted"));
    return box;
  }
  if (others.length === 0) {
    box.append(el("p", t("其他网站没有符合搜索的条目。"), "muted"));
    return box;
  }
  const rows = el("div", undefined, "rows");
  rows.setAttribute("aria-label", t("其他网站的条目"));
  for (const c of others) {
    const row = el("div", undefined, "item-main other");
    const text = el("div", undefined, "text");
    text.append(highlighted(c.title, "title"), el("div", c.subtitle, "subtitle"));
    const open = button("", () => void openInKeevo(c.item_id), "secondary open");
    open.append(glyph("external", 11, 2.2), document.createTextNode(t("打开")));
    open.setAttribute("aria-label", t("在 Keevo 中打开 {}", String(c.title)));
    row.append(siteIcon(c.title, ""), text, open);
    rows.append(row);
  }
  box.append(rows, el("p", t("其他网站的条目不能在这里填充，可以在 Keevo 中打开后查看或复制。"), "note"));
  return box;
}

/** 用户输入时搜索：不请用户在 Keevo 中允许（`ask: false`），没有允许时显示"在全部条目中搜索"。 */
function scheduleSearch(): void {
  clearTimeout(searchTimer);
  if (view.version < 3 || view.query.trim() === "") return;
  if (view.search.status !== "needs_permission") view.search = { query: view.search.query, status: "searching", results: [] };
  searchTimer = setTimeout(() => void searchAll(false), 250);
}

async function searchAll(allow: boolean): Promise<void> {
  const query = view.query.trim();
  if (!query) return;
  if (allow) {
    view.search = { query, status: "waiting", results: [] };
    refreshList();
  }
  const r = await ask({ type: "search", query, ask: allow });
  // 等待期间用户可能改了搜索词：只采用仍然对应当前搜索词的结果
  if (view.query.trim() !== query) return;
  if (r.results) view.search = { query, status: "results", results: r.results };
  else if (r.error === "not_authorized") {
    view.search = { query, status: "needs_permission", results: [] };
    if (allow) setNote("warning", t("没有得到允许：在 Keevo 中被拒绝或超时。"));
  } else {
    view.search = { query, status: "error", results: [] };
    if (r.error === "locked") view.state = r.state;
    else setNote("danger", ERRORS[r.error ?? "failed"] ?? t("出错了（{}）", String(r.error)));
  }
  if (r.error === "locked" || (allow && r.error)) render();
  else refreshList();
}

async function openInKeevo(itemId?: string): Promise<void> {
  const r = await ask(itemId ? { type: "open", itemId } : { type: "open" });
  if (r.error) {
    setNote("danger", ERRORS[r.error] ?? r.error);
    render();
  }
}

/** 底部入口（设计稿）：生成密码、新建登录、在 Keevo 中打开。 */
function links(): HTMLElement {
  const bar = el("footer", undefined, "links");
  bar.append(
    button(t("生成密码"), () => {
      view.page = "generator";
      view.note = null;
      render();
      if (!view.generated) void regenerate();
    }, "link"),
  );
  if (view.version >= 2) {
    const create = button(t("新建登录"), () => void startNewLogin(), "link");
    if (!onWebsite()) {
      create.disabled = true;
      create.title = t("当前页面不是网站");
    }
    bar.append(create);
  }
  if (view.version >= 3) {
    const open = button(t("在 Keevo 中打开"), () => void openInKeevo(), "link");
    open.classList.add("end");
    bar.append(open);
  }
  return bar;
}

/**
 * 标准模式开关：在输入框旁显示 Keevo 图标需要"读取和更改网站数据"的权限，默认不申请（最小权限模式），
 * 由用户在这里开启（docs/ux.md §4.5）。关闭后仍可用弹窗或快捷键填充。
 */
function inlineSetting(): HTMLElement {
  const row = el("div", undefined, "setting");
  const text = el("div", undefined, "text");
  text.append(
    el("div", t("在输入框旁显示 Keevo 图标"), "setting-title"),
    el("div", view.inline ? t("已开启。刷新页面后生效。") : t("需要读取和更改网站数据的权限。不开启时可用快捷键或这个弹窗填充。"), "subtitle"),
  );
  const toggle = button(view.inline ? t("关闭") : t("开启"), () => {
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

/** 选中条目的更多操作：复制用户名、复制密码、一次性密码、在 Keevo 中打开。 */
function actions(c: Candidate): HTMLElement {
  const bar = el("div", undefined, "actions");
  const copyUser = button(t("复制用户名"), () => void copyUsername(c), "secondary");
  const copyPass = button(t("复制密码"), () => void copySecret(c, "password"), "secondary");
  const otp = button(t("一次性密码"), () => void showTotp(c), "secondary");
  for (const b of [copyUser, copyPass, otp]) b.disabled = view.busy;
  bar.append(copyUser, copyPass, otp);
  if (view.version >= 3) bar.append(button(t("在 Keevo 中打开"), () => void openInKeevo(c.item_id), "secondary"));
  if (view.totp?.itemId === c.item_id) {
    const code = view.totp.code;
    const box = el("div", undefined, "totp");
    const digits = el("span", code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code, "totp-code");
    digits.setAttribute("aria-label", t("一次性密码 {}", String(code.split("").join(" "))));
    box.append(digits, button(t("复制"), () => void copySecret(c, "totp"), "secondary"));
    bar.append(box);
  }
  return bar;
}

// ---- 生成密码

function recipe(): Recipe {
  const g = view.gen;
  return g.kind === "password"
    ? { kind: "password", length: g.length, digits: g.digits, symbols: g.symbols }
    : { kind: "passphrase", words: g.words, capitalize: g.capitalize, number: g.number };
}

async function generate(): Promise<{ value: string; entropy: number } | null> {
  const r = await ask({ type: "generate", recipe: recipe() });
  return r.generated ?? null;
}

async function regenerate(): Promise<void> {
  view.generated = await generate();
  if (!view.generated) setNote("danger", ERRORS.failed ?? "");
  render();
}

/** 数字蓝色、符号红色，便于手动输入时分辨（与 Keevo.app 一致）。 */
function classified(value: string): HTMLElement {
  const out = el("span", undefined, "classified");
  for (const ch of value) {
    const span = el("span", ch);
    if (/[0-9]/.test(ch)) span.className = "digit";
    else if (!/[\p{L}]/u.test(ch)) span.className = "symbol";
    out.append(span);
  }
  return out;
}

/** 强度：文字、四段条与颜色一起表示（与 Keevo.app 的划分一致）。 */
function meter(bits: number): HTMLElement {
  const [level, label, cls]: [number, string, string] =
    bits < 40 ? [1, t("弱"), "danger"] : bits < 60 ? [2, t("一般"), "warning"] : bits < 80 ? [3, t("强"), "success"] : [4, t("很强"), "success"];
  const box = el("div", undefined, `meter ${cls}`);
  box.setAttribute("role", "img");
  box.setAttribute("aria-label", t("强度：{}", String(label)));
  for (let i = 1; i <= 4; i++) box.append(el("span", undefined, i <= level ? "bar on" : "bar"));
  box.append(el("span", label, "level"));
  return box;
}

function toggleRow(label: string, on: boolean, change: (on: boolean) => void): HTMLElement {
  const row = el("label", undefined, "gen-row");
  const box = el("input");
  box.type = "checkbox";
  box.setAttribute("role", "switch");
  box.checked = on;
  box.onchange = () => change(box.checked);
  row.append(el("span", label), box);
  return row;
}

function sliderRow(label: string, value: number, min: number, max: number, change: (v: number) => void): HTMLElement {
  const row = el("label", undefined, "gen-row");
  const range = el("input");
  range.type = "range";
  range.id = "gen-range";
  range.min = String(min);
  range.max = String(max);
  range.value = String(value);
  range.setAttribute("aria-label", label);
  const badge = el("span", String(value), "badge-value");
  range.oninput = () => {
    badge.textContent = range.value;
  };
  range.onchange = () => change(Number(range.value));
  row.append(el("span", label), range, badge);
  return row;
}

function renderGenerator(): void {
  const g = view.gen;
  const seg = el("div", undefined, "segmented");
  seg.setAttribute("role", "radiogroup");
  seg.setAttribute("aria-label", t("生成方式"));
  for (const [kind, label] of [
    ["password", t("随机字符")],
    ["passphrase", t("口令短语")],
  ] as const) {
    const b = button(label, () => {
      if (g.kind === kind) return;
      g.kind = kind;
      saveGenerator();
      void regenerate();
    });
    b.setAttribute("role", "radio");
    b.setAttribute("aria-checked", String(g.kind === kind));
    if (g.kind === kind) b.className = "on";
    seg.append(b);
  }
  const valueBox = el("div", undefined, "gen-value");
  const output = el("output");
  output.setAttribute("aria-label", t("生成的密码"));
  if (view.generated) output.append(classified(view.generated.value));
  valueBox.append(output, iconButton(glyph("refresh", 15), t("重新生成"), () => void regenerate()));
  const card = el("div", undefined, "gen-card");
  const changed = (): void => {
    saveGenerator();
    void regenerate();
  };
  if (g.kind === "password") {
    card.append(
      sliderRow(t("长度"), g.length, 8, 64, (v) => {
        g.length = v;
        changed();
      }),
      toggleRow(t("数字（0–9）"), g.digits, (on) => {
        g.digits = on;
        changed();
      }),
      toggleRow(t("符号（!#$%&*+-.:;=?@^_~）"), g.symbols, (on) => {
        g.symbols = on;
        changed();
      }),
    );
  } else {
    card.append(
      sliderRow(t("单词数"), g.words, 3, 10, (v) => {
        g.words = v;
        changed();
      }),
      toggleRow(t("首字母大写"), g.capitalize, (on) => {
        g.capitalize = on;
        changed();
      }),
      toggleRow(t("加一位数字"), g.number, (on) => {
        g.number = on;
        changed();
      }),
    );
  }
  const copy = button(t("复制"), () => void copyText(view.generated?.value ?? "", t("密码")), "secondary big");
  const fillPage = button(t("填入网页"), () => void fillGenerated(), "big");
  copy.disabled = !view.generated;
  fillPage.disabled = !view.generated || !onWebsite();
  if (!onWebsite()) fillPage.title = t("当前页面不是网站");
  const buttons = el("div", undefined, "pair-buttons");
  buttons.append(copy, fillPage);
  root.append(seg, valueBox);
  if (view.generated) root.append(meter(view.generated.entropy));
  root.append(
    card,
    buttons,
    el(
      "p",
      t("在扩展内生成，不经过网络。「填入网页」填到当前网页的新密码框；提交后 Keevo 会询问是否保存。复制的密码 90 秒后从剪贴板清除。"),
      "note",
    ),
  );
}

async function fillGenerated(): Promise<void> {
  const value = view.generated?.value;
  if (!value) return;
  const r = await ask({ type: "fill_generated", password: value });
  if (r.fill === "filled") {
    window.close();
    return;
  }
  setNote("warning", FILL_RESULTS[r.fill ?? ""] ?? ERRORS[r.fill ?? "failed"] ?? ERRORS.failed ?? "");
  render();
}

// ---- 新建登录（v2 `save`：只保存网站地址，标题为主机名）

async function startNewLogin(): Promise<void> {
  const g = await generate();
  // 刚生成的密码还没有保存，显示出来便于核对（设计稿）；用户可以随时隐藏
  view.form = { username: "", password: g?.value ?? "", generated: g?.value ?? "", reveal: true };
  view.page = "new_login";
  view.note = null;
  render();
}

function renderNewLogin(): void {
  const f = view.form;
  const site = el("div", undefined, "field");
  site.append(el("span", t("网站"), "field-label"));
  const siteValue = el("div", view.origin, view.origin.startsWith("https:") ? "readonly origin secure" : "readonly origin");
  site.append(siteValue);

  const userLabel = el("label", t("用户名"), "field-label");
  const user = el("input");
  user.id = "nl-user";
  user.value = f.username;
  user.maxLength = 1024;
  user.autocomplete = "off";
  user.placeholder = t("用户名或邮箱");
  userLabel.htmlFor = user.id;
  user.oninput = () => {
    f.username = user.value;
  };

  const pwLabel = el("label", t("密码"), "field-label");
  const pwRow = el("div", undefined, "password-row");
  const pw = el("input");
  pw.id = "nl-password";
  pw.type = f.reveal ? "text" : "password";
  pw.value = f.password;
  pw.maxLength = 4096;
  pw.autocomplete = "off";
  pw.spellcheck = false;
  pwLabel.htmlFor = pw.id;
  const hint = el("p", "", "note");
  const updateHint = (): void => {
    hint.textContent =
      f.password !== "" && f.password === f.generated ? t("已生成 {} 位随机密码，可以改成你自己的。", String([...f.password].length)) : "";
  };
  updateHint();
  const save = button(t("保存到 Keevo"), () => void saveLogin(), "big");
  pw.oninput = () => {
    f.password = pw.value;
    save.disabled = f.password === "" || view.busy;
    updateHint();
  };
  pwRow.append(
    pw,
    iconButton(glyph(f.reveal ? "eyeOff" : "eye", 14), f.reveal ? t("隐藏密码") : t("显示密码"), () => {
      f.reveal = !f.reveal;
      render();
    }),
    iconButton(glyph("refresh", 14), t("重新生成"), () => {
      void generate().then((g) => {
        if (!g) return;
        f.password = g.value;
        f.generated = g.value;
        render();
      });
    }),
  );
  save.disabled = f.password === "" || view.busy;
  const cancel = button(
    t("取消"),
    () => {
      view.page = "list";
      render();
    },
    "secondary big",
  );
  const buttons = el("div", undefined, "form-buttons");
  buttons.append(cancel, save);
  root.append(
    site,
    userLabel,
    user,
    pwLabel,
    pwRow,
    hint,
    el("p", t("标题为 {}。只保存网站地址，不保存路径。保存后在这个网站上填充不再询问。", String(host().replace(/^www\./, ""))), "note"),
    buttons,
  );
  if (!document.activeElement || document.activeElement === document.body) user.focus();
}

async function saveLogin(): Promise<void> {
  const f = view.form;
  if (!f.password || view.busy) return;
  view.busy = true;
  const r = await ask({ type: "save_login", username: f.username.trim(), password: f.password });
  view.busy = false;
  view.state = r.state;
  if (r.saved) {
    view.form = { username: "", password: "", generated: "", reveal: false };
    view.page = "list";
    setNote("success", t("已保存到 Keevo：{}。", String(host().replace(/^www\./, ""))));
    await loadCandidates();
    return;
  }
  setNote(
    "danger",
    r.error === "not_authorized"
      ? t("保存得太频繁（10 分钟内最多 5 个），请稍后再试，或在 Keevo 中新建。")
      : (ERRORS[r.error ?? "failed"] ?? t("出错了（{}）", String(r.error))),
  );
  render();
}

// ---- 操作

/** 等待 Keevo 期间的提示：第一次在某个网站上使用某个条目时，Keevo 会请用户确认（spec/ipc.md §5.2）。 */
function waiting(): void {
  view.busy = true;
  setNote("info", t("正在向 Keevo 取用。第一次在这个网站上使用这个条目时，请在 Keevo 中确认。"));
  render();
}

function failed(code: string | undefined): void {
  setNote("danger", ERRORS[code ?? "failed"] ?? t("出错了（{}）", String(code)));
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
  else if (!r.secret.username) setNote("warning", t("这个条目没有用户名。"));
  else {
    await navigator.clipboard.writeText(r.secret.username);
    setNote("success", t("已复制用户名。"));
  }
  render();
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * 复制的秘密 90 秒后清除。为了只清除 Keevo 自己写入的值，需要读取剪贴板，这是可选权限：
 * 第一次复制时才请求，用户拒绝就不复制（仍可以直接填充）。
 * 权限请求必须是点击之后的第一个异步操作，否则会失去用户手势。
 */
async function clipboardGranted(): Promise<boolean> {
  try {
    return await chrome.permissions.request({ permissions: ["clipboardRead", "clipboardWrite"] });
  } catch {
    return false;
  }
}

const NO_CLIPBOARD = t("没有得到剪贴板权限，Keevo 无法在 90 秒后只清除自己写入的内容，所以没有复制。");

async function writeSecret(value: string): Promise<void> {
  await navigator.clipboard.writeText(value);
  await ask({ type: "copied", hash: await sha256Hex(value) });
}

/** 复制生成的密码。 */
async function copyText(value: string, label: string): Promise<void> {
  if (!(await clipboardGranted())) {
    setNote("warning", NO_CLIPBOARD);
    render();
    return;
  }
  if (!value) return;
  await writeSecret(value);
  setNote("success", t("已复制{}，90 秒后从剪贴板清除。", String(label)));
  render();
}

/** 复制条目的密码或一次性密码。 */
async function copySecret(c: Candidate, field: "password" | "totp"): Promise<void> {
  if (!(await clipboardGranted())) {
    setNote("warning", t("{}你仍可以直接填充。", String(NO_CLIPBOARD)));
    render();
    return;
  }
  const r = await fetchSecret(c);
  const value = r.secret ? (field === "password" ? r.secret.password : r.secret.totp) : undefined;
  if (!r.secret) failed(r.error);
  else if (!value) setNote("warning", field === "totp" ? t("这个条目没有一次性密码。") : t("这个条目没有密码。"));
  else {
    await writeSecret(value);
    setNote("success", t("已复制{}，90 秒后从剪贴板清除。", String(field === "totp" ? t("一次性密码") : t("密码"))));
  }
  render();
}

async function showTotp(c: Candidate): Promise<void> {
  const r = await fetchSecret(c);
  if (!r.secret) failed(r.error);
  else if (!r.secret.totp) setNote("warning", t("这个条目没有一次性密码。"));
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
  if (state.status === "connected" && !state.locked) {
    view.unlocking = 0;
    void loadCandidates();
  } else render();
}

async function loadCandidates(): Promise<void> {
  const r = await ask({ type: "candidates" });
  view.candidates = r.candidates ?? [];
  view.origin = r.origin ?? "";
  if (r.error) setNote("warning", ERRORS[r.error] ?? r.error);
  view.selected = Math.min(view.selected, Math.max(0, view.candidates.length - 1));
  view.state = r.state;
  render();
  // 重新打开弹窗时恢复刚在 Keevo 中允许的搜索
  if (view.page === "list" && view.query.trim() && view.version >= 3 && view.search.status === "idle") void searchAll(false);
}

async function update(): Promise<void> {
  // 操作进行中、或用户正在填写配对表单时不打断
  if (view.busy || view.repairing) return;
  const r = await ask({ type: "state" });
  if (r.name) view.name = r.name;
  if (r.version !== undefined) view.version = r.version;
  if (r.resume) view.query = r.resume.query;
  const extra = r.inline !== view.inline || r.blocked !== view.blocked;
  view.inline = r.inline === true;
  view.blocked = r.blocked === true;
  apply(r.state);
  // 等待解锁的提示到时后恢复按钮
  if (view.unlocking && Date.now() - view.unlocking >= UNLOCK_WAIT_MS) {
    view.unlocking = 0;
    render();
  } else if (extra && lastKey === JSON.stringify(r.state)) render();
}

void update();
// 配对确认与锁定状态变化需要轮询；弹窗关闭时随之停止
setInterval(() => void update(), 500);
