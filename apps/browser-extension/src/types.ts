// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 弹窗、离屏文档与 Service Worker 之间的消息，以及会话内消息的类型（spec/ipc.md §5.2）。

export interface Candidate {
  item_id: string;
  title: string;
  subtitle: string;
}

/** 填充凭据（`fill` 的结果）。 */
export interface Secret {
  username: string;
  password: string;
  totp?: string;
}

/** `status` 的结果；v3 中也是 `open` 与 `unlock` 的结果，多一个 `touch_id`（spec/ipc.md §5.6）。 */
export type CallResult = { locked: boolean; touch_id?: boolean } | { items: Candidate[] } | Secret | { item_id: string };

export type ServerMessage =
  | { id: number; result: CallResult }
  | { id: number; error: { code: string } }
  | { event: "paired" | "locked" | "unlocked" };

/** 配对码的一个词：同一个字节的中文词与英文词互为翻译（spec/sas-wordlist-v1.tsv）。 */
export interface SasWord {
  zh: string;
  en: string;
}

export type ViewState =
  | { status: "idle" }
  | { status: "unpaired" }
  | { status: "connecting" }
  | { status: "pairing" }
  | { status: "awaiting_confirm"; words: SasWord[] }
  /** `touchId`：v3 中现在能否用 Touch ID 解锁（锁定时决定按钮文字）。 */
  | { status: "connected"; locked: boolean; touchId?: boolean | undefined }
  | { status: "error"; error: string };

export type PopupRequest =
  | { type: "state" }
  | { type: "display_name"; name: string }
  | { type: "pair"; name: string }
  | { type: "candidates" }
  | { type: "fill"; itemId: string }
  | { type: "secret"; itemId: string }
  | { type: "copied"; hash: string }
  /** v3：搜索全部条目。`ask` 为 false 时不会请用户在 Keevo 中允许（用户输入时）。 */
  | { type: "search"; query: string; ask: boolean }
  /** v3：显示 Keevo 的主窗口，给出条目时选中它。 */
  | { type: "open"; itemId?: string }
  /** v3：请 Keevo 解锁（可以用 Touch ID 时直接请求验证）。 */
  | { type: "unlock" }
  /** 生成密码（在扩展内的 WASM 中进行）。 */
  | { type: "generate"; recipe: Recipe }
  /** 把生成的密码填入当前网页的新密码框。 */
  | { type: "fill_generated"; password: string }
  /** v2：把弹窗中填写的登录保存到 Keevo（当前网站）。 */
  | { type: "save_login"; username: string; password: string };

/** 生成方式，与 Keevo.app 的生成器一致（crates/keevo-generator）。 */
export type Recipe =
  | { kind: "password"; length: number; digits: boolean; symbols: boolean }
  | { kind: "passphrase"; words: number; capitalize: boolean; number: boolean };

export interface PopupResponse {
  state: ViewState;
  /** 页内菜单是否已启用（标准模式：已授予网站权限）。 */
  inline?: boolean;
  /** 这个标签页的页内菜单因为被遮挡或变透明而关闭过（点击劫持防护），请在弹窗中填充。 */
  blocked?: boolean;
  /** 这个浏览器在 Keevo 中的显示名（清洗后，与 Keevo.app 一致）。 */
  name?: string;
  candidates?: Candidate[];
  origin?: string;
  fill?: string;
  secret?: Secret;
  error?: string;
  /** 会话协商出的协议版本：v2 起可以保存，v3 起可以搜索全部条目、打开 Keevo、请求解锁。 */
  version?: number | undefined;
  /** `search` 的结果。 */
  results?: Candidate[];
  /** `generate` 的结果。 */
  generated?: { value: string; entropy: number };
  /** `save_login` 成功时的条目 ID。 */
  saved?: string;
  /** 弹窗关闭期间在 Keevo 中完成的搜索允许：重新打开时恢复这个搜索词。 */
  resume?: { query: string };
}

/** 页内菜单的初始内容。 */
export interface MenuInit {
  /** 输入框所在帧的来源（由 Chrome 提供，不采信页面自述）。 */
  origin: string;
  /** 标签页顶层的来源；与 origin 不同时，输入框位于 iframe 中。 */
  topOrigin: string | null;
  /** 输入框在跨站的 iframe 中（来源不同，也不同站）：显示嵌入提示，第一次点击只要求确认。 */
  crossSite: boolean;
  kind: "login" | "otp";
  candidates: Candidate[];
  /** 不能列出条目时的原因。 */
  message?: "unpaired" | "locked" | "connecting" | "error" | "no_session" | "limited";
}

/** 页内菜单（menu.html）发给 Service Worker 的消息。 */
export type MenuRequest =
  | { type: "menu_init" }
  | { type: "menu_fill"; itemId: string; confirmed: boolean }
  | { type: "menu_close" }
  | { type: "menu_size"; height: number }
  | { type: "menu_blocked" };

export interface MenuResponse {
  init?: MenuInit;
  fill?: string;
  error?: string;
}

/** 保存栏的内容（不含密码）。 */
export interface BarInit {
  kind: "save" | "update";
  /** 站点的主机名。 */
  host: string;
  username: string;
  /** 要更新的条目标题（update）。 */
  title: string;
}

/** 保存栏（bar.html）发给 Service Worker 的消息。 */
export type BarRequest =
  | { type: "bar_init" }
  | { type: "bar_save" }
  | { type: "bar_dismiss" }
  | { type: "bar_never" }
  | { type: "bar_close" };

export interface BarResponse {
  init?: BarInit;
  ok?: boolean;
  error?: string;
}

/** 视口坐标中的矩形。 */
export interface Rect {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

/** 内容脚本发给 Service Worker 的消息。 */
export type ContentRequest =
  /** 打开页内菜单。`frame`：输入框在直接嵌在顶层页面中的 iframe 里，请顶层帧代为显示菜单，`rect` 是输入框在 iframe 中的位置。 */
  | { type: "inline_open"; kind: "login" | "otp"; frame?: boolean; rect?: Rect }
  | { type: "inline_close" }
  /** 顶层帧收到子帧的定位消息后，凭其中的随机数接手显示菜单。 */
  | { type: "inline_locate"; nonce: string }
  /** 输入框所在的帧中按 ↓：把焦点移入顶层帧代为显示的菜单。 */
  | { type: "inline_focus" }
  /** 用户提交了带密码的表单。`change` 表示这是修改密码的表单。 */
  | { type: "submitted"; username: string; password: string; change: boolean }
  /** 分步登录的第一步：只提交了用户名。 */
  | { type: "username_step"; username: string }
  /** 新页面加载：这个标签页是否有待显示的保存栏。 */
  | { type: "offer_query" };

/** Service Worker 发给离屏文档的消息。 */
export interface OffscreenRequest {
  target: "offscreen";
  type: "clear_if";
  /** Keevo 写入剪贴板的值的 SHA-256（十六进制）；剪贴板仍是这个值时才清除。 */
  hash: string;
}
