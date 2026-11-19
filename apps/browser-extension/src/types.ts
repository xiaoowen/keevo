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

export type CallResult = { locked: boolean } | { items: Candidate[] } | Secret;

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
  | { status: "connected"; locked: boolean }
  | { status: "error"; error: string };

export type PopupRequest =
  | { type: "state" }
  | { type: "display_name"; name: string }
  | { type: "pair"; name: string }
  | { type: "candidates" }
  | { type: "fill"; itemId: string }
  | { type: "secret"; itemId: string }
  | { type: "copied"; hash: string };

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
}

/** 页内菜单的初始内容。 */
export interface MenuInit {
  /** 输入框所在帧的来源（由 Chrome 提供，不采信页面自述）。 */
  origin: string;
  /** 标签页顶层的来源；与 origin 不同时，输入框位于跨域 iframe 中。 */
  topOrigin: string | null;
  kind: "login" | "otp";
  candidates: Candidate[];
  /** 不能列出条目时的原因。 */
  message?: "unpaired" | "locked" | "connecting" | "error" | "no_session";
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

/** 内容脚本发给 Service Worker 的消息。 */
export type ContentRequest =
  | { type: "inline_open"; kind: "login" | "otp" }
  | { type: "inline_close" }
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
