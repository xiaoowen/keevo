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
  /** 这个浏览器在 Keevo 中的显示名（清洗后，与 Keevo.app 一致）。 */
  name?: string;
  candidates?: Candidate[];
  origin?: string;
  fill?: string;
  secret?: Secret;
  error?: string;
}

/** Service Worker 发给离屏文档的消息。 */
export interface OffscreenRequest {
  target: "offscreen";
  type: "clear_if";
  /** Keevo 写入剪贴板的值的 SHA-256（十六进制）；剪贴板仍是这个值时才清除。 */
  hash: string;
}
