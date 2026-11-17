// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 弹窗与 Service Worker 之间的消息，以及会话内消息的类型（spec/ipc.md §5.2）。

export interface Candidate {
  item_id: string;
  title: string;
  subtitle: string;
}

export type CallResult =
  | { locked: boolean }
  | { items: Candidate[] }
  | { username: string; password: string; totp?: string };

export type ServerMessage =
  | { id: number; result: CallResult }
  | { id: number; error: { code: string } }
  | { event: "paired" | "locked" | "unlocked" };

export type ViewState =
  | { status: "idle" }
  | { status: "unpaired" }
  | { status: "connecting" }
  | { status: "pairing" }
  | { status: "awaiting_confirm"; sas: string }
  | { status: "connected"; locked: boolean }
  | { status: "error"; error: string };

export type PopupRequest =
  | { type: "state" }
  | { type: "pair" }
  | { type: "candidates" }
  | { type: "fill"; itemId: string };

export interface PopupResponse {
  state: ViewState;
  candidates?: Candidate[];
  origin?: string;
  fill?: string;
}
