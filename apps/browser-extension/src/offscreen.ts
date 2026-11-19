// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 离屏文档：Service Worker 不能访问剪贴板，由这里在 90 秒后核对并清除。
// 只在剪贴板仍是 Keevo 写入的值时才清除（按 SHA-256 比较：Service Worker 只保存哈希，不保存明文），
// 不会抹掉用户之后复制的其他内容（docs/ux.md §5）。

import type { OffscreenRequest } from "./types.js";

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

function readClipboard(): string {
  const area = document.createElement("textarea");
  document.body.append(area);
  area.focus();
  document.execCommand("paste");
  const value = area.value;
  area.remove();
  return value;
}

function writeEmpty(): void {
  const onCopy = (e: ClipboardEvent): void => {
    e.clipboardData?.setData("text/plain", "");
    e.preventDefault();
  };
  document.addEventListener("copy", onCopy, { once: true });
  document.execCommand("copy");
}

chrome.runtime.onMessage.addListener((msg: OffscreenRequest, sender, sendResponse) => {
  // 只接受 Service Worker 发来的、指明给离屏文档的消息
  if (sender.id !== chrome.runtime.id || sender.tab || msg?.target !== "offscreen" || msg.type !== "clear_if") return false;
  void (async () => {
    const current = readClipboard();
    const cleared = current !== "" && (await sha256Hex(current)) === msg.hash;
    if (cleared) writeEmpty();
    sendResponse({ cleared });
  })();
  return true;
});
