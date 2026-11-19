// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 界面文字的翻译（docs/ux.md §9）。中文是源语言：代码写 t("模板", 参数…)，模板中的 {} 依次对应参数；
// 浏览器的界面语言不是中文时，按 i18n/en.json（生成为 i18n-table.ts）查找英文模板，可以用 {0}、{1} 调整顺序。

import { EN } from "./i18n-table.js";

function detect(): "zh" | "en" {
  let lang = "";
  try {
    lang = chrome.i18n.getUILanguage();
  } catch {
    // 没有 chrome.i18n（例如测试中的纯脚本环境）：退回 navigator.language
  }
  if (!lang && typeof navigator !== "undefined") lang = navigator.language;
  return lang.toLowerCase().startsWith("zh") ? "zh" : "en";
}

/** 当前的界面语言。 */
export const LANG = detect();

/** 翻译一段界面文字。 */
export function t(key: string, ...args: string[]): string {
  const template = LANG === "en" ? (EN[key] ?? key) : key;
  let next = 0;
  return template.replace(/\{(\d*)\}/g, (_m, n: string) =>
    n === "" ? (args[next++] ?? "") : (args[Number(n)] ?? ""),
  );
}
