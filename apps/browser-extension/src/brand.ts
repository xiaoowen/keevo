// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 弹窗与页内菜单共用的品牌元素：Keevo 标志、网站图标（设计稿"扩展弹窗""页内菜单"）。

const SVG_NS = "http://www.w3.org/2000/svg";

/** 盾形线条（20×20 视图框），与输入框旁的 Keevo 图标一致。 */
export const SHIELD_PATH = "M10 2.6 4.4 4.8v4.4c0 3.6 2.4 6.6 5.6 7.8 3.2-1.2 5.6-4.2 5.6-7.8V4.8L10 2.6Z";

function svg(size: number, viewBox: string): SVGSVGElement {
  const s = document.createElementNS(SVG_NS, "svg");
  s.setAttribute("viewBox", viewBox);
  s.setAttribute("width", String(size));
  s.setAttribute("height", String(size));
  s.setAttribute("aria-hidden", "true");
  return s;
}

function stroke(d: string, width: number): SVGPathElement {
  const p = document.createElementNS(SVG_NS, "path");
  p.setAttribute("d", d);
  p.setAttribute("fill", "none");
  p.setAttribute("stroke", "currentColor");
  p.setAttribute("stroke-width", String(width));
  p.setAttribute("stroke-linejoin", "round");
  p.setAttribute("stroke-linecap", "round");
  return p;
}

/** Keevo 标志：品牌色圆角方块中的白色盾形。 */
export function logoMark(size = 20): HTMLElement {
  const box = document.createElement("span");
  box.className = "logo";
  box.style.width = `${size}px`;
  box.style.height = `${size}px`;
  const s = svg(Math.round(size * 0.62), "0 0 20 20");
  s.append(stroke(SHIELD_PATH, 2));
  box.append(s);
  box.setAttribute("aria-hidden", "true");
  return box;
}

/** 锁形线条图标（锁定状态）。 */
export function lockGlyph(size = 22): SVGSVGElement {
  const s = svg(size, "0 0 24 24");
  s.append(stroke("M7 10.5V8a5 5 0 0 1 10 0v2.5", 1.8), stroke("M5.5 10.5h13v9.5h-13z", 1.8));
  return s;
}

const SITE_COLORS = 8;

/**
 * 网站图标：首字母 + 按域名选取的颜色，与 macOS 应用共用同一算法（design/README.md「网站图标」）：
 * key = 去掉 www. 的小写主机名，index = FNV-1a-32(UTF-8(key)) mod 8。
 */
export function siteIcon(title: string, origin: string, size = 28): HTMLElement {
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
  const icon = document.createElement("div");
  icon.className = "site-icon";
  icon.textContent = (first?.segment ?? "?").toUpperCase();
  icon.style.background = `var(--kv-site-${(hash % SITE_COLORS) + 1})`;
  icon.style.width = `${size}px`;
  icon.style.height = `${size}px`;
  icon.setAttribute("aria-hidden", "true");
  return icon;
}

/** 线条图标（24×24 视图框），与设计稿一致。 */
const GLYPHS = {
  back: ["M15 5l-7 7 7 7"],
  refresh: ["M20 11a8 8 0 1 0-2.3 5.7", "M20 4v7h-7"],
  eye: ["M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z", "M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0z"],
  eyeOff: [
    "M3 3l18 18",
    "M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3 3.9M6.1 6.1C3.6 7.8 2 12 2 12s3.5 7 10 7a9.6 9.6 0 0 0 4.2-.9",
  ],
  external: ["M14 4h6v6M20 4l-9 9", "M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"],
  search: ["M18 11a7 7 0 1 1-14 0 7 7 0 0 1 14 0z", "M20 20l-3.5-3.5"],
  touchid: [
    "M12 4a8 8 0 0 1 8 8v1M4 13v-1a8 8 0 0 1 4-6.9",
    "M8 20c1-2 1.5-4 1.5-8a2.5 2.5 0 0 1 5 0c0 3-.5 6-1.5 8",
    "M12 12c0 4-.5 6-2 9",
    "M17 17c-.3 1.2-.7 2.3-1.2 3.2",
  ],
} as const;

export function glyph(name: keyof typeof GLYPHS, size = 14, width = 2): SVGSVGElement {
  const s = svg(size, "0 0 24 24");
  for (const d of GLYPHS[name]) s.append(stroke(d, width));
  return s;
}
