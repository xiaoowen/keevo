#!/usr/bin/env python3
"""Keevo 设计令牌生成器。

读取 design/tokens/*.json（单一来源），校验 WCAG 对比度，生成：
  - apps/browser-extension/static/tokens.css      浏览器扩展（CSS 自定义属性）
  - apps/macos/Sources/KeevoUI/DesignTokens.swift   macOS 应用（随系统外观切换的颜色）
  - design/contrast.md                            对比度报告（供评审与审计）

用法：
  python3 design/build_tokens.py          # 生成
  python3 design/build_tokens.py --check  # 只校验：对比度达标，且已提交的产物与令牌一致（CI 使用）

只依赖 Python 标准库。
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOKENS = ROOT / "design" / "tokens"
OUT_CSS = ROOT / "apps" / "browser-extension" / "static" / "tokens.css"
OUT_SWIFT = ROOT / "apps" / "macos" / "Sources" / "KeevoUI" / "DesignTokens.swift"
OUT_REPORT = ROOT / "design" / "contrast.md"

THEMES = ["light", "dark", "light-hc", "dark-hc"]
HEADER = "由 design/build_tokens.py 从 design/tokens/*.json 生成，请勿手改。"

# ------------------------------------------------------------------ 对比度规则
# (前景, [背景...], 普通主题最低值, 高对比主题最低值)。依据 WCAG 2.2：正文 4.5:1（AAA 为 7:1），
# 大字与非文字元素（控件边界、焦点环）3:1。
CONTRAST_RULES = [
    ("fg-primary", ["bg-canvas", "bg-surface", "bg-raised", "bg-hover", "bg-selected"], 7.0, 7.0),
    ("fg-secondary", ["bg-canvas", "bg-surface", "bg-raised", "bg-hover"], 4.5, 7.0),
    ("fg-tertiary", ["bg-canvas"], 3.0, 4.5),
    ("fg-on-accent", ["accent-fill", "accent-fill-hover"], 4.5, 4.5),
    ("accent-fg", ["bg-canvas", "bg-surface", "bg-raised", "accent-subtle"], 4.5, 7.0),
    ("status-danger-fg", ["bg-canvas", "bg-raised", "status-danger-bg"], 4.5, 7.0),
    ("status-warning-fg", ["bg-canvas", "bg-raised", "status-warning-bg"], 4.5, 7.0),
    ("status-success-fg", ["bg-canvas", "bg-raised", "status-success-bg"], 4.5, 7.0),
    ("status-info-fg", ["bg-canvas", "bg-raised", "status-info-bg"], 4.5, 7.0),
    ("secret-digit", ["bg-canvas", "bg-raised", "bg-sunken"], 4.5, 7.0),
    ("secret-symbol", ["bg-canvas", "bg-raised", "bg-sunken"], 4.5, 7.0),
    ("focus-ring", ["bg-canvas", "bg-surface"], 3.0, 4.5),
    ("border-control", ["bg-canvas", "bg-raised"], 3.0, 4.5),
]
SITE_TEXT = "#FFFFFF"
SITE_MIN = 4.5


# ------------------------------------------------------------------ 读取与解析


def load(name: str) -> dict:
    return json.loads((TOKENS / name).read_text(encoding="utf-8"))


def deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict) and "$value" not in v:
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def tokens(tree: dict, prefix: tuple[str, ...] = ()):
    """遍历令牌树，产出 (路径, 令牌)。"""
    for k, v in tree.items():
        if k.startswith("$"):
            continue
        if isinstance(v, dict) and "$value" in v:
            yield prefix + (k,), v
        elif isinstance(v, dict):
            yield from tokens(v, prefix + (k,))


def lookup(tree: dict, dotted: str):
    node = tree
    for part in dotted.split("."):
        node = node[part]
    return node["$value"]


def resolve(value, base: dict):
    if isinstance(value, str) and (m := re.fullmatch(r"\{([^}]+)\}", value)):
        return resolve(lookup(base, m.group(1)), base)
    return value


def theme_colors(base: dict) -> dict[str, dict[str, str]]:
    light, dark = load("theme.light.json"), load("theme.dark.json")
    trees = {
        "light": light,
        "dark": dark,
        "light-hc": deep_merge(light, load("theme.light-hc.json")),
        "dark-hc": deep_merge(dark, load("theme.dark-hc.json")),
    }
    out: dict[str, dict[str, str]] = {}
    for theme, tree in trees.items():
        out[theme] = {}
        for path, tok in tokens(tree):
            value = str(resolve(tok["$value"], base)).upper()
            if not re.fullmatch(r"#[0-9A-F]{6}([0-9A-F]{2})?", value):
                raise SystemExit(f"{theme}: {'.'.join(path)} 不是合法颜色：{value}")
            out[theme]["-".join(path)] = value
    names = [set(v) for v in out.values()]
    if any(n != names[0] for n in names):
        raise SystemExit("各主题的语义令牌名称不一致")
    return out


def descriptions(tree: dict) -> dict[str, str]:
    return {"-".join(p): t.get("$description", "") for p, t in tokens(tree)}


# ------------------------------------------------------------------ 对比度


def luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    def channel(c: int) -> float:
        s = c / 255
        return s / 12.92 if s <= 0.04045 else ((s + 0.055) / 1.055) ** 2.4
    r, g, b = (int(h[i : i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast(a: str, b: str) -> float:
    la, lb = sorted([luminance(a), luminance(b)], reverse=True)
    return (la + 0.05) / (lb + 0.05)


def check_contrast(colors: dict, site: dict[str, str]) -> tuple[list[str], list[tuple]]:
    failures, rows = [], []
    for theme in THEMES:
        c = colors[theme]
        for fg, bgs, normal, hc in CONTRAST_RULES:
            need = hc if theme.endswith("-hc") else normal
            for bg in bgs:
                ratio = contrast(c[fg], c[bg])
                ok = ratio >= need
                rows.append((theme, fg, bg, c[fg], c[bg], ratio, need, ok))
                if not ok:
                    failures.append(f"{theme}: {fg} {c[fg]} / {bg} {c[bg]} = {ratio:.2f} < {need}")
    for name, value in site.items():
        ratio = contrast(SITE_TEXT, value)
        rows.append(("all", "site-text", name, SITE_TEXT, value, ratio, SITE_MIN, ratio >= SITE_MIN))
        if ratio < SITE_MIN:
            failures.append(f"site {name} {value} 配白字 = {ratio:.2f} < {SITE_MIN}")
    return failures, rows


# ------------------------------------------------------------------ 生成


def px(value: str) -> float:
    return float(value.removesuffix("px"))


def ms(value: str) -> float:
    return float(value.removesuffix("ms"))


def css_family(families: list[str]) -> str:
    generic = {"sans-serif", "serif", "monospace", "ui-monospace", "-apple-system", "BlinkMacSystemFont"}
    return ", ".join(f if f in generic else f'"{f}"' for f in families)


def build_css(base: dict, colors: dict) -> str:
    fam = {k: css_family(v["$value"]) for k, v in base["font"]["family"].items()}
    lines = [f"/* {HEADER} */", "", ":root {", "  color-scheme: light dark;", ""]
    for path, tok in tokens(base["space"], ("space",)):
        lines.append(f"  --kv-{'-'.join(path).replace('_', '-')}: {tok['$value']};")
    for path, tok in tokens(base["radius"], ("radius",)):
        lines.append(f"  --kv-{'-'.join(path)}: {tok['$value']};")
    lines.append("")
    for name, f in fam.items():
        lines.append(f"  --kv-font-{name}: {f};")
    for path, tok in tokens(base["font"]["style"]):
        v = tok["$value"]
        family = f"var(--kv-font-{v.get('family', 'sans')})"
        lines.append(f"  --kv-type-{path[-1]}: {v['fontWeight']} {v['fontSize']}/{v['lineHeight']} {family};")
    lines.append("")
    for path, tok in tokens(base["motion"], ("motion",)):
        v = tok["$value"]
        css = f"cubic-bezier({', '.join(str(x) for x in v)})" if isinstance(v, list) else v
        lines.append(f"  --kv-{'-'.join(path[1:])}: {css};")
    lines.append("")
    for path, tok in tokens(base["color"]["site"], ("site",)):
        lines.append(f"  --kv-{'-'.join(path)}: {tok['$value']};")
    lines.append("")
    lines += [f"  --kv-{k}: {v};" for k, v in colors["light"].items()]
    lines.append("}")

    def block(media: str, theme: str, against: str | None) -> list[str]:
        ref = colors[against] if against else {}
        diff = {k: v for k, v in colors[theme].items() if ref.get(k) != v}
        return ["", f"@media {media} {{", "  :root {"] + [f"    --kv-{k}: {v};" for k, v in diff.items()] + ["  }", "}"]

    lines += block("(prefers-color-scheme: dark)", "dark", "light")
    lines += block("(prefers-color-scheme: light) and (prefers-contrast: more)", "light-hc", "light")
    lines += block("(prefers-color-scheme: dark) and (prefers-contrast: more)", "dark-hc", "dark")
    lines += [
        "",
        "@media (prefers-reduced-motion: reduce) {",
        "  :root {",
        "    --kv-duration-fast: 0ms;",
        "    --kv-duration-base: 0ms;",
        "    --kv-duration-slow: 0ms;",
        "  }",
        "}",
        "",
    ]
    return "\n".join(lines)


def swift_name(token: str) -> str:
    parts = re.split(r"[-_]", token)
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])


def swift_hex(value: str) -> str:
    v = value.lstrip("#")
    if len(v) == 6:
        v += "FF"
    return f"0x{v}"


def build_swift(base: dict, colors: dict, desc: dict[str, str]) -> str:
    out = [
        f"// {HEADER}",
        "// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）",
        "",
        "import AppKit",
        "import SwiftUI",
        "",
        "/// Keevo 设计令牌（设计系统 v0，见 design/README.md）。",
        "///",
        "/// 颜色随系统外观自动切换：浅色、深色，以及「增强对比度」下的两种高对比外观。",
        "enum KV {",
        "    /// 语义颜色。",
        "    enum Colors {",
    ]
    for name in colors["light"]:
        d = desc.get(name)
        if d:
            out.append(f"        /// {d}")
        args = ", ".join(
            f"{label}: {swift_hex(colors[t][name])}"
            for label, t in (("light", "light"), ("dark", "dark"), ("lightHC", "light-hc"), ("darkHC", "dark-hc"))
        )
        out.append(f"        static let {swift_name(name)} = dynamicColor({args})")
    out += ["    }", "", "    /// 本地生成的网站图标底色，配白色文字。", "    static let siteColors: [Color] = ["]
    for _, tok in tokens(base["color"]["site"]):
        out.append(f"        rgba({swift_hex(tok['$value'])}),")
    out += ["    ]", "", "    /// 间距（pt）。", "    enum Space {"]
    for path, tok in tokens(base["space"]):
        out.append(f"        static let s{path[-1]}: CGFloat = {px(tok['$value']):g}")
    out += ["    }", "", "    /// 圆角（pt）。", "    enum Radius {"]
    for path, tok in tokens(base["radius"]):
        out.append(f"        static let {path[-1]}: CGFloat = {px(tok['$value']):g}")
    out += ["    }", "", "    /// 字体。macOS 没有动态字体，字号与系统控件保持一致。", "    enum Typography {"]
    weights = {400: ".regular", 500: ".medium", 600: ".semibold", 700: ".bold"}
    for path, tok in tokens(base["font"]["style"]):
        v = tok["$value"]
        design = ", design: .monospaced" if v.get("family") == "mono" else ""
        out.append(
            f"        static let {swift_name(path[-1])} = Font.system(size: {px(v['fontSize']):g}, "
            f"weight: {weights[v['fontWeight']]}{design})"
        )
    out += ["    }", "", "    /// 动效。调用方需在「减弱动态效果」开启时改用瞬时变化。", "    enum Motion {"]
    for path, tok in tokens(base["motion"]["duration"]):
        out.append(f"        static let {path[-1]}: Double = {ms(tok['$value']) / 1000:g}")
    std = base["motion"]["easing"]["standard"]["$value"]
    out += [
        f"        static func standard(duration: Double = base) -> Animation {{",
        f"            .timingCurve({', '.join(f'{x:g}' for x in std)}, duration: duration)",
        "        }",
        "    }",
        "}",
        "",
        "private func rgba(_ value: UInt32) -> Color {",
        "    Color(nsColor: nsColor(value))",
        "}",
        "",
        "private func nsColor(_ value: UInt32) -> NSColor {",
        "    NSColor(",
        "        srgbRed: CGFloat((value >> 24) & 0xFF) / 255,",
        "        green: CGFloat((value >> 16) & 0xFF) / 255,",
        "        blue: CGFloat((value >> 8) & 0xFF) / 255,",
        "        alpha: CGFloat(value & 0xFF) / 255",
        "    )",
        "}",
        "",
        "private func dynamicColor(light: UInt32, dark: UInt32, lightHC: UInt32, darkHC: UInt32) -> Color {",
        "    Color(nsColor: NSColor(name: nil) { appearance in",
        "        switch appearance.bestMatch(from: [",
        "            .aqua, .darkAqua, .accessibilityHighContrastAqua, .accessibilityHighContrastDarkAqua,",
        "        ]) {",
        "        case .darkAqua?: return nsColor(dark)",
        "        case .accessibilityHighContrastAqua?: return nsColor(lightHC)",
        "        case .accessibilityHighContrastDarkAqua?: return nsColor(darkHC)",
        "        default: return nsColor(light)",
        "        }",
        "    })",
        "}",
        "",
    ]
    return "\n".join(out)


def build_report(rows: list[tuple]) -> str:
    out = [
        "# 颜色对比度报告",
        "",
        f"> {HEADER}",
        "",
        "依据 WCAG 2.2：正文 ≥ 4.5:1，高对比主题 ≥ 7:1；控件边界与焦点环 ≥ 3:1。规则定义在 `design/build_tokens.py` 的 `CONTRAST_RULES`。",
        "",
        "| 主题 | 前景 | 背景 | 对比度 | 要求 | 结果 |",
        "|---|---|---|---|---|---|",
    ]
    for theme, fg, bg, fgv, bgv, ratio, need, ok in rows:
        out.append(f"| {theme} | `{fg}` {fgv} | `{bg}` {bgv} | {ratio:.2f} | {need:g} | {'✅' if ok else '❌'} |")
    out.append("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    base = load("base.json")
    colors = theme_colors(base)
    site = {"-".join(p): t["$value"] for p, t in tokens(base["color"]["site"], ("site",))}
    failures, rows = check_contrast(colors, site)
    if failures:
        print("对比度不达标：", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    desc = descriptions(load("theme.light.json"))
    outputs = {
        OUT_CSS: build_css(base, colors),
        OUT_SWIFT: build_swift(base, colors, desc),
        OUT_REPORT: build_report(rows),
    }
    if args.check:
        stale = [p for p, content in outputs.items() if not p.exists() or p.read_text(encoding="utf-8") != content]
        if stale:
            print("以下产物与令牌不一致，请运行 python3 design/build_tokens.py：", file=sys.stderr)
            for p in stale:
                print(f"  - {p.relative_to(ROOT)}", file=sys.stderr)
            return 1
        print(f"设计令牌校验通过：{len(rows)} 组对比度全部达标，产物与令牌一致。")
        return 0
    for path, content in outputs.items():
        path.write_text(content, encoding="utf-8")
        print(f"已生成 {path.relative_to(ROOT)}")
    print(f"{len(rows)} 组对比度全部达标。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
