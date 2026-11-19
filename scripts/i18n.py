#!/usr/bin/env python3
"""界面文字的英文翻译（docs/ux.md §9）。

中文是源语言：界面代码中的中文字面量写成 `tr("模板", 参数…)`（Swift）或 `t("模板", 参数…)`（扩展），
模板中的 `{}` 依次对应参数。英文翻译在 JSON 表中，键是中文模板，值是英文模板（可用 `{0}`、`{1}` 调整顺序）。

用法：
  scripts/i18n.py wrap <文件…>   把文件中的中文字面量改写为 tr(...) / t(...)（只需做一次；可重复运行）
  scripts/i18n.py check          检查翻译表：缺少的键、多余的键、占位符个数不一致
  scripts/i18n.py gen            由翻译表生成 Swift 与 TypeScript 中的表（check 通过后）
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SWIFT_DIR = ROOT / "apps/macos/Sources/KeevoUI"
TS_DIR = ROOT / "apps/browser-extension/src"
SWIFT_TABLE = ROOT / "apps/macos/Localization/en.json"
# 保险库中的数据（模板的默认字段名等），显示时也查表
DATA_LABELS = ROOT / "apps/macos/Localization/data-labels.txt"
TS_TABLE = ROOT / "apps/browser-extension/i18n/en.json"
SWIFT_OUT = SWIFT_DIR / "LocalizationTable.swift"
TS_OUT = TS_DIR / "i18n-table.ts"
# 截图程序的示例数据不翻译
SWIFT_SKIP = {"Snapshots.swift", "LocalizationTable.swift", "Localization.swift"}
TS_SKIP = {"i18n-table.ts", "i18n.ts"}

CJK = re.compile(r"[　-〿一-鿿＀-￯]")


# ---------------------------------------------------------------------------
# Swift 字面量的解析与改写
# ---------------------------------------------------------------------------


class Lexer:
    def __init__(self, src: str):
        self.s = src
        self.i = 0

    def peek(self, k: int = 0) -> str:
        j = self.i + k
        return self.s[j] if j < len(self.s) else ""


def transform_swift(src: str, func: str = "tr") -> tuple[str, int]:
    """返回改写后的源代码与改写的字面量个数。"""
    out: list[str] = []
    count = 0
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "//":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(src[i:j])
            i = j
            continue
        if two == "/*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(src[i:j])
            i = j
            continue
        if c == "#" and src[i:i + 2] == '#"':
            # 原始字符串：原样保留
            j = src.find('"#', i + 2)
            j = n if j < 0 else j + 2
            out.append(src[i:j])
            i = j
            continue
        if c == '"':
            if src[i:i + 3] == '"""':
                j = src.find('"""', i + 3)
                j = n if j < 0 else j + 3
                out.append(src[i:j])
                i = j
                continue
            parts, j = parse_literal(src, i)
            replaced, k = render_literal(src, i, j, parts, func)
            count += k
            out.append(replaced)
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out), count


def parse_literal(src: str, start: int) -> tuple[list[tuple[str, str]], int]:
    """解析从 start（开引号）开始的字面量，返回 (部分, 结束位置之后)。部分为 ("text", 原文) 或 ("expr", 表达式源码)。"""
    i = start + 1
    parts: list[tuple[str, str]] = []
    buf: list[str] = []
    while i < len(src):
        c = src[i]
        if c == "\\":
            if src[i + 1] == "(":
                if buf:
                    parts.append(("text", "".join(buf)))
                    buf = []
                j = i + 2
                depth = 1
                while depth > 0:
                    ch = src[j]
                    if ch == '"':
                        _, j = parse_literal(src, j)
                        continue
                    if ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                    j += 1
                parts.append(("expr", src[i + 2:j - 1]))
                i = j
                continue
            buf.append(src[i:i + 2])
            i += 2
            continue
        if c == '"':
            if buf:
                parts.append(("text", "".join(buf)))
            return parts, i + 1
        if c == "\n":
            raise ValueError(f"未闭合的字面量：{src[start:i]}")
        buf.append(c)
        i += 1
    raise ValueError("文件在字面量中结束")


def render_literal(src: str, start: int, end: int, parts, func: str) -> tuple[str, int]:
    original = src[start:end]
    text = "".join(p[1] for p in parts if p[0] == "text")
    # 已经是 tr( 的第一个参数，或是枚举的原始值：不改写
    before = src[max(0, start - len(func) - 1):start]
    raw_value = re.search(r"\bcase\s+\w+\s*=\s*$", src[max(0, start - 80):start])
    if before == func + "(" or raw_value or not CJK.search(text):
        # 插值中的表达式仍可能有中文字面量
        if any(p[0] == "expr" for p in parts) and not before == func + "(":
            rebuilt = ['"']
            k = 0
            for kind, val in parts:
                if kind == "text":
                    rebuilt.append(val)
                else:
                    inner, c = transform_swift(val, func)
                    k += c
                    rebuilt.append("\\(" + inner + ")")
            rebuilt.append('"')
            return "".join(rebuilt), k
        return original, 0
    template = []
    args = []
    k = 1
    for kind, val in parts:
        if kind == "text":
            template.append(val.replace("{", "{{").replace("}", "}}") if False else val)
        else:
            template.append("{}")
            inner, c = transform_swift(val, func)
            k += c
            args.append('"\\(' + inner + ')"')
    call = f'{func}("' + "".join(template) + '"' + "".join(", " + a for a in args) + ")"
    return call, k


def unescape_swift(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            simple = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "'": "'", "0": "\0"}
            if nxt in simple:
                out.append(simple[nxt])
                i += 2
                continue
            if nxt == "u" and s[i + 2:i + 3] == "{":
                j = s.index("}", i)
                out.append(chr(int(s[i + 3:j], 16)))
                i = j + 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def swift_keys() -> set[str]:
    keys: set[str] = set()
    for f in sorted(SWIFT_DIR.glob("*.swift")):
        if f.name in SWIFT_SKIP:
            continue
        src = f.read_text(encoding="utf-8")
        for m in re.finditer(r'\btr\("', src):
            parts, _ = parse_literal(src, m.end() - 1)
            keys.add(unescape_swift("".join(p[1] for p in parts if p[0] == "text")))
    for line in DATA_LABELS.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            keys.add(line.strip())
    return keys


# ---------------------------------------------------------------------------
# TypeScript：t("…", …) 与 t(`…`) 的第一个参数
# ---------------------------------------------------------------------------


def transform_ts(src: str) -> tuple[str, int]:
    """把 TypeScript 中的中文字符串（'…'、"…"、`…${…}…`）改写为 t("模板", String(参数)…)。"""
    out: list[str] = []
    count = 0
    i, n = 0, len(src)
    while i < n:
        two = src[i:i + 2]
        if two == "//":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(src[i:j]); i = j; continue
        if two == "/*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(src[i:j]); i = j; continue
        c = src[i]
        if c in "'\"":
            j = i + 1
            while src[j] != c:
                j += 2 if src[j] == "\\" else 1
            raw = src[i + 1:j]
            before = src[max(0, i - 2):i]
            if CJK.search(raw) and before != "t(":
                value = raw.replace('\\' + c, c) if c == "'" else raw
                out.append("t(" + json.dumps(json.loads('"' + value.replace("\\'", "'") + '"'), ensure_ascii=False) + ")")
                count += 1
            else:
                out.append(src[i:j + 1])
            i = j + 1
            continue
        if c == "`":
            parts, j = parse_template(src, i)
            text = "".join(p[1] for p in parts if p[0] == "text")
            if CJK.search(text) and src[max(0, i - 2):i] != "t(":
                tmpl, args = [], []
                for kind, val in parts:
                    if kind == "text":
                        tmpl.append(val)
                    else:
                        inner, k = transform_ts(val)
                        count += k
                        tmpl.append("{}")
                        args.append("String(" + inner + ")")
                key = json.loads('"' + "".join(tmpl).replace('"', '\\"').replace("\n", "\\n") + '"') if False else "".join(tmpl)
                out.append("t(" + json.dumps(key.replace("\\`", "`"), ensure_ascii=False) + "".join(", " + a for a in args) + ")")
                count += 1
            else:
                rebuilt = ["`"]
                for kind, val in parts:
                    if kind == "text":
                        rebuilt.append(val)
                    else:
                        inner, k = transform_ts(val)
                        count += k
                        rebuilt.append("${" + inner + "}")
                rebuilt.append("`")
                out.append("".join(rebuilt))
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out), count


def parse_template(src: str, start: int):
    i = start + 1
    parts, buf = [], []
    while True:
        c = src[i]
        if c == "\\":
            buf.append(src[i:i + 2]); i += 2; continue
        if c == "`":
            if buf: parts.append(("text", "".join(buf)))
            return parts, i + 1
        if src[i:i + 2] == "${":
            if buf: parts.append(("text", "".join(buf))); buf = []
            j = i + 2
            depth = 1
            while depth:
                ch = src[j]
                if ch in "'\"":
                    k = j + 1
                    while src[k] != ch:
                        k += 2 if src[k] == "\\" else 1
                    j = k + 1; continue
                if ch == "`":
                    _, j = parse_template(src, j); continue
                if ch == "{": depth += 1
                elif ch == "}": depth -= 1
                j += 1
            parts.append(("expr", src[i + 2:j - 1]))
            i = j
            continue
        buf.append(c); i += 1


def ts_keys() -> set[str]:
    keys: set[str] = set()
    pat = re.compile(r"""\bt\(\s*(['"])((?:(?!\1)[^\\\n]|\\.)*)\1""")
    for f in sorted(TS_DIR.glob("*.ts")):
        if f.name in TS_SKIP:
            continue
        for m in pat.finditer(f.read_text(encoding="utf-8")):
            keys.add(json.loads('"' + m.group(2).replace('\\\'', "'") + '"') if m.group(1) == '"' else m.group(2).replace("\\'", "'"))
    return keys


# ---------------------------------------------------------------------------


def placeholders(s: str) -> int:
    return len(re.findall(r"\{\d*\}", s))


def check_table(keys: set[str], path: pathlib.Path, label: str) -> bool:
    table = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    ok = True
    missing = sorted(keys - table.keys())
    extra = sorted(table.keys() - keys)
    for k in missing:
        print(f"{label} 缺少翻译：{k!r}")
    for k in extra:
        print(f"{label} 多余的翻译：{k!r}")
    for k, v in table.items():
        if k in keys and placeholders(k) != placeholders(v):
            print(f"{label} 占位符个数不一致：{k!r} → {v!r}")
            ok = False
        if k in keys and CJK.search(v.replace("简体中文", "")):
            print(f"{label} 译文中有中文：{k!r} → {v!r}")
            ok = False
    return ok and not missing and not extra


def gen() -> None:
    swift_table = json.loads(SWIFT_TABLE.read_text(encoding="utf-8"))
    body = json.dumps(dict(sorted(swift_table.items())), ensure_ascii=False, indent=1)
    SWIFT_OUT.write_text(
        "// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）\n//\n"
        "// 由 scripts/i18n.py gen 根据 apps/macos/Localization/en.json 生成，不要手工修改。\n\n"
        "let englishTableJSON = #\"\"\"\n" + body + "\n\"\"\"#\n",
        encoding="utf-8",
    )
    ts_table = json.loads(TS_TABLE.read_text(encoding="utf-8"))
    TS_OUT.write_text(
        "// 由 scripts/i18n.py gen 根据 apps/browser-extension/i18n/en.json 生成，不要手工修改。\n"
        "export const EN: Record<string, string> = "
        + json.dumps(dict(sorted(ts_table.items())), ensure_ascii=False, indent=1)
        + ";\n",
        encoding="utf-8",
    )


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    if cmd == "wrap":
        for name in sys.argv[2:]:
            p = pathlib.Path(name)
            func = "t" if p.suffix == ".ts" else "tr"
            if p.suffix == ".ts":
                new, k = transform_ts(p.read_text(encoding="utf-8"))
                # 浏览器中的模块导入必须带 .js；内容脚本（content.ts）不能导入，改用 chrome.i18n.getMessage
                if k and 'from "./i18n.js"' not in new:
                    # 在第一条 import 之前加入
                    idx = new.find("\nimport ")
                    idx = 0 if idx < 0 else idx + 1
                    new = new[:idx] + 'import { t } from "./i18n.js";\n' + new[idx:]
                p.write_text(new, encoding="utf-8")
                print(f"{p.name}：{k}")
                continue
            new, k = transform_swift(p.read_text(encoding="utf-8"), func)
            p.write_text(new, encoding="utf-8")
            print(f"{p.name}：{k}")
        return 0
    if cmd == "keys":
        which = sys.argv[2] if len(sys.argv) > 2 else "swift"
        keys = swift_keys() if which == "swift" else ts_keys()
        print(json.dumps(sorted(keys), ensure_ascii=False, indent=1))
        return 0
    if cmd == "check":
        ok = check_table(swift_keys(), SWIFT_TABLE, "macOS")
        ok = check_table(ts_keys(), TS_TABLE, "扩展") and ok
        if ok:
            print("翻译表完整。")
        return 0 if ok else 1
    if cmd == "gen":
        gen()
        print(f"已生成 {SWIFT_OUT.relative_to(ROOT)}、{TS_OUT.relative_to(ROOT)}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
