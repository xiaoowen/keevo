#!/usr/bin/env python3
"""Keevo 保险库明文格式（spec/vault-format.md）与修订模型（spec/revisions.md）的独立参考实现与测试向量生成器。

只依据规范文字编写，刻意不复用 Rust 实现的任何代码；只使用 Python 标准库。

用法：
  python3 -I spec/reference/format_vectors.py              # 写入 spec/test-vectors/{vault-format,revisions}-v1.json
  python3 -I spec/reference/format_vectors.py --check      # 只校验已提交的文件是否一致
  python3 -I spec/reference/format_vectors.py --self-test  # 另外运行合并性质的随机测试

所有输入都由固定标签确定性派生，输出可复现，CI 会比对生成结果。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent / "test-vectors"
FORMAT_OUT = OUT_DIR / "vault-format-v1.json"
REVISIONS_OUT = OUT_DIR / "revisions-v1.json"
FORMAT_V2_OUT = OUT_DIR / "vault-format-v2.json"

# ---------------------------------------------------------------------------
# 常量（vault-format.md §1–§2）
# ---------------------------------------------------------------------------

ITEM_TYPES = {
    "login", "email_account", "secure_note", "ssh_key", "api_credential", "database", "environment", "two_factor",
}
TEXT_KINDS = {
    "text", "multiline", "concealed", "email", "url", "phone", "date", "month_year", "select", "totp",
    "ssh_private_key", "reference",
}
KINDS = TEXT_KINDS | {"kv_list", "recovery_codes", "attachment"}
# 条目详情的版本（vault-format.md §2.5）：含 attachment 字段的文档为 2，否则为 1
ITEM_VERSIONS = (1, 2)
PURPOSES = {"username", "password", "otp", "notes"}
MAX_SAFE = 2**53 - 1
I64_MIN, I64_MAX = -(2**63), 2**63 - 1
MAX_VALUE_LEN = 256 * 1024
MAX_KEYS = 4096
KEY_KINDS = ("attr", "tag", "section", "field")  # 也是记录键的排序先后（§1.1"映射"）
DELETION_STATE = {("attr", "trashed"), ("attr", "purged")}
PURGED = ("attr", "purged")
TRASHED = ("attr", "trashed")
HEX = set("0123456789abcdef")
ORDER_ALPHABET = set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
ATTR_ALPHABET = set("abcdefghijklmnopqrstuvwxyz0123456789_")


class FormatError(Exception):
    """规范定义的错误码。"""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def malformed() -> FormatError:
    return FormatError("malformed")


# ---------------------------------------------------------------------------
# 严格的 JSON 解析：重复键、NaN/Infinity、非法 UTF-8、单独代理项都按 malformed
# ---------------------------------------------------------------------------


def parse_json(data: bytes):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise malformed() from None

    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise malformed()
            out[k] = v
        return out

    def no_constant(_name):
        raise malformed()

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=no_constant)
    except FormatError:
        raise
    except (ValueError, RecursionError):
        raise malformed() from None
    _check_scalars(value)
    return value


def _check_scalars(v) -> None:
    if isinstance(v, str):
        try:
            v.encode("utf-8")
        except UnicodeEncodeError:
            raise malformed() from None
    elif isinstance(v, dict):
        for k, x in v.items():
            _check_scalars(k)
            _check_scalars(x)
    elif isinstance(v, list):
        for x in v:
            _check_scalars(x)


# ---------------------------------------------------------------------------
# 规范编码（vault-format.md §1.1）
# ---------------------------------------------------------------------------

SHORT_ESCAPES = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def enc_str(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append(SHORT_ESCAPES.get(o, f"\\u{o:04x}"))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def enc_obj(fields: list[tuple[str, str]]) -> str:
    return "{" + ",".join(enc_str(k) + ":" + v for k, v in fields) + "}"


def enc_bool(b: bool) -> str:
    return "true" if b else "false"


def enc_hlc(h: int) -> str:
    return enc_str(f"{h:016x}")


def enc_id(i: bytes) -> str:
    return enc_str(i.hex())


# 类型化的值：
#   记录值 ("text", s) | ("bool", b) | ("int", n) | ("tag",) | ("section", label, order) | ("field", FieldValue)
#   FieldValue = dict(section: bytes|None, order, kind, label, purpose: str|None, data)
#   data = ("text", s) | ("kv", [(key, value, concealed)]) | ("codes", [(code, used)])
#        | ("attachment", (id: bytes, name, size, added))
#   记录版本 = (hlc: int, rev: bytes, value | None)
#   记录键 = (kind, name)，section/field 的 name 是 16 字节 ID


def enc_data(d) -> str:
    if d[0] == "text":
        return enc_obj([("text", enc_str(d[1]))])
    if d[0] == "kv":
        items = [enc_obj([("key", enc_str(k)), ("value", enc_str(v)), ("concealed", enc_bool(c))]) for k, v, c in d[1]]
        return enc_obj([("kv", "[" + ",".join(items) + "]")])
    if d[0] == "attachment":
        aid, name, size, added = d[1]
        return enc_obj([("attachment", enc_obj([("id", enc_id(aid)), ("name", enc_str(name)), ("size", str(size)), ("added", str(added))]))])
    items = [enc_obj([("code", enc_str(c)), ("used", enc_bool(u))]) for c, u in d[1]]
    return enc_obj([("codes", "[" + ",".join(items) + "]")])


def enc_value(v) -> str:
    kind = v[0]
    if kind == "text":
        return enc_obj([("text", enc_str(v[1]))])
    if kind == "bool":
        return enc_obj([("bool", enc_bool(v[1]))])
    if kind == "int":
        return enc_obj([("int", str(v[1]))])
    if kind == "tag":
        return enc_str("tag")
    if kind == "section":
        return enc_obj([("section", enc_obj([("label", enc_str(v[1])), ("order", enc_str(v[2]))]))])
    f = v[1]
    fields = []
    if f["section"] is not None:
        fields.append(("section", enc_id(f["section"])))
    fields += [("order", enc_str(f["order"])), ("kind", enc_str(f["kind"])), ("label", enc_str(f["label"]))]
    if f["purpose"] is not None:
        fields.append(("purpose", enc_str(f["purpose"])))
    fields.append(("data", enc_data(f["data"])))
    return enc_obj([("field", enc_obj(fields))])


def compare_bytes(v) -> bytes:
    """合并时比较同一修订不同内容所用的编码（revisions.md §5.1 步骤 1）：墓碑为 `null`。"""
    return b"null" if v is None else enc_value(v).encode("utf-8")


def enc_version(ver) -> str:
    hlc, rev, value = ver
    fields = [("hlc", enc_hlc(hlc)), ("rev", enc_id(rev))]
    if value is not None:
        fields.append(("val", enc_value(value)))
    return enc_obj(fields)


def key_str(key) -> str:
    kind, name = key
    return f"{kind}:{name.hex()}" if kind in ("section", "field") else f"{kind}:{name}"


def key_order(key):
    kind, name = key
    return (KEY_KINDS.index(kind), name if isinstance(name, bytes) else name.encode("utf-8"))


def doc_version(doc) -> int:
    """条目详情的版本：任何记录版本（含并发版本）是 attachment 字段时为 2，否则为 1。"""
    versions = list(doc["records"].values()) + [v for vs in doc["concurrent"].values() for v in vs]
    has = any(v[2] is not None and v[2][0] == "field" and v[2][1]["kind"] == "attachment" for v in versions)
    return 2 if has else 1


def enc_doc(doc) -> str:
    records = sorted(doc["records"].items(), key=lambda kv: key_order(kv[0]))
    fields = [
        ("v", str(doc_version(doc))),
        ("type", enc_str(doc["type"])),
        ("records", enc_obj([(key_str(k), enc_version(v)) for k, v in records])),
    ]
    if doc["concurrent"]:
        conc = sorted(doc["concurrent"].items(), key=lambda kv: key_order(kv[0]))
        fields.append(("concurrent", enc_obj([(key_str(k), "[" + ",".join(enc_version(x) for x in vs) + "]") for k, vs in conc])))
    return enc_obj(fields)


# ---------------------------------------------------------------------------
# 结构解析（vault-format.md §1.2）：不符合时 malformed
# ---------------------------------------------------------------------------


def is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def exact_keys(obj, required: set[str], optional: set[str] = frozenset()) -> None:
    if not isinstance(obj, dict):
        raise malformed()
    keys = set(obj)
    if not required <= keys or not keys <= required | optional:
        raise malformed()


def s_str(x) -> str:
    if not isinstance(x, str):
        raise malformed()
    return x


def s_bool(x) -> bool:
    if not isinstance(x, bool):
        raise malformed()
    return x


def s_i64(x) -> int:
    if not is_int(x) or not I64_MIN <= x <= I64_MAX:
        raise malformed()
    return x


def s_id(x) -> bytes:
    if not isinstance(x, str) or len(x) != 32 or not set(x) <= HEX:
        raise malformed()
    return bytes.fromhex(x)


def s_hlc(x) -> int:
    if not isinstance(x, str) or len(x) != 16 or not set(x) <= HEX:
        raise malformed()
    return int(x, 16)


def s_key(s: str):
    """记录键的语法属于结构：种类前缀与 ID 格式。属性名、标签名的规则属于语义（invalid_key）。"""
    kind, sep, rest = s.partition(":")
    if not sep or kind not in KEY_KINDS:
        raise malformed()
    if kind in ("section", "field"):
        return (kind, s_id(rest))
    return (kind, rest)


def s_data(x):
    if not isinstance(x, dict) or len(x) != 1:
        raise malformed()
    (k, v), = x.items()
    if k == "text":
        return ("text", s_str(v))
    if k == "kv":
        if not isinstance(v, list):
            raise malformed()
        out = []
        for e in v:
            exact_keys(e, {"key", "value", "concealed"})
            out.append((s_str(e["key"]), s_str(e["value"]), s_bool(e["concealed"])))
        return ("kv", out)
    if k == "codes":
        if not isinstance(v, list):
            raise malformed()
        out = []
        for e in v:
            exact_keys(e, {"code", "used"})
            out.append((s_str(e["code"]), s_bool(e["used"])))
        return ("codes", out)
    if k == "attachment":
        exact_keys(v, {"id", "name", "size", "added"})
        return ("attachment", (s_id(v["id"]), s_str(v["name"]), s_i64(v["size"]), s_i64(v["added"])))
    raise malformed()


def s_value(x):
    if isinstance(x, str):
        if x != "tag":
            raise malformed()
        return ("tag",)
    if not isinstance(x, dict) or len(x) != 1:
        raise malformed()
    (k, v), = x.items()
    if k == "text":
        return ("text", s_str(v))
    if k == "bool":
        return ("bool", s_bool(v))
    if k == "int":
        return ("int", s_i64(v))
    if k == "section":
        exact_keys(v, {"label", "order"})
        return ("section", s_str(v["label"]), s_str(v["order"]))
    if k == "field":
        exact_keys(v, {"order", "kind", "label", "data"}, {"section", "purpose"})
        kind = s_str(v["kind"])
        if kind not in KINDS:
            raise malformed()
        purpose = None
        if "purpose" in v:
            purpose = s_str(v["purpose"])
            if purpose not in PURPOSES:
                raise malformed()
        return ("field", {
            "section": s_id(v["section"]) if "section" in v else None,
            "order": s_str(v["order"]),
            "kind": kind,
            "label": s_str(v["label"]),
            "purpose": purpose,
            "data": s_data(v["data"]),
        })
    raise malformed()


def s_version(x):
    exact_keys(x, {"hlc", "rev"}, {"val"})
    return (s_hlc(x["hlc"]), s_id(x["rev"]), s_value(x["val"]) if "val" in x else None)


def check_version_field(obj, known=(1,)) -> None:
    """错误先后的第 0 步（1.1 澄清）：`v` 是能用 64 位有符号整数表示的整数但不是已知版本时返回 unsupported_version，
    先于结构检查。新版本的文档可能带有本版本不认识的字段，否则会被误报为 malformed。"""
    if isinstance(obj, dict) and "v" in obj and is_int(obj["v"]) and I64_MIN <= obj["v"] <= I64_MAX and obj["v"] not in known:
        raise FormatError("unsupported_version")


# ---------------------------------------------------------------------------
# 条目详情的解码（vault-format.md §1.1 错误先后、§2）
# ---------------------------------------------------------------------------


def valid_key_name(key) -> bool:
    kind, name = key
    if kind == "attr":
        return 1 <= len(name) <= 64 and set(name) <= ATTR_ALPHABET
    if kind == "tag":
        return 1 <= len(name.encode("utf-8")) <= 256
    return True


def valid_order(order: str) -> bool:
    return 1 <= len(order) <= 64 and set(order) <= ORDER_ALPHABET


def check_value(key, value) -> None:
    kind = key[0]
    vk = value[0]
    ok = (
        (kind == "attr" and vk in ("text", "bool", "int"))
        or (kind == "tag" and vk == "tag")
        or (kind == "section" and vk == "section")
        or (kind == "field" and vk == "field")
    )
    if not ok:
        raise FormatError("value_kind_mismatch")
    if vk == "field":
        f = value[1]
        expected = {"kv_list": "kv", "recovery_codes": "codes", "attachment": "attachment"}.get(f["kind"], "text")
        if f["data"][0] != expected:
            raise FormatError("value_kind_mismatch")
        if expected == "attachment":
            _, _, size, added = f["data"][1]
            if not (0 <= size <= MAX_SAFE and 0 <= added <= MAX_SAFE):
                raise FormatError("value_too_large")
        if not valid_order(f["order"]):
            raise FormatError("value_kind_mismatch")
    if vk == "section" and not valid_order(value[2]):
        raise FormatError("value_kind_mismatch")
    if vk == "int" and not -MAX_SAFE <= value[1] <= MAX_SAFE:
        raise FormatError("value_too_large")
    if len(enc_value(value).encode("utf-8")) > MAX_VALUE_LEN:
        raise FormatError("value_too_large")


def decode_item(data: bytes):
    obj = parse_json(data)
    check_version_field(obj, ITEM_VERSIONS)
    # 1. 结构
    exact_keys(obj, {"v", "type", "records"}, {"concurrent"})
    if not is_int(obj["v"]) or obj["v"] not in ITEM_VERSIONS:
        raise malformed()
    item_type = s_str(obj["type"])
    if item_type not in ITEM_TYPES:
        raise malformed()
    if not isinstance(obj["records"], dict):
        raise malformed()
    records = {}
    for k, v in obj["records"].items():
        key = s_key(k)
        if key in records:
            raise malformed()
        records[key] = s_version(v)
    concurrent = {}
    if "concurrent" in obj:
        if not isinstance(obj["concurrent"], dict):
            raise malformed()
        for k, vs in obj["concurrent"].items():
            key = s_key(k)
            if not isinstance(vs, list) or key in concurrent:
                raise malformed()
            concurrent[key] = [s_version(v) for v in vs]
    doc = {"type": item_type, "records": records, "concurrent": concurrent}
    # 2. 规范编码
    if enc_doc(doc).encode("utf-8") != data:
        raise malformed()
    # 3. 语义
    validate_doc(doc)
    return doc


def validate_doc(doc) -> None:
    records, concurrent = doc["records"], doc["concurrent"]
    for key in list(records) + list(concurrent):
        if not valid_key_name(key):
            raise FormatError("invalid_key")
    for key, ver in records.items():
        if ver[2] is not None:
            check_value(key, ver[2])
    for key, vs in concurrent.items():
        if key not in records and key not in DELETION_STATE:
            raise malformed()
        if not vs:
            raise malformed()
        if any(a[1] >= b[1] for a, b in zip(vs, vs[1:])):
            raise malformed()
        if key in records and any(v[1] == records[key][1] for v in vs):
            raise malformed()
        for v in vs:
            if v[2] is not None:
                check_value(key, v[2])
    if PURGED in records and records[PURGED][2] is not None:
        raise FormatError("reserved_key")
    for v in concurrent.get(PURGED, []):
        if v[2] is not None and not (v[0] == 0 and v[2] == ("bool", True)):
            raise FormatError("reserved_key")
    if len(set(records) | set(concurrent)) > MAX_KEYS:
        raise FormatError("too_many_keys")


# ---------------------------------------------------------------------------
# 条目概要与保险库元数据（vault-format.md §3、§5）
# ---------------------------------------------------------------------------


def enc_overview(o) -> str:
    fields = [
        ("v", "1"),
        ("type", enc_str(o["type"])),
        ("title", enc_str(o["title"])),
        ("subtitle", enc_str(o["subtitle"])),
        ("urls", "[" + ",".join(enc_str(u) for u in o["urls"]) + "]"),
        ("tags", "[" + ",".join(enc_str(t) for t in o["tags"]) + "]"),
        ("favorite", enc_bool(o["favorite"])),
        ("archived", enc_bool(o["archived"])),
    ]
    if o["trashed_at"] is not None:
        fields.append(("trashed_at", str(o["trashed_at"])))
    fields.append(("updated", enc_hlc(o["updated"])))
    if o["conflicts"]:
        fields.append(("conflicts", "true"))
    return enc_obj(fields)


def s_str_list(x) -> list[str]:
    if not isinstance(x, list):
        raise malformed()
    return [s_str(e) for e in x]


def decode_overview(data: bytes):
    obj = parse_json(data)
    check_version_field(obj)
    exact_keys(
        obj,
        {"v", "type", "title", "subtitle", "urls", "tags", "favorite", "archived", "updated"},
        {"trashed_at", "conflicts"},
    )
    if not is_int(obj["v"]) or obj["v"] != 1:
        raise malformed()
    o = {
        "type": s_str(obj["type"]),
        "title": s_str(obj["title"]),
        "subtitle": s_str(obj["subtitle"]),
        "urls": s_str_list(obj["urls"]),
        "tags": s_str_list(obj["tags"]),
        "favorite": s_bool(obj["favorite"]),
        "archived": s_bool(obj["archived"]),
        "trashed_at": s_i64(obj["trashed_at"]) if "trashed_at" in obj else None,
        "updated": s_hlc(obj["updated"]),
        "conflicts": s_bool(obj["conflicts"]) if "conflicts" in obj else False,
    }
    if o["type"] not in ITEM_TYPES:
        raise malformed()
    if enc_overview(o).encode("utf-8") != data:
        raise malformed()
    if o["trashed_at"] is not None and not -MAX_SAFE <= o["trashed_at"] <= MAX_SAFE:
        raise FormatError("value_too_large")
    return o


def decode_vault_meta(data: bytes):
    obj = parse_json(data)
    check_version_field(obj)
    exact_keys(obj, {"v", "name", "updated"})
    if not is_int(obj["v"]) or obj["v"] != 1:
        raise malformed()
    m = {"name": s_str(obj["name"]), "updated": s_hlc(obj["updated"])}
    if enc_obj([("v", "1"), ("name", enc_str(m["name"])), ("updated", enc_hlc(m["updated"]))]).encode("utf-8") != data:
        raise malformed()
    return m


# ---------------------------------------------------------------------------
# 修订图与合并（revisions.md §5）
# ---------------------------------------------------------------------------


class Graph:
    def __init__(self):
        self.parents: dict[bytes, tuple[bytes, ...]] = {}
        self.origin: dict[bytes, bytes] = {}
        self._anc: dict[bytes, frozenset[bytes]] = {}

    def insert(self, rev: bytes, parents, origin: bytes) -> None:
        ps = tuple(sorted(set(parents)))
        if rev in self.parents:
            if self.parents[rev] != ps or self.origin[rev] != origin:
                raise FormatError("revision_conflict")
            return
        if any(p not in self.parents for p in ps):
            raise FormatError("missing_parent")
        self.parents[rev] = ps
        self.origin[rev] = origin
        anc = {rev}
        for p in ps:
            anc |= self._anc[p]
        self._anc[rev] = frozenset(anc)

    def ancestors(self, rev: bytes) -> frozenset[bytes]:
        """含自身。不在图中的修订没有祖先。"""
        return self._anc.get(rev, frozenset())

    def is_ancestor(self, a: bytes, b: bytes) -> bool:
        return a in self.ancestors(b)


def merge(heads, graph: Graph):
    """heads：[(rev, doc 或 None)]，None 表示墓碑修订。返回 dict 或抛出 FormatError。"""
    if not heads:
        raise FormatError("no_heads")
    unique = {}
    for rev, doc in heads:
        unique[rev] = doc
    live = [(r, d) for r, d in unique.items() if d is not None]
    types = {d["type"] for _, d in live}
    if len(types) > 1:
        raise FormatError("item_type_mismatch")
    if not live:
        return {"deleted": True, "doc": None, "resurrected": False, "conflicts": [], "integrity_issues": []}
    item_type = types.pop()
    # §5.2：墓碑修订视为在 attr:purged 上写了一个版本：hlc = 0，rev 为该墓碑修订，值为 true
    states = [(r, d["records"], d["concurrent"]) for r, d in live]
    states += [(r, {PURGED: (0, r, ("bool", True))}, {}) for r, d in unique.items() if d is None]

    keys = set()
    for _, recs, conc in states:
        keys |= set(recs) | set(conc)

    records, concurrent, conflicts, integrity = {}, {}, [], []
    for key in sorted(keys, key=key_order):
        # 步骤 0：出处
        suspicious = False
        candidates: dict[bytes, list] = {}
        for head, recs, conc in states:
            versions = ([recs[key]] if key in recs else []) + list(conc.get(key, []))
            anc = graph.ancestors(head)
            for ver in versions:
                if ver[1] not in anc:
                    suspicious = True
                    continue
                candidates.setdefault(ver[1], []).append(ver)
        # 步骤 1：按 rev 去重；同一 rev 内容不同时取 (hlc, 规范编码) 最大者
        deduped = []
        for rev, vs in candidates.items():
            if any(v != vs[0] for v in vs):
                suspicious = True
            deduped.append(max(vs, key=lambda v: (v[0], compare_bytes(v[2]))))
        if suspicious:
            integrity.append(key)
        if not deduped:
            continue
        # 步骤 2：极大元
        maximal = [v for v in deduped if not any(w[1] != v[1] and graph.is_ancestor(v[1], w[1]) for w in deduped)]
        # 步骤 3：当前版本
        pool = [v for v in maximal if v[2] is not None] or maximal
        current = max(pool, key=lambda v: (v[0], graph.origin.get(v[1], bytes(16)), v[1]))
        others = sorted((v for v in maximal if v[1] != current[1]), key=lambda v: v[1])
        records[key] = current
        if others:
            concurrent[key] = others
            if key not in DELETION_STATE and any(compare_bytes(o[2]) != compare_bytes(current[2]) for o in others):
                conflicts.append(key)

    def concurrent_modification(d: bytes) -> bool:
        return any(
            k not in DELETION_STATE and v[2] is not None
            and not graph.is_ancestor(v[1], d) and not graph.is_ancestor(d, v[1])
            for k, v in records.items()
        )

    def suppress(key) -> None:
        cur = records.pop(key, None)
        if cur is not None:
            concurrent[key] = sorted(concurrent.get(key, []) + [cur], key=lambda v: v[1])

    resurrected = False
    # §5.2 步骤 1：回收站
    trash = records.get(TRASHED)
    if trash is not None and trash[2] is not None and concurrent_modification(trash[1]):
        suppress(TRASHED)
        resurrected = True
    # §5.2 步骤 2：永久删除
    purges = [v for v in ([records[PURGED]] if PURGED in records else []) + concurrent.get(PURGED, []) if v[2] is not None]
    if purges:
        if any(not concurrent_modification(p[1]) for p in purges):
            return {"deleted": True, "doc": None, "resurrected": False, "conflicts": [], "integrity_issues": integrity}
        suppress(PURGED)
        resurrected = True
    return {
        "deleted": False,
        "doc": {"type": item_type, "records": records, "concurrent": concurrent},
        "resurrected": resurrected,
        "conflicts": conflicts,
        "integrity_issues": integrity,
    }


# ---------------------------------------------------------------------------
# 确定性的测试输入
# ---------------------------------------------------------------------------


def det_id(label: str) -> bytes:
    return hashlib.sha256(b"keevo-format-vectors:" + label.encode("utf-8")).digest()[:16]


BASE_MS = 1763366400000  # 2025-11-17T08:00:00Z


def hlc(ms_offset: int, counter: int = 0) -> int:
    return ((BASE_MS + ms_offset) << 16) | counter


def field(order: str, kind: str, label: str, text: str | None = None, purpose: str | None = None, section=None, data=None):
    return ("field", {
        "section": section, "order": order, "kind": kind, "label": label, "purpose": purpose,
        "data": data if data is not None else ("text", text or ""),
    })


def text(s: str):
    return ("text", s)


def new_doc(item_type: str = "login"):
    return {"type": item_type, "records": {}, "concurrent": {}}


def write(base, rev: bytes, at: int, changes: dict):
    """按 §4.2 写入一个修订：改动的键写入新版本并清除其并发版本；其余原样复制。值为 None 表示删除（墓碑）。"""
    doc = {"type": base["type"], "records": dict(base["records"]), "concurrent": dict(base["concurrent"])}
    for key, value in changes.items():
        doc["records"][key] = (at, rev, value)
        doc["concurrent"].pop(key, None)
    return doc


def A(name: str):
    return ("attr", name)


def T(name: str):
    return ("tag", name)


def F(label: str):
    return ("field", det_id("field:" + label))


def S(label: str):
    return ("section", det_id("section:" + label))


# ---------------------------------------------------------------------------
# vault-format 向量
# ---------------------------------------------------------------------------


def loose(value) -> str:
    """同一个 JSON 值的另一种写法：缩进、字段倒序、全部非 ASCII 转义。宽松解析后应得到同一个规范编码。"""

    def rev(v):
        if isinstance(v, dict):
            return {k: rev(v[k]) for k in reversed(list(v))}
        if isinstance(v, list):
            return [rev(x) for x in v]
        return v

    return json.dumps(rev(value), ensure_ascii=True, indent=1)


def canonical_value_vectors() -> list:
    cases = [
        ("text_plain", text("GitHub")),
        ("text_empty", text("")),
        ("text_escapes", text('引号" 反斜杠\\ 斜杠/ 退格\b 制表\t 换行\n 换页\f 回车\r 其他控制\x00\x01\x1f DEL\x7f')),
        ("text_non_ascii_unescaped", text("中文 é ｚ 😀    ﻿")),
        ("bool_true", ("bool", True)),
        ("bool_false", ("bool", False)),
        ("int_zero", ("int", 0)),
        ("int_negative", ("int", -1)),
        ("int_max_safe", ("int", MAX_SAFE)),
        ("int_min_safe", ("int", -MAX_SAFE)),
        ("tag", ("tag",)),
        ("section", ("section", "服务器", "0000001024")),
        ("field_minimal", field("0", "text", "备注", "")),
        ("field_full", field("a1Z", "concealed", "密码", "s3cret\n", purpose="password", section=det_id("section:s"))),
        ("field_kv", field("1", "kv_list", "环境", data=("kv", [("API_KEY", "k\"1", True), ("HOST", "", False)]))),
        ("field_kv_empty", field("1", "kv_list", "环境", data=("kv", []))),
        ("field_codes", field("2", "recovery_codes", "恢复码", data=("codes", [("aaaa-bbbb", False), ("cccc", True)]))),
    ]
    out = []
    for name, value in cases:
        canonical = enc_value(value)
        out.append({"name": name, "loose": loose(json.loads(canonical)), "canonical": canonical})
    return out


def sample_doc():
    """覆盖各种记录键、值与排序的条目详情。"""
    r0, r1 = det_id("rev:0"), det_id("rev:1")
    doc = new_doc("login")
    rec = doc["records"]
    rec[A("title")] = (hlc(0), r0, text("GitHub"))
    rec[A("favorite")] = (hlc(1), r1, ("bool", True))
    rec[A("a")] = (hlc(0), r0, ("int", 7))
    rec[A("a_b")] = (hlc(0), r0, ("int", -7))
    rec[A("ab")] = (hlc(0), r0, None)
    # 标签按 UTF-8 字节序：Z < a < b < é < ｚ（EF BD 9A）< 😀（F0 9F 98 80）。按 UTF-16 会把 😀 排在 ｚ 之前
    for t in ["😀", "ｚ", "é", "b", "a", "Z"]:
        rec[T(t)] = (hlc(0), r0, ("tag",))
    rec[S("s")] = (hlc(0), r0, ("section", "服务器", "0000001024"))
    rec[F("user")] = (hlc(0), r0, field("0000000000", "text", "用户名", "octocat", purpose="username"))
    rec[F("pass")] = (hlc(1), r1, field("0000000001", "concealed", "密码", "hunter2", purpose="password", section=S("s")[1]))
    rec[F("gone")] = (hlc(1), r1, None)
    doc["concurrent"][A("title")] = [(hlc(1), r1, text("GitHub（工作）"))]
    return doc


def item_vectors() -> dict:
    r0, r1, r2 = det_id("rev:0"), det_id("rev:1"), det_id("rev:2")
    valid_docs = []

    def add_valid(name, doc):
        enc = enc_doc(doc)
        decode_item(enc.encode("utf-8"))  # 自检
        valid_docs.append({"name": name, "doc": enc})

    add_valid("minimal", new_doc("secure_note"))
    add_valid("ordering_and_all_value_kinds", sample_doc())
    d = new_doc("login")
    d["records"][A("title")] = (hlc(0), r0, text("x"))
    d["concurrent"][TRASHED] = sorted([(hlc(1), r1, ("int", BASE_MS)), (hlc(2), r2, ("int", BASE_MS + 1))], key=lambda v: v[1])
    add_valid("deletion_state_only_in_concurrent", d)
    d = new_doc("login")
    d["records"][PURGED] = (hlc(3), r2, None)
    d["concurrent"][PURGED] = sorted([(0, r0, ("bool", True)), (hlc(1), r1, None)], key=lambda v: v[1])
    add_valid("purged_allowed_forms", d)
    add_valid("type_two_factor", new_doc("two_factor"))

    base = enc_doc(sample_doc())
    title_ver = enc_version((hlc(0), r0, text("GitHub")))
    minimal = enc_doc(new_doc("secure_note"))
    invalid = []

    def bad(name, doc: str, error: str):
        try:
            decode_item(doc.encode("utf-8"))
        except FormatError as e:
            assert e.code == error, (name, e.code, error)
        else:
            raise AssertionError(f"{name} 应当失败")
        invalid.append({"name": name, "doc": doc, "error": error})

    def doc_with(records: str, item_type="login", extra=""):
        return '{"v":1,"type":"' + item_type + '","records":{' + records + "}" + extra + "}"

    # 第 0 步：版本
    bad("unsupported_version", minimal.replace('"v":1', '"v":3'), "unsupported_version")
    bad("unsupported_version_before_structure", '{"v":3,"type":"login","records":{},"attachments":[]}', "unsupported_version")
    bad("version_as_string", minimal.replace('"v":1', '"v":"1"'), "malformed")
    bad("version_as_bool", minimal.replace('"v":1', '"v":true'), "malformed")
    bad("version_as_fraction", minimal.replace('"v":1', '"v":1.0'), "malformed")
    bad("version_beyond_i64", minimal.replace('"v":1', '"v":9223372036854775808'), "malformed")
    bad("version_negative", minimal.replace('"v":1', '"v":-1'), "unsupported_version")
    # 第 1 步：JSON 与结构
    bad("not_json", "{", "malformed")
    raw = b'{"v":1,"type":"\xff","records":{}}'
    try:
        decode_item(raw)
    except FormatError as e:
        assert e.code == "malformed"
    invalid.append({"name": "not_utf8", "doc_hex": raw.hex(), "error": "malformed"})
    bad("trailing_data", minimal + "{}", "malformed")
    bad("top_level_array", "[1]", "malformed")
    bad("missing_records", '{"v":1,"type":"login"}', "malformed")
    bad("unknown_field", minimal[:-1] + ',"x":1}', "malformed")
    bad("duplicate_member", '{"v":1,"v":1,"type":"secure_note","records":{}}', "malformed")
    bad("duplicate_record_key", doc_with('"attr:title":' + title_ver + ',"attr:title":' + title_ver), "malformed")
    bad("unknown_item_type", minimal.replace("secure_note", "passkey"), "malformed")
    bad("unknown_key_kind", doc_with('"label:x":' + title_ver), "malformed")
    bad("key_without_kind", doc_with('"title":' + title_ver), "malformed")
    bad("field_id_uppercase", doc_with('"field:' + "A" * 32 + '":' + enc_version((hlc(0), r0, field("0", "text", "x", "")))), "malformed")
    bad("field_id_short", doc_with('"field:' + "a" * 30 + '":' + enc_version((hlc(0), r0, field("0", "text", "x", "")))), "malformed")
    bad("hlc_short", doc_with('"attr:title":' + title_ver.replace(f"{hlc(0):016x}", f"{hlc(0):015x}")), "malformed")
    bad("rev_uppercase", doc_with('"attr:title":' + title_ver.replace(r0.hex(), r0.hex().upper())), "malformed")
    bad("val_null", doc_with('"attr:title":{"hlc":"' + f"{hlc(0):016x}" + '","rev":"' + r0.hex() + '","val":null}'), "malformed")
    bad("val_unknown_variant", doc_with('"attr:x":{"hlc":"' + f"{hlc(0):016x}" + '","rev":"' + r0.hex() + '","val":{"float":1}}'), "malformed")
    bad("val_two_variants", doc_with('"attr:x":{"hlc":"' + f"{hlc(0):016x}" + '","rev":"' + r0.hex() + '","val":{"bool":true,"int":1}}'), "malformed")
    bad("tag_as_object", doc_with('"tag:a":{"hlc":"' + f"{hlc(0):016x}" + '","rev":"' + r0.hex() + '","val":{"tag":null}}'), "malformed")
    bad("version_as_array", doc_with('"attr:title":["' + f"{hlc(0):016x}" + '","' + r0.hex() + '"]'), "malformed")
    bad("int_fraction", doc_with('"attr:a":{"hlc":"' + f"{hlc(0):016x}" + '","rev":"' + r0.hex() + '","val":{"int":1.0}}'), "malformed")
    bad("int_exponent", doc_with('"attr:a":{"hlc":"' + f"{hlc(0):016x}" + '","rev":"' + r0.hex() + '","val":{"int":1e3}}'), "malformed")
    bad("int_beyond_i64", doc_with('"attr:a":{"hlc":"' + f"{hlc(0):016x}" + '","rev":"' + r0.hex() + '","val":{"int":9223372036854775808}}'), "malformed")
    bad("nan", doc_with('"attr:a":{"hlc":"' + f"{hlc(0):016x}" + '","rev":"' + r0.hex() + '","val":{"int":NaN}}'), "malformed")
    bad("unknown_field_kind", base.replace('"kind":"text"', '"kind":"file"', 1), "malformed")
    bad("unknown_purpose", base.replace('"purpose":"username"', '"purpose":"pin"', 1), "malformed")
    bad("lone_surrogate", doc_with('"attr:title":{"hlc":"' + f"{hlc(0):016x}" + '","rev":"' + r0.hex() + '","val":{"text":"\\ud800"}}'), "malformed")
    bad("concurrent_not_object", minimal[:-1] + ',"concurrent":[]}', "malformed")
    # 第 2 步：规范编码
    bad("whitespace", minimal.replace(",", ", ", 1), "malformed")
    bad("member_order", '{"type":"secure_note","v":1,"records":{}}', "malformed")
    bad("record_key_order", doc_with('"tag:a":' + enc_version((hlc(0), r0, ("tag",))) + ',"attr:title":' + title_ver), "malformed")
    bad("tag_order_utf16", base.replace('"tag:ｚ"', '"tag:TMP"').replace('"tag:😀"', '"tag:ｚ"').replace('"tag:TMP"', '"tag:😀"'), "malformed")
    bad("version_member_order", doc_with('"attr:title":{"rev":"' + r0.hex() + '","hlc":"' + f"{hlc(0):016x}" + '","val":{"text":"GitHub"}}'), "malformed")
    bad("negative_zero", doc_with('"attr:a":{"hlc":"' + f"{hlc(0):016x}" + '","rev":"' + r0.hex() + '","val":{"int":-0}}'), "malformed")
    bad("unnecessary_escape", doc_with('"attr:title":{"hlc":"' + f"{hlc(0):016x}" + '","rev":"' + r0.hex() + '","val":{"text":"\\u0041"}}'), "malformed")
    bad("escaped_slash", doc_with('"attr:title":{"hlc":"' + f"{hlc(0):016x}" + '","rev":"' + r0.hex() + '","val":{"text":"\\/"}}'), "malformed")
    bad("uppercase_escape", doc_with('"attr:title":{"hlc":"' + f"{hlc(0):016x}" + '","rev":"' + r0.hex() + '","val":{"text":"\\u001F"}}'), "malformed")
    bad("long_escape_for_newline", doc_with('"attr:title":{"hlc":"' + f"{hlc(0):016x}" + '","rev":"' + r0.hex() + '","val":{"text":"\\u000a"}}'), "malformed")
    bad("empty_concurrent_present", minimal[:-1] + ',"concurrent":{}}', "malformed")
    bad("field_member_order", base.replace('"order":"0000000000","kind":"text"', '"kind":"text","order":"0000000000"', 1), "malformed")
    # 第 3 步：语义
    bad("attr_name_uppercase", doc_with('"attr:Title":' + title_ver), "invalid_key")
    bad("attr_name_empty", doc_with('"attr:":' + title_ver), "invalid_key")
    bad("attr_name_too_long", doc_with('"attr:' + "a" * 65 + '":' + title_ver), "invalid_key")
    bad("tag_name_empty", doc_with('"tag:":' + enc_version((hlc(0), r0, ("tag",)))), "invalid_key")
    bad("tag_name_too_long", doc_with('"tag:' + "é" * 129 + '":' + enc_version((hlc(0), r0, ("tag",)))), "invalid_key")
    bad("int_beyond_safe", doc_with('"attr:a":' + enc_version((hlc(0), r0, ("int", MAX_SAFE + 1)))), "value_too_large")
    bad("int_below_safe", doc_with('"attr:a":' + enc_version((hlc(0), r0, ("int", -MAX_SAFE - 1)))), "value_too_large")
    bad("tag_value_on_attr", doc_with('"attr:a":' + enc_version((hlc(0), r0, ("tag",)))), "value_kind_mismatch")
    bad("text_value_on_tag", doc_with('"tag:a":' + enc_version((hlc(0), r0, text("x")))), "value_kind_mismatch")
    bad("text_value_on_field", doc_with('"field:' + F("x")[1].hex() + '":' + title_ver), "value_kind_mismatch")
    bad("field_kind_data_mismatch", doc_with('"field:' + F("x")[1].hex() + '":' + enc_version((hlc(0), r0, field("0", "kv_list", "x", "text")))), "value_kind_mismatch")
    bad("order_key_bad_alphabet", doc_with('"field:' + F("x")[1].hex() + '":' + enc_version((hlc(0), r0, field("0-1", "text", "x", "")))), "value_kind_mismatch")
    bad("order_key_empty", doc_with('"section:' + S("x")[1].hex() + '":' + enc_version((hlc(0), r0, ("section", "x", "")))), "value_kind_mismatch")
    bad("order_key_too_long", doc_with('"field:' + F("x")[1].hex() + '":' + enc_version((hlc(0), r0, field("1" * 65, "text", "x", "")))), "value_kind_mismatch")
    bad("concurrent_without_current", doc_with('', extra=',"concurrent":{"attr:title":[' + title_ver + "]}"), "malformed")
    bad("concurrent_empty_list", doc_with('"attr:title":' + title_ver, extra=',"concurrent":{"attr:title":[]}'), "malformed")
    bad("concurrent_same_rev_as_current", doc_with('"attr:title":' + title_ver, extra=',"concurrent":{"attr:title":[' + enc_version((hlc(1), r0, text("y"))) + "]}"), "malformed")
    lo, hi = sorted([r1, r2])
    bad("concurrent_not_ascending", doc_with('"attr:title":' + title_ver, extra=',"concurrent":{"attr:title":[' + enc_version((hlc(1), hi, text("y"))) + "," + enc_version((hlc(1), lo, text("z"))) + "]}"), "malformed")
    bad("purged_current_not_tombstone", doc_with('"attr:purged":' + enc_version((0, r0, ("bool", True)))), "reserved_key")
    bad("purged_concurrent_nonzero_hlc", doc_with('"attr:title":' + title_ver, extra=',"concurrent":{"attr:purged":[' + enc_version((hlc(1), r1, ("bool", True))) + "]}"), "reserved_key")
    bad("purged_concurrent_false", doc_with('"attr:title":' + title_ver, extra=',"concurrent":{"attr:purged":[' + enc_version((0, r1, ("bool", False))) + "]}"), "reserved_key")
    # 错误的先后：结构先于规范编码，规范编码先于语义
    bad("precedence_version_over_structure", '{"v":3,"type":"passkey"}', "unsupported_version")
    bad("precedence_structure_over_semantic", doc_with('"attr:Title":' + title_ver, extra=',"x":1'), "malformed")
    bad("precedence_canonical_over_semantic", doc_with('"attr:Title":' + title_ver.replace(",", ", ")), "malformed")
    return {"valid": valid_docs, "invalid": invalid}


def item_v2_vectors() -> dict:
    """条目详情 v2（vault-format.md §2.5）：attachment 字段。"""
    r0, r1 = det_id("rev:0"), det_id("rev:1")
    att = ("attachment", (det_id("attachment:ca"), "ca-certificate.pem", 1843, BASE_MS))
    valid_docs = []

    def add_valid(name, doc):
        enc = enc_doc(doc)
        assert enc.startswith('{"v":2,'), name
        decode_item(enc.encode("utf-8"))
        valid_docs.append({"name": name, "doc": enc})

    d = new_doc("database")
    d["records"][A("title")] = (hlc(0), r0, text("生产数据库"))
    d["records"][F("证书")] = (hlc(0), r0, field("0", "attachment", "ca-certificate.pem", data=att))
    add_valid("attachment_field", d)
    with_att = enc_doc(d)
    d2 = new_doc("database")
    d2["records"][F("证书")] = (hlc(1), r1, None)
    d2["concurrent"] = {}
    d2["records"][A("title")] = (hlc(0), r0, text("x"))
    d2["concurrent"][F("证书")] = [(hlc(0), r0, field("0", "attachment", "a", data=att))]
    add_valid("attachment_only_in_concurrent", d2)
    e = new_doc("secure_note")
    e["records"][F("空文件")] = (hlc(0), r0, field("0", "attachment", "empty.txt", data=("attachment", (det_id("attachment:e"), "", 0, 0))))
    add_valid("attachment_empty_name_zero_size", e)

    invalid = []

    def bad(name, doc: str, error: str):
        try:
            decode_item(doc.encode("utf-8"))
        except FormatError as err:
            assert err.code == error, (name, err.code, error)
        else:
            raise AssertionError(f"{name} 应当失败")
        invalid.append({"name": name, "doc": doc, "error": error})

    minimal_v1 = enc_doc(new_doc("secure_note"))
    bad("v1_with_attachment", with_att.replace('"v":2', '"v":1', 1), "malformed")
    bad("v2_without_attachment", minimal_v1.replace('"v":1', '"v":2', 1), "malformed")
    bad("unsupported_version_3", minimal_v1.replace('"v":1', '"v":3', 1), "unsupported_version")
    bad("attachment_missing_member", with_att.replace(',"added":' + str(BASE_MS), "", 1), "malformed")
    bad("attachment_unknown_member", with_att.replace(',"added":' + str(BASE_MS), ',"added":' + str(BASE_MS) + ',"mime":"x"', 1), "malformed")
    bad("attachment_id_uppercase", with_att.replace(det_id("attachment:ca").hex(), det_id("attachment:ca").hex().upper(), 1), "malformed")
    bad("attachment_size_string", with_att.replace('"size":1843', '"size":"1843"', 1), "malformed")
    bad("attachment_member_order", with_att.replace('"size":1843,"added":' + str(BASE_MS), '"added":' + str(BASE_MS) + ',"size":1843', 1), "malformed")
    bad("attachment_size_beyond_safe", with_att.replace('"size":1843', '"size":' + str(MAX_SAFE + 1), 1), "value_too_large")
    bad("attachment_size_negative", with_att.replace('"size":1843', '"size":-1', 1), "value_too_large")
    bad("attachment_kind_with_text_data", with_att.replace(
        enc_data(att), enc_data(("text", "x")), 1), "value_kind_mismatch")
    t = new_doc("secure_note")
    t["records"][F("x")] = (hlc(0), r0, field("0", "text", "x", data=att))
    bad("text_kind_with_attachment_data", enc_doc(t), "value_kind_mismatch")
    return {"valid": valid_docs, "invalid": invalid}


def overview_vectors() -> dict:
    base = {
        "type": "login", "title": "GitHub", "subtitle": "octocat", "urls": ["https://github.com/login"],
        "tags": ["work"], "favorite": False, "archived": False, "trashed_at": None, "updated": hlc(5), "conflicts": False,
    }
    valid = []
    for name, changes in [
        ("plain", {}),
        ("trashed_with_conflicts", {"trashed_at": BASE_MS, "conflicts": True, "urls": [], "tags": []}),
        ("trashed_at_min_safe", {"trashed_at": -MAX_SAFE}),
    ]:
        o = dict(base, **changes)
        enc = enc_overview(o)
        decode_overview(enc.encode())
        valid.append({"name": name, "doc": enc})
    ok = enc_overview(base)
    invalid = []

    def bad(name, doc, error):
        try:
            decode_overview(doc.encode())
        except FormatError as e:
            assert e.code == error, (name, e.code)
        else:
            raise AssertionError(name)
        invalid.append({"name": name, "doc": doc, "error": error})

    bad("unsupported_version", ok.replace('"v":1', '"v":2'), "unsupported_version")
    bad("conflicts_false_is_not_canonical", ok[:-1] + ',"conflicts":false}', "malformed")
    bad("trashed_at_null", ok.replace(',"updated"', ',"trashed_at":null,"updated"'), "malformed")
    bad("missing_archived", ok.replace(',"archived":false', ""), "malformed")
    bad("unknown_type", ok.replace('"login"', '"passkey"'), "malformed")
    bad("trashed_at_beyond_safe", enc_overview(dict(base, trashed_at=MAX_SAFE + 1)), "value_too_large")
    bad("field_order", ok.replace('"title":"GitHub","subtitle":"octocat"', '"subtitle":"octocat","title":"GitHub"'), "malformed")
    return {"valid": valid, "invalid": invalid}


def vault_meta_vectors() -> dict:
    ok = enc_obj([("v", "1"), ("name", enc_str("个人")), ("updated", enc_hlc(hlc(0)))])
    decode_vault_meta(ok.encode())
    invalid = []

    def bad(name, doc, error):
        try:
            decode_vault_meta(doc.encode())
        except FormatError as e:
            assert e.code == error, (name, e.code)
        else:
            raise AssertionError(name)
        invalid.append({"name": name, "doc": doc, "error": error})

    bad("unsupported_version", ok.replace('"v":1', '"v":2'), "unsupported_version")
    bad("unsupported_version_with_new_fields", '{"v":2,"records":{}}', "unsupported_version")
    bad("unknown_field", ok[:-1] + ',"icon":"x"}', "malformed")
    bad("escaped_non_ascii", ok.replace("个人", "\\u4e2a\\u4eba"), "malformed")
    return {"valid": [{"name": "plain", "doc": ok}], "invalid": invalid}


# ---------------------------------------------------------------------------
# revisions 向量：合并场景
# ---------------------------------------------------------------------------


class Scenario:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.graph = Graph()
        self.revisions: list[dict] = []
        self.docs: dict[bytes, dict | None] = {}

    def rev(self, label: str) -> bytes:
        return det_id(f"{self.name}:{label}")

    def commit(self, label: str, parents: list[str], device: str, doc=None, tombstone: bool = False) -> bytes:
        rev = self.rev(label)
        ps = [self.rev(p) for p in parents]
        origin = det_id("device:" + device)
        self.graph.insert(rev, ps, origin)
        self.revisions.append({"rev": rev.hex(), "parents": sorted(p.hex() for p in set(ps)), "origin": origin.hex()})
        self.docs[rev] = None if tombstone else doc
        return rev

    def result(self, heads: list[str]):
        return merge([(self.rev(h), self.docs[self.rev(h)]) for h in heads], self.graph)

    def vector(self, heads: list[str]) -> dict:
        try:
            r = self.result(heads)
            expected = {
                "deleted": r["deleted"],
                "doc": enc_doc(r["doc"]) if r["doc"] is not None else None,
                "resurrected": r["resurrected"],
                "conflicts": [key_str(k) for k in r["conflicts"]],
                "integrity_issues": [key_str(k) for k in r["integrity_issues"]],
            }
        except FormatError as e:
            expected = {"error": e.code}
        return {
            "name": self.name,
            "description": self.description,
            "revisions": self.revisions,
            "heads": [
                {"rev": self.rev(h).hex(), "doc": enc_doc(self.docs[self.rev(h)]) if self.docs[self.rev(h)] is not None else None}
                for h in heads
            ],
            "expected": expected,
        }


def base_login(s: Scenario) -> dict:
    """创建一个登录条目：标题、用户名、密码。"""
    r = s.rev("A0")
    doc = write(new_doc("login"), r, hlc(0), {
        A("title"): text("GitHub"),
        F("user"): field("0000000000", "text", "用户名", "octocat", purpose="username"),
        F("pass"): field("0000000001", "concealed", "密码", "hunter2", purpose="password"),
    })
    s.commit("A0", [], "A", doc)
    return doc


def merge_vectors() -> list:
    out = []

    def done(s: Scenario, heads: list[str], check):
        r = s.result(heads)
        check(r)
        out.append(s.vector(heads))

    def title(r):
        return r["doc"]["records"][A("title")][2][1]

    # 1
    s = Scenario("single_head", "只有一个头：合并视图就是它本身")
    a0 = base_login(s)
    done(s, ["A0"], lambda r: r["doc"] == a0)

    # 2
    s = Scenario("disjoint_edits", "两台设备并发修改不同的键：各自的修改都保留，没有冲突")
    a0 = base_login(s)
    s.commit("A1", ["A0"], "A", write(a0, s.rev("A1"), hlc(10), {A("title"): text("GitHub 工作")}))
    s.commit("B1", ["A0"], "B", write(a0, s.rev("B1"), hlc(11), {A("favorite"): ("bool", True)}))
    done(s, ["A1", "B1"], lambda r: title(r) == "GitHub 工作" and A("favorite") in r["doc"]["records"] and not r["conflicts"])

    # 3
    s = Scenario("same_key_hlc_wins", "并发修改同一个键：HLC 较大者成为当前版本，另一个保存为并发版本，报告冲突")
    a0 = base_login(s)
    s.commit("A1", ["A0"], "A", write(a0, s.rev("A1"), hlc(10), {A("title"): text("A 的标题")}))
    s.commit("B1", ["A0"], "B", write(a0, s.rev("B1"), hlc(20), {A("title"): text("B 的标题")}))
    done(s, ["A1", "B1"], lambda r: title(r) == "B 的标题" and r["conflicts"] == [A("title")])

    # 4
    s = Scenario("causality_beats_clock", "因果上更晚的修改胜出，即使它的 HLC 更小（写入者的时钟偏慢）")
    a0 = base_login(s)
    a1 = write(a0, s.rev("A1"), hlc(100), {A("title"): text("旧标题")})
    s.commit("A1", ["A0"], "A", a1)
    s.commit("B2", ["A1"], "B", write(a1, s.rev("B2"), hlc(50), {A("title"): text("新标题")}))
    s.commit("C2", ["A1"], "C", write(a1, s.rev("C2"), hlc(60), {A("favorite"): ("bool", True)}))
    done(s, ["B2", "C2"], lambda r: title(r) == "新标题" and not r["conflicts"])

    # 5
    s = Scenario("hlc_tie_origin_decides", "HLC 相同：按来源设备的字节序决定")
    a0 = base_login(s)
    s.commit("A1", ["A0"], "A", write(a0, s.rev("A1"), hlc(10), {A("title"): text("来自 A")}))
    s.commit("B1", ["A0"], "B", write(a0, s.rev("B1"), hlc(10), {A("title"): text("来自 B")}))
    winner = "来自 A" if det_id("device:A") > det_id("device:B") else "来自 B"
    done(s, ["A1", "B1"], lambda r: title(r) == winner)

    # 6
    s = Scenario("hlc_and_origin_tie_rev_decides", "HLC 与来源设备都相同（克隆的设备）：按 rev 的字节序决定")
    a0 = base_login(s)
    s.commit("X1", ["A0"], "A", write(a0, s.rev("X1"), hlc(10), {A("title"): text("X")}))
    s.commit("Y1", ["A0"], "A", write(a0, s.rev("Y1"), hlc(10), {A("title"): text("Y")}))
    winner = "X" if s.rev("X1") > s.rev("Y1") else "Y"
    done(s, ["X1", "Y1"], lambda r: title(r) == winner)

    # 7
    s = Scenario("value_beats_concurrent_tombstone", "并发的删除与修改：非墓碑胜出（宁可多保留），即使墓碑的 HLC 更大；墓碑保存为并发版本")
    a0 = base_login(s)
    s.commit("A1", ["A0"], "A", write(a0, s.rev("A1"), hlc(20), {F("pass"): None}))
    s.commit("B1", ["A0"], "B", write(a0, s.rev("B1"), hlc(10), {F("pass"): field("0000000001", "concealed", "密码", "n3w", purpose="password")}))
    done(s, ["A1", "B1"], lambda r: r["doc"]["records"][F("pass")][2] is not None and r["conflicts"] == [F("pass")])

    # 8
    s = Scenario("equal_values_no_conflict", "两台设备并发地改成同一个值：保存并发版本，但不报告冲突")
    a0 = base_login(s)
    s.commit("A1", ["A0"], "A", write(a0, s.rev("A1"), hlc(10), {A("title"): text("同一个")}))
    s.commit("B1", ["A0"], "B", write(a0, s.rev("B1"), hlc(11), {A("title"): text("同一个")}))
    done(s, ["A1", "B1"], lambda r: A("title") in r["doc"]["concurrent"] and not r["conflicts"])

    # 9
    s = Scenario("tag_remove_after_seen", "删除标签的修订看到了添加：删除（墓碑）因果覆盖添加")
    a0 = base_login(s)
    a1 = write(a0, s.rev("A1"), hlc(10), {T("work"): ("tag",)})
    s.commit("A1", ["A0"], "A", a1)
    s.commit("A2", ["A1"], "A", write(a1, s.rev("A2"), hlc(20), {T("work"): None}))
    s.commit("B2", ["A1"], "B", write(a1, s.rev("B2"), hlc(21), {A("favorite"): ("bool", True)}))
    done(s, ["A2", "B2"], lambda r: r["doc"]["records"][T("work")][2] is None)

    # 10
    s = Scenario("tag_concurrent_add_and_remove", "并发地删除与重新添加同一个标签：添加胜出")
    a0 = base_login(s)
    a1 = write(a0, s.rev("A1"), hlc(10), {T("work"): ("tag",)})
    s.commit("A1", ["A0"], "A", a1)
    s.commit("A2", ["A1"], "A", write(a1, s.rev("A2"), hlc(30), {T("work"): None}))
    s.commit("B2", ["A1"], "B", write(a1, s.rev("B2"), hlc(20), {T("work"): ("tag",)}))
    done(s, ["A2", "B2"], lambda r: r["doc"]["records"][T("work")][2] == ("tag",))

    # 11
    s = Scenario("trash_concurrent_with_edit", "移入回收站与修改并发：撤销，回收站状态只留在并发版本中；标记 resurrected，删除状态不算字段冲突")
    a0 = base_login(s)
    s.commit("T1", ["A0"], "A", write(a0, s.rev("T1"), hlc(10), {TRASHED: ("int", BASE_MS + 10)}))
    s.commit("B1", ["A0"], "B", write(a0, s.rev("B1"), hlc(11), {A("title"): text("还在用")}))
    done(s, ["T1", "B1"], lambda r: r["resurrected"] and TRASHED not in r["doc"]["records"] and TRASHED in r["doc"]["concurrent"] and not r["conflicts"])

    # 12
    s = Scenario("trash_stands_against_concurrent_tombstone", "与移入回收站并发的只是删除了一个字段（墓碑）：不撤销")
    a0 = base_login(s)
    s.commit("T1", ["A0"], "A", write(a0, s.rev("T1"), hlc(10), {TRASHED: ("int", BASE_MS + 10)}))
    s.commit("B1", ["A0"], "B", write(a0, s.rev("B1"), hlc(11), {F("pass"): None}))
    done(s, ["T1", "B1"], lambda r: not r["resurrected"] and r["doc"]["records"][TRASHED][2] is not None)

    # 13
    s = Scenario("edit_inside_trash_does_not_resurrect", "在回收站中编辑（看到了移入回收站）不算并发，条目仍在回收站")
    a0 = base_login(s)
    t1 = write(a0, s.rev("T1"), hlc(10), {TRASHED: ("int", BASE_MS + 10)})
    s.commit("T1", ["A0"], "A", t1)
    s.commit("E2", ["T1"], "A", write(t1, s.rev("E2"), hlc(20), {A("title"): text("在回收站里改")}))
    s.commit("B1", ["A0"], "B", write(a0, s.rev("B1"), hlc(11), {F("pass"): None}))
    done(s, ["E2", "B1"], lambda r: not r["resurrected"] and r["doc"]["records"][TRASHED][2] is not None)

    # 14
    s = Scenario("concurrent_trash_two_devices", "两台设备在不同时间并发地移入回收站：HLC 较大者为当前版本；删除状态不算字段冲突")
    a0 = base_login(s)
    s.commit("T1", ["A0"], "A", write(a0, s.rev("T1"), hlc(10), {TRASHED: ("int", BASE_MS + 10)}))
    s.commit("U1", ["A0"], "B", write(a0, s.rev("U1"), hlc(20), {TRASHED: ("int", BASE_MS + 20)}))
    done(s, ["T1", "U1"], lambda r: not r["conflicts"] and not r["resurrected"] and r["doc"]["records"][TRASHED][2] == ("int", BASE_MS + 20))

    # 15
    s = Scenario("purge_concurrent_with_edit", "永久删除与修改并发：撤销删除；墓碑修订对应的删除版本（hlc = 0）保存在 attr:purged 的并发版本中")
    a0 = base_login(s)
    s.commit("P1", ["A0"], "A", tombstone=True)
    s.commit("B1", ["A0"], "B", write(a0, s.rev("B1"), hlc(11), {A("title"): text("还在用")}))
    done(s, ["P1", "B1"], lambda r: r["resurrected"] and r["doc"]["concurrent"][PURGED] == [(0, s.rev("P1"), ("bool", True))])

    # 16
    s = Scenario("purge_after_all_edits", "墓碑修订看到了全部修改：删除成立")
    a0 = base_login(s)
    b1 = write(a0, s.rev("B1"), hlc(11), {A("title"): text("改过")})
    s.commit("B1", ["A0"], "B", b1)
    s.commit("P2", ["B1"], "A", tombstone=True)
    done(s, ["P2"], lambda r: r["deleted"])

    # 17
    s = Scenario("purge_stands_against_concurrent_tombstone", "与永久删除并发的只是删除了一个字段（墓碑）：删除成立（本次澄清：与回收站的规则一致，只看非墓碑的修改）")
    a0 = base_login(s)
    s.commit("P1", ["A0"], "A", tombstone=True)
    s.commit("B1", ["A0"], "B", write(a0, s.rev("B1"), hlc(11), {F("pass"): None}))
    done(s, ["P1", "B1"], lambda r: r["deleted"])

    # 18
    s = Scenario("all_heads_tombstones", "全部头都是墓碑：已删除")
    base_login(s)
    s.commit("P1", ["A0"], "A", tombstone=True)
    s.commit("P2", ["A0"], "B", tombstone=True)
    done(s, ["P1", "P2"], lambda r: r["deleted"])

    # 19、20：分组合并与一次合并结果相同（结合律，§5.3）
    for grouped in (False, True):
        name = "grouped_merge_matches_three_way" if grouped else "three_way_merge"
        desc = (
            "先把 P1 与 B1 纯合并写成修订 M，再与 C1 合并：结果与一次合并三个头相同"
            if grouped else "一个墓碑头与两个修改头一次合并：撤销删除，两处修改都保留"
        )
        s = Scenario(name, desc)
        # 两个场景使用同一组修订 ID，便于比较结果
        s.rev = (lambda label, _s=s: det_id(f"associativity:{label}"))
        a0 = base_login(s)
        s.commit("P1", ["A0"], "A", tombstone=True)
        b1 = write(a0, s.rev("B1"), hlc(11), {A("title"): text("B 改了标题")})
        s.commit("B1", ["A0"], "B", b1)
        c1 = write(a0, s.rev("C1"), hlc(12), {A("favorite"): ("bool", True)})
        s.commit("C1", ["A0"], "C", c1)
        if grouped:
            m = s.result(["P1", "B1"])
            s.commit("M", ["P1", "B1"], "B", m["doc"])
            done(s, ["M", "C1"], lambda r: r["resurrected"])
        else:
            done(s, ["P1", "B1", "C1"], lambda r: r["resurrected"])
    assert out[-1]["expected"] == out[-2]["expected"], "结合律"

    # 21
    s = Scenario("provenance_violation", "版本声称写于一个不是其所在头祖先的修订：丢弃该版本，报告完整性问题")
    a0 = base_login(s)
    s.commit("X1", ["A0"], "C", write(a0, s.rev("X1"), hlc(5), {A("title"): text("X")}))
    b1 = write(a0, s.rev("B1"), hlc(11), {A("favorite"): ("bool", True)})
    b1["records"][A("title")] = (hlc(99), s.rev("X1"), text("伪造：声称写于 X1"))
    s.commit("B1", ["A0"], "B", b1)
    s.commit("D1", ["A0"], "D", write(a0, s.rev("D1"), hlc(12), {A("archived"): ("bool", False)}))
    done(s, ["B1", "D1"], lambda r: r["integrity_issues"] == [A("title")] and title(r) == "GitHub")

    # 22
    s = Scenario("same_rev_different_content", "两个头里同一 rev 的版本内容不同：取 (hlc, 规范编码) 最大者，报告完整性问题")
    a0 = base_login(s)
    s.commit("A1", ["A0"], "A", write(a0, s.rev("A1"), hlc(10), {A("favorite"): ("bool", True)}))
    tampered = write(a0, s.rev("B1"), hlc(11), {A("archived"): ("bool", True)})
    tampered["records"][A("title")] = (hlc(0), s.rev("A0"), text("被改过的旧值"))
    s.commit("B1", ["A0"], "B", tampered)
    expect = max(["GitHub", "被改过的旧值"], key=lambda t: enc_value(text(t)).encode())
    done(s, ["A1", "B1"], lambda r: r["integrity_issues"] == [A("title")] and title(r) == expect)

    # 23
    s = Scenario("duplicate_head_is_ignored", "头列表中重复的修订只算一次")
    a0 = base_login(s)
    s.commit("A1", ["A0"], "A", write(a0, s.rev("A1"), hlc(10), {A("title"): text("A")}))
    s.commit("B1", ["A0"], "B", write(a0, s.rev("B1"), hlc(20), {A("title"): text("B")}))
    done(s, ["A1", "B1", "A1"], lambda r: title(r) == "B")

    # 24
    s = Scenario("item_type_mismatch", "各头的条目类型不一致")
    s.commit("A0", [], "A", write(new_doc("login"), s.rev("A0"), hlc(0), {A("title"): text("x")}))
    s.commit("B0", [], "B", write(new_doc("secure_note"), s.rev("B0"), hlc(0), {A("title"): text("y")}))
    out.append(s.vector(["A0", "B0"]))
    assert out[-1]["expected"] == {"error": "item_type_mismatch"}
    return out


# ---------------------------------------------------------------------------
# 自检：合并的确定性与结合律（随机多设备模拟）
# ---------------------------------------------------------------------------


def self_test(rounds: int = 300) -> None:
    rng = random.Random(20261118)
    keys = [A("title"), A("favorite"), T("a"), F("f1")]
    for n in range(rounds):
        g = Graph()
        docs: dict[bytes, dict | None] = {}
        root = det_id(f"st:{n}:root")
        g.insert(root, [], det_id("device:0"))
        docs[root] = write(new_doc("login"), root, hlc(0), {A("title"): text("0")})
        heads = [root]
        for i in range(rng.randint(2, 8)):
            parents = rng.sample(heads, k=min(len(heads), rng.randint(1, 2)))
            rev = det_id(f"st:{n}:{i}")
            g.insert(rev, parents, det_id(f"device:{rng.randint(0, 2)}"))
            if rng.random() < 0.1:
                docs[rev] = None
            else:
                m = merge([(p, docs[p]) for p in parents], g)
                if m["doc"] is None:
                    docs[rev] = None
                else:
                    k = rng.choice(keys + [TRASHED])
                    val = None if rng.random() < 0.3 else (
                        ("int", BASE_MS) if k == TRASHED else ("tag",) if k[0] == "tag"
                        else field("0", "text", "f", str(i)) if k[0] == "field" else text(str(rng.randint(0, 2)))
                    )
                    docs[rev] = write(m["doc"], rev, hlc(i + 1, rng.randint(0, 1)), {k: val})
            heads = [h for h in heads if h not in parents] + [rev]
        pairs = [(h, docs[h]) for h in heads]
        r1 = merge(pairs, g)
        r2 = merge(list(reversed(pairs)), g)
        assert r1 == r2, "与输入顺序无关"
        if len(heads) >= 3:
            first = merge(pairs[:2], g)
            if not first["deleted"]:
                mrev = det_id(f"st:{n}:m")
                g.insert(mrev, heads[:2], det_id("device:9"))
                grouped = merge([(mrev, first["doc"])] + pairs[2:], g)
                assert grouped["deleted"] == r1["deleted"], "结合律：是否删除"
                if not r1["deleted"]:
                    assert grouped["doc"] == r1["doc"], "结合律：合并视图"
        for _, d in pairs:
            if d is not None:
                decode_item(enc_doc(d).encode())
    print(f"自检通过：{rounds} 轮随机多设备合并")


# ---------------------------------------------------------------------------


def build() -> tuple[str, str]:
    fmt = {
        "description": "spec/vault-format.md 1.1 的测试向量，由独立的 Python 参考实现生成（spec/reference/format_vectors.py）。"
        "canonical_values：宽松写法（loose）解析后，规范编码必须等于 canonical。"
        "valid：必须原样接受，重新编码后逐字节相同。invalid：必须返回 error 指定的错误码；doc_hex 给出的是非 UTF-8 的原始字节。",
        "canonical_values": canonical_value_vectors(),
        "item_details": item_vectors(),
        "overview": overview_vectors(),
        "vault_meta": vault_meta_vectors(),
    }
    rev = {
        "description": "spec/revisions.md 1.1 §5 合并算法的测试向量，由独立的 Python 参考实现生成（spec/reference/format_vectors.py）。"
        "revisions 按拓扑顺序列出修订图（rev、按字节序的 parents、origin 设备）；heads 中 doc 为 null 表示墓碑修订。"
        "实现必须得到 expected：deleted、合并视图的规范编码 doc、resurrected、冲突与完整性问题的记录键（按记录键排序），"
        "或 error。结果必须与 heads 的顺序无关。",
        "merges": merge_vectors(),
    }
    v2 = {
        "description": "spec/vault-format.md 1.5 §2.5 条目详情 v2（attachment 字段）的测试向量，由独立的 Python 参考实现生成"
        "（spec/reference/format_vectors.py）。读取方必须同时接受 v1（vault-format-v1.json）。"
        "valid：必须原样接受，重新编码后逐字节相同。invalid：必须返回 error 指定的错误码。",
        "item_details": item_v2_vectors(),
    }
    dump = lambda d: json.dumps(d, ensure_ascii=False, indent=2) + "\n"  # noqa: E731
    return dump(fmt), dump(rev), dump(v2)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="只比对，不写入")
    parser.add_argument("--self-test", action="store_true", help="另外运行随机多设备合并自检")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    fmt, rev, v2 = build()
    if args.check:
        ok = (
            FORMAT_OUT.read_text(encoding="utf-8") == fmt
            and REVISIONS_OUT.read_text(encoding="utf-8") == rev
            and FORMAT_V2_OUT.exists()
            and FORMAT_V2_OUT.read_text(encoding="utf-8") == v2
        )
        if not ok:
            print("测试向量与参考实现的输出不一致", file=sys.stderr)
            return 1
        print("格式与合并测试向量与参考实现一致。")
        return 0
    FORMAT_OUT.write_text(fmt, encoding="utf-8")
    REVISIONS_OUT.write_text(rev, encoding="utf-8")
    FORMAT_V2_OUT.write_text(v2, encoding="utf-8")
    print(f"已写入 {FORMAT_OUT.name}、{REVISIONS_OUT.name}、{FORMAT_V2_OUT.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
