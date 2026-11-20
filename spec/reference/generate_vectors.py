#!/usr/bin/env python3
"""Keevo 加密规范（spec/crypto.md）v0.1 的独立参考实现与测试向量生成器。

刻意不复用 Rust 实现的任何代码，只依赖：
  - argon2-cffi：Argon2 官方 C 参考实现的绑定
  - PyNaCl：libsodium 的绑定（XChaCha20-Poly1305）
  - Python 标准库：hashlib、hmac、unicodedata

用法：
  python3 -m venv .venv && .venv/bin/pip install --require-hashes -r spec/reference/requirements.txt
  .venv/bin/python spec/reference/generate_vectors.py            # 写入 spec/test-vectors/crypto-v1.json、attachment-v1.json 与 export-v1.json
  .venv/bin/python spec/reference/generate_vectors.py --check    # 只校验已提交的文件是否一致

所有输入都由固定标签确定性派生，因此输出可复现，CI 会比对生成结果。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import struct
import sys
import unicodedata
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)

OUTPUT = Path(__file__).resolve().parent.parent / "test-vectors" / "crypto-v1.json"
# §8.9 附件（草案）：单独的文件，已冻结的 crypto-v1.json 不变
ATTACHMENT_OUTPUT = OUTPUT.parent / "attachment-v1.json"
# spec/export.md §3 加密导出文件（草案）
EXPORT_OUTPUT = OUTPUT.parent / "export-v1.json"

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ZERO16 = bytes(16)
ZERO32 = bytes(32)

# §5.2
KDF_ALG_ARGON2ID = 0x01
M_MIN, M_MAX = 65536, 4194304
T_MIN, T_MAX = 3, 32
P_MIN, P_MAX = 1, 16

# §9
OBJECT_TYPES = {
    "account_keyset": 0x01,
    "vault": 0x02,
    "item": 0x03,
    "attachment": 0x04,
    "sync_segment": 0x05,
    "sync_snapshot": 0x06,
    "device_name": 0x07,
}
PARTS = {"content": 0x01, "wrapped_key": 0x02, "overview": 0x03, "details": 0x04, "chunk": 0x05}

MAX_PLAINTEXT = 16 * 1024 * 1024


def det(label: str, n: int) -> bytes:
    """由标签确定性派生测试输入（不是密码学用途）。"""
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"keevo-test-vector/{label}/{counter}".encode()).digest()
        counter += 1
    return out[:n]


# ---------------------------------------------------------------- HKDF（RFC 5869）


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if not salt:
        salt = bytes(32)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, i = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        okm += block
        i += 1
    return okm[:length]


# ---------------------------------------------------------------- 账户密钥（§4）


def gf_mul(a: int, b: int) -> int:
    """GF(32) 乘法，本原多项式 x^5 + x^2 + 1。"""
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x20:
            a ^= 0x25
    return r


def rs_check(values: list[int]) -> list[int]:
    """GF(32) 上的 Reed-Solomon 校验，生成多项式 g(x) = (x + a)(x + a^2) = x^2 + 6x + 8。"""
    r1 = r0 = 0
    for m in values:
        feedback = m ^ r1
        r1 = r0 ^ gf_mul(feedback, 6)
        r0 = gf_mul(feedback, 8)
    return [r1, r0]


def body_values(sk: bytes) -> list[int]:
    v = int.from_bytes(sk, "big")  # 视为 130 位整数 0b00 || SK
    return [(v >> (125 - 5 * i)) & 31 for i in range(26)]


def secret_key_encode(sk: bytes) -> str:
    assert len(sk) == 16
    body = body_values(sk)
    s = "".join(CROCKFORD[v] for v in body + rs_check(body))
    return "K1-" + "-".join(s[i : i + 7] for i in range(0, 28, 7))


def secret_key_parse(text: str) -> tuple[bytes | None, str | None]:
    s = unicodedata.normalize("NFKC", text)
    s = "".join(c.upper() if "a" <= c <= "z" else c for c in s)
    s = "".join(c for c in s if c not in "- \t\r\n")
    if len(s) == 30:
        if not s.startswith("K1"):
            return None, "wrong_prefix"
        s = s[2:]
    elif len(s) != 28:
        return None, "wrong_length"
    s = s.replace("O", "0").replace("I", "1").replace("L", "1")
    if any(c not in CROCKFORD for c in s):
        return None, "invalid_character"
    values = [CROCKFORD.index(c) for c in s]
    if values[0] > 7:
        return None, "non_canonical"
    body = 0
    for v in values[:26]:
        body = (body << 5) | v
    if rs_check(values[:26]) != values[26:]:
        return None, "checksum_mismatch"
    return body.to_bytes(16, "big"), None


# ---------------------------------------------------------------- KDF 参数（§5）


def kdf_encode(alg: int, m: int, t: int, p: int, salt: bytes) -> bytes:
    return struct.pack(">BIII", alg, m, t, p) + salt


def kdf_validate(encoded: bytes) -> str | None:
    if len(encoded) != 29:
        return "malformed"
    alg, m, t, p = struct.unpack(">BIII", encoded[:13])
    if alg != KDF_ALG_ARGON2ID:
        return "unsupported_algorithm"
    if m < M_MIN or t < T_MIN or p < P_MIN:
        return "below_minimum"
    if m > M_MAX or t > T_MAX or p > P_MAX:
        return "above_maximum"
    return None


# ---------------------------------------------------------------- 2SKD（§6）


def two_skd(password: str, sk: bytes, account_id: bytes, kdf: bytes) -> dict:
    assert kdf_validate(kdf) is None
    _, m, t, p = struct.unpack(">BIII", kdf[:13])
    salt = kdf[13:]
    pw = unicodedata.normalize("NFKD", password).encode("utf-8")
    assert 0 < len(pw) <= 4096
    k_p = hash_secret_raw(
        secret=pw, salt=salt, time_cost=t, memory_cost=m, parallelism=p,
        hash_len=32, type=Type.ID, version=19,
    )
    k_s = hkdf_sha256(sk, account_id, b"keevo/v1/secret-key", 32)
    auk = hkdf_sha256(k_p + k_s, account_id, b"keevo/v1/auk", 32)
    auk_kid = hkdf_sha256(auk, account_id, b"keevo/v1/auk-kid", 16)
    return {"nfkd": pw, "k_p": k_p, "k_s": k_s, "auk": auk, "auk_kid": auk_kid}


# ---------------------------------------------------------------- 填充与信封（§8）


def padded_len(n: int) -> int:
    if n <= 256:
        return 256
    e = n.bit_length() - 1
    s = e.bit_length()
    mask = (1 << (e - s)) - 1
    return (n + mask) & ~mask


def pad(m: bytes) -> bytes:
    assert len(m) <= MAX_PLAINTEXT
    n = 4 + len(m)
    return struct.pack(">I", len(m)) + m + bytes(padded_len(n) - n)


def aad(kid, object_type, part, part_index, account_id, vault_id, object_id, rev_id, binding) -> bytes:
    out = (
        b"keevo/v1/aad"
        + bytes([0x01, 0x01])
        + kid
        + bytes([object_type, part])
        + struct.pack(">I", part_index)
        + account_id + vault_id + object_id + rev_id + binding
    )
    assert len(out) == 132
    return out


def seal(key: bytes, kid: bytes, nonce: bytes, ctx: dict, plaintext: bytes) -> tuple[bytes, bytes]:
    a = aad(kid, **ctx)
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(pad(plaintext), a, nonce, key)
    return bytes([0x01, 0x01]) + kid + nonce + ct, a


def keyset_binding(epoch: int, kdf: bytes) -> bytes:
    return hashlib.sha256(b"keevo/v1/keyset-binding" + struct.pack(">Q", epoch) + kdf).digest()


# ---------------------------------------------------------------- 自检：先对照 RFC 验证本实现


def self_check() -> None:
    h = bytes.fromhex
    assert hkdf_sha256(h("0b" * 22), h("000102030405060708090a0b0c"), h("f0f1f2f3f4f5f6f7f8f9"), 42) == h(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    ), "RFC 5869 A.1"
    assert hkdf_sha256(h("0b" * 22), b"", b"", 42) == h(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    ), "RFC 5869 A.3"
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
        h("50515253c0c1c2c3c4c5c6c7"),
        h("404142434445464748494a4b4c4d4e4f5051525354555657"),
        h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
    )
    assert ct[-16:] == h("c0875924c1c7987947deafd8780acf49"), "draft-irtf-cfrg-xchacha-03 A.1"


# ---------------------------------------------------------------- 向量生成


def secret_key_vectors() -> dict:
    encode = []
    for i in range(4):
        sk = det(f"secret-key/{i}", 16)
        encode.append({"bytes": sk.hex(), "display": secret_key_encode(sk)})
    # 边界值：全 0、全 1
    for sk in (bytes(16), b"\xff" * 16):
        encode.append({"bytes": sk.hex(), "display": secret_key_encode(sk)})

    base_sk = det("secret-key/0", 16)
    canonical = secret_key_encode(base_sk)
    compact = canonical.replace("-", "")
    body = compact[2:]
    fullwidth = "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in canonical)
    lookalike = "K1" + body.replace("0", "O").replace("1", "l")

    ok_inputs = [
        canonical,
        canonical.lower(),
        compact,
        body,
        "  " + " ".join(canonical.split("-")) + "\n",
        lookalike,
        fullwidth,
    ]
    parse_ok = []
    for text in ok_inputs:
        sk, err = secret_key_parse(text)
        assert err is None and sk == base_sk, (text, err)
        parse_ok.append({"input": text, "bytes": sk.hex()})

    flipped = body[:5] + ("X" if body[5] != "X" else "Y") + body[6:]
    bad_cases = [
        ("K2" + body, "wrong_prefix"),
        (compact[:-1], "wrong_length"),
        ("", "wrong_length"),
        ("K1" + body[:10] + "U" + body[11:], "invalid_character"),
        ("K1" + "Z" + body[1:], "non_canonical"),
        ("K1" + flipped, "checksum_mismatch"),
    ]
    parse_err = []
    for text, expected in bad_cases:
        sk, err = secret_key_parse(text)
        assert err == expected, (text, err, expected)
        parse_err.append({"input": text, "error": err})
    return {"encode": encode, "parse_ok": parse_ok, "parse_err": parse_err}


def kdf_vectors() -> list:
    salt = det("kdf/salt", 16)
    cases = [
        ("default", (0x01, 262144, 3, 4, salt)),
        ("minimum", (0x01, M_MIN, T_MIN, P_MIN, salt)),
        ("maximum", (0x01, M_MAX, T_MAX, P_MAX, salt)),
        ("memory_below_minimum", (0x01, M_MIN - 1, 3, 4, salt)),
        ("time_below_minimum", (0x01, M_MIN, 2, 4, salt)),
        ("zero_parallelism", (0x01, M_MIN, 3, 0, salt)),
        ("memory_above_maximum", (0x01, M_MAX + 1, 3, 4, salt)),
        ("parallelism_above_maximum", (0x01, M_MIN, 3, 17, salt)),
        ("unknown_algorithm", (0x02, 262144, 3, 4, salt)),
    ]
    out = []
    for name, args in cases:
        enc = kdf_encode(*args)
        out.append({"name": name, "encoded": enc.hex(), "error": kdf_validate(enc)})
    out.append({"name": "truncated", "encoded": kdf_encode(*cases[0][1])[:-1].hex(), "error": "malformed"})
    return out


def two_skd_vectors() -> list:
    # 后两个用例输入相同、只是 Unicode 组合方式不同，NFKD 后必须得到相同的 AUK
    passwords = [
        ("ascii", "ascii", "correct horse battery staple"),
        ("fullwidth_cjk_ime", "fullwidth", "Ｋｅｅｖｏ　２０２６"),
        ("mixed_scripts_precomposed", "mixed", "密码-Пароль-Señor"),
        ("mixed_scripts_decomposed", "mixed", "密码-Пароль-Señor"),
    ]
    out = []
    for name, label, pw in passwords:
        sk = det(f"2skd/{label}/secret-key", 16)
        account_id = det(f"2skd/{label}/account-id", 16)
        kdf = kdf_encode(0x01, M_MIN, T_MIN, 4, det(f"2skd/{label}/salt", 16))
        r = two_skd(pw, sk, account_id, kdf)
        out.append({
            "name": name,
            "password": pw,
            "password_nfkd": r["nfkd"].hex(),
            "secret_key": sk.hex(),
            "account_id": account_id.hex(),
            "kdf_params": kdf.hex(),
            "k_p": r["k_p"].hex(),
            "k_s": r["k_s"].hex(),
            "auk": r["auk"].hex(),
            "auk_kid": r["auk_kid"].hex(),
        })
    return out


def padding_vectors() -> list:
    lengths = [0, 1, 100, 252, 253, 300, 1000, 4096, 65535, 1_000_000, MAX_PLAINTEXT]
    return [{"plaintext_len": n, "padded_len": padded_len(4 + n)} for n in lengths]


def envelope_vectors() -> list:
    cases = [
        ("item_overview", "item", "overview", 0, b'{"title":"GitHub","subtitle":"octocat"}', True),
        ("empty_plaintext", "item", "details", 0, b"", True),
        ("padme_bucket", "item", "details", 0, det("envelope/padme/plaintext", 1000), True),
        ("vault_wrapped_key", "vault", "wrapped_key", 0, det("envelope/vk/kid", 16) + det("envelope/vk/key", 32), True),
        ("attachment_chunk", "attachment", "chunk", 7, det("envelope/chunk/plaintext", 300), True),
        ("with_binding", "item", "details", 0, "密码 🔐".encode(), False),
    ]
    out = []
    for name, otype, part, index, plaintext, zero_binding in cases:
        key = det(f"envelope/{name}/key", 32)
        kid = det(f"envelope/{name}/kid", 16)
        nonce = det(f"envelope/{name}/nonce", 24)
        ctx = {
            "object_type": OBJECT_TYPES[otype],
            "part": PARTS[part],
            "part_index": index,
            "account_id": det(f"envelope/{name}/account-id", 16),
            "vault_id": det(f"envelope/{name}/vault-id", 16),
            "object_id": det(f"envelope/{name}/object-id", 16),
            "rev_id": det(f"envelope/{name}/rev-id", 16),
            "binding": ZERO32 if zero_binding else det(f"envelope/{name}/binding", 32),
        }
        env, a = seal(key, kid, nonce, ctx, plaintext)
        # 用 libsodium 解密一次，确认可逆
        assert crypto_aead_xchacha20poly1305_ietf_decrypt(env[42:], a, nonce, key) == pad(plaintext)
        out.append({
            "name": name,
            "key": key.hex(),
            "kid": kid.hex(),
            "nonce": nonce.hex(),
            "object_type": ctx["object_type"],
            "part": ctx["part"],
            "part_index": index,
            "account_id": ctx["account_id"].hex(),
            "vault_id": ctx["vault_id"].hex(),
            "object_id": ctx["object_id"].hex(),
            "rev_id": ctx["rev_id"].hex(),
            "binding": ctx["binding"].hex(),
            "plaintext": plaintext.hex(),
            "aad": a.hex(),
            "envelope": env.hex(),
        })
    return out


def keyset_vectors() -> list:
    account_id = det("keyset/account-id", 16)
    auk = det("keyset/auk", 32)
    auk_kid = hkdf_sha256(auk, account_id, b"keevo/v1/auk-kid", 16)
    kdf = kdf_encode(0x01, 262144, 3, 4, det("keyset/salt", 16))
    epoch = 1
    fields = {name: (det(f"keyset/{name}/kid", 16), det(f"keyset/{name}/key", 32)) for name in ("ask", "syk", "sign")}
    plaintext = b"\x01" + b"".join(kid + key for kid, key in fields.values())
    assert len(plaintext) == 145
    binding = keyset_binding(epoch, kdf)
    nonce = det("keyset/nonce", 24)
    ctx = {
        "object_type": OBJECT_TYPES["account_keyset"],
        "part": PARTS["content"],
        "part_index": 0,
        "account_id": account_id,
        "vault_id": ZERO16,
        "object_id": account_id,
        "rev_id": ZERO16,
        "binding": binding,
    }
    env, _ = seal(auk, auk_kid, nonce, ctx, plaintext)
    return [{
        "name": "keyset_v1",
        "account_id": account_id.hex(),
        "auk": auk.hex(),
        "auk_kid": auk_kid.hex(),
        "epoch": epoch,
        "kdf_params": kdf.hex(),
        "ask_kid": fields["ask"][0].hex(),
        "ask": fields["ask"][1].hex(),
        "syk_kid": fields["syk"][0].hex(),
        "syk": fields["syk"][1].hex(),
        "sign_kid": fields["sign"][0].hex(),
        "sign_seed": fields["sign"][1].hex(),
        "binding": binding.hex(),
        "nonce": nonce.hex(),
        "envelope": env.hex(),
    }]


# ---------------------------------------------------------------- §8.9 附件（草案）

CHUNK_LEN = 65536


def canonical_str(text: str) -> str:
    """vault-format.md §1.1 的字符串规范编码：只转义 "、\\ 与 U+0000–U+001F。"""
    short = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}
    out = ['"']
    for ch in text:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif c in short:
            out.append(short[c])
        elif c < 0x20:
            out.append(f"\\u{c:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def attachment_meta(item_id: bytes, name: str, size: int, chunks: int) -> bytes:
    """§8.9 的元数据：成员 v、item、name、size、chunks，按 vault-format.md §1.1 规范编码。"""
    text = (
        '{"v":1,"item":"' + item_id.hex() + '","name":' + canonical_str(name)
        + ',"size":' + str(size) + ',"chunks":' + str(chunks) + "}"
    )
    meta = text.encode("utf-8")
    assert len(meta) <= 1024
    return meta


def attachment_case(name: str, file_name: str, data: bytes, error: str | None = None, meta_override: bytes | None = None,
                    ref_override: dict | None = None) -> dict:
    """按 §8.9 封装一个附件。`error` 不为空时是反例：读取方必须报告篡改（`tampered`）。"""
    label = f"attachment/{name}"
    account_id = det(f"{label}/account-id", 16)
    vault_id = det(f"{label}/vault-id", 16)
    item_id = det(f"{label}/item-id", 16)
    attachment_id = det(f"{label}/attachment-id", 16)
    vk_kid, vk = det(f"{label}/vk-kid", 16), det(f"{label}/vk", 32)
    ak_kid, ak = det(f"{label}/ak-kid", 16), det(f"{label}/ak", 32)
    n = -(-len(data) // CHUNK_LEN)

    def ctx(part: str, index: int, binding: bytes) -> dict:
        return {
            "object_type": OBJECT_TYPES["attachment"], "part": PARTS[part], "part_index": index,
            "account_id": account_id, "vault_id": vault_id, "object_id": attachment_id,
            "rev_id": ZERO16, "binding": binding,
        }

    wrapped, _ = seal(vk, vk_kid, det(f"{label}/nonce/wrapped", 24), ctx("wrapped_key", 0, ZERO32), ak_kid + ak)
    meta = meta_override if meta_override is not None else attachment_meta(item_id, file_name, len(data), n)
    meta_ct, _ = seal(ak, ak_kid, det(f"{label}/nonce/meta", 24), ctx("content", 0, ZERO32), meta)
    binding = struct.pack(">I", n) + bytes(28)
    chunks = []
    for i in range(n):
        piece = data[i * CHUNK_LEN:(i + 1) * CHUNK_LEN]
        ct, _ = seal(ak, ak_kid, det(f"{label}/nonce/chunk/{i}", 24), ctx("chunk", i, binding), piece)
        chunks.append(ct)
    # 各部分的长度（§8.9 的表）
    assert len(wrapped) == 314
    assert 314 <= len(meta_ct) <= 1146
    assert all(len(c) == 67642 for c in chunks[:-1])
    assert all(314 <= len(c) <= 67642 for c in chunks[-1:])
    reference = {"name": file_name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    reference.update(ref_override or {})
    out = {
        "name": name,
        "account_id": account_id.hex(), "vault_id": vault_id.hex(), "item_id": item_id.hex(),
        "attachment_id": attachment_id.hex(),
        "vk_kid": vk_kid.hex(), "vk": vk.hex(),
        "reference": reference,
        "content_len": len(data),
        "content_sha256": hashlib.sha256(data).hexdigest(),
        "meta": meta.decode("utf-8"),
        "wrapped_key": wrapped.hex(),
        "meta_ct": meta_ct.hex(),
        "chunks": [c.hex() for c in chunks],
    }
    if error is not None:
        out["error"] = error
    return out


def attachment_vectors() -> dict:
    valid = [
        # 两块：一个完整块（密文恰好 67642 字节）与一个短块；文件名带转义与非 ASCII 字符
        attachment_case("two_chunks", '备份 "db"\\1.sql', det("attachment/two_chunks/data", CHUNK_LEN + 100)),
        attachment_case("exactly_one_chunk", "a.bin", det("attachment/exactly_one_chunk/data", CHUNK_LEN)),
        attachment_case("empty", "empty.txt", b""),
    ]
    small = det("attachment/small/data", 300)
    item = det("attachment/meta_not_canonical/item-id", 16)
    invalid = [
        attachment_case("meta_not_canonical", "a.txt", small, "tampered",
                        meta_override=('{"v":1, "item":"' + item.hex() + '","name":"a.txt","size":300,"chunks":1}').encode()),
        attachment_case("meta_unknown_member", "a.txt", small, "tampered",
                        meta_override=('{"v":1,"item":"' + det("attachment/meta_unknown_member/item-id", 16).hex()
                                       + '","name":"a.txt","size":300,"chunks":1,"mime":"text/plain"}').encode()),
        attachment_case("meta_other_item", "a.txt", small, "tampered",
                        meta_override=attachment_meta(det("attachment/other", 16), "a.txt", 300, 1)),
        attachment_case("reference_size_differs", "a.txt", small, "tampered", ref_override={"size": 301}),
        attachment_case("reference_name_differs", "a.txt", small, "tampered", ref_override={"name": "b.txt"}),
        attachment_case("reference_sha256_differs", "a.txt", small, "tampered",
                        ref_override={"sha256": hashlib.sha256(b"other").hexdigest()}),
    ]
    return {
        "spec": "spec/crypto.md §8.9（草案）",
        "generator": "spec/reference/generate_vectors.py",
        "note": "所有字节串均为小写十六进制。测试输入由固定标签确定性派生，不是真实密钥。valid：读取方解开 VK 包裹的 AK、"
                "核对元数据与引用，得到长度为 content_len、SHA-256 为 content_sha256 的内容；meta 是元数据的明文，也是写入方"
                "应产生的规范编码。invalid：读取方必须报告篡改。",
        "valid": valid,
        "invalid": invalid,
    }


# ---------------------------------------------------------------- export.md §3 加密导出文件（草案）

EXPORT_MAGIC = b"KEEVOEXP"


def export_key(password: str, kdf: bytes) -> bytes:
    """k = Argon2id(NFKD(导出密码), KdfParams)；key = HKDF-SHA256(k, salt = 空, info = "keevo/v1/export")。"""
    alg, m, t, p = kdf[0], *struct.unpack(">III", kdf[1:13])
    assert alg == KDF_ALG_ARGON2ID
    salt = kdf[13:29]
    pw = unicodedata.normalize("NFKD", password).encode("utf-8")
    assert pw, "口令不能为空"
    k = hash_secret_raw(pw, salt, time_cost=t, memory_cost=m, parallelism=p, hash_len=32, type=Type.ID, version=19)
    return hkdf_sha256(k, b"", b"keevo/v1/export", 32)


def export_seal(password: str, kdf: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    header = EXPORT_MAGIC + b"\x01" + kdf + nonce
    assert len(header) == 62
    return header + crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, header, nonce, export_key(password, kdf))


def export_open(password: str, data: bytes) -> bytes:
    """读取规则（不含本机 KDF 预算，那是读取方的本机策略，crypto §5.3）。返回明文，或抛出带错误码的 ValueError。"""
    if not data.startswith(EXPORT_MAGIC) or len(data) < 9:
        raise ValueError("malformed")
    if data[8] != 0x01:
        raise ValueError("unsupported_version")
    if len(data) < 62 + 16:
        raise ValueError("malformed")
    kdf = data[9:38]
    if kdf_validate(kdf) is not None:
        raise ValueError("kdf_invalid")
    header, body = data[:62], data[62:]
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(body, header, data[38:62], export_key(password, kdf))
    except Exception:  # noqa: BLE001 — libsodium 的认证失败
        raise ValueError("decryption_failed") from None


def export_vectors() -> dict:
    # 规范允许的最小参数，测试快；写出方实际使用默认参数（crypto §5.2）
    kdf = kdf_encode(KDF_ALG_ARGON2ID, M_MIN, T_MIN, 1, det("export/salt", 16))
    plain = json.dumps({"format": "keevo-export", "version": 1, "exported_at": "2026-11-20T00:00:00Z",
                        "vaults": [{"name": "个人", "items": [{"type": "login", "title": "GitHub", "fields": [
                            {"kind": "concealed", "label": "密码", "purpose": "password", "value": "  correct horse  "}]}]}]},
                       ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    # 另一组合法参数：迭代次数与并行度不同
    kdf_other = kdf_encode(KDF_ALG_ARGON2ID, M_MIN, T_MIN + 1, 2, det("export/salt-other", 16))
    valid = []
    for name, password, equivalent, plaintext, kdf in [
        ("json_items", "plum orbit cactus velvet 41", None, plain, kdf),
        # 全角与半角的口令 NFKD 之后相同，两者都能打开
        ("nfkd_equivalent", "ｐｌｕｍ orbit cactus velvet ４１", "plum orbit cactus velvet 41", plain, kdf),
        ("empty_plaintext", "plum orbit cactus velvet 41", None, b"", kdf),
        ("other_kdf_params", "plum orbit cactus velvet 41", None, plain, kdf_other),
    ]:
        nonce = det(f"export/{name}/nonce", 24)
        data = export_seal(password, kdf, nonce, plaintext)
        assert export_open(password, data) == plaintext
        case = {
            "name": name,
            "password": password,
            "kdf_params": kdf.hex(),
            "nonce": nonce.hex(),
            "aad": data[:62].hex(),
            "key": export_key(password, kdf).hex(),
            "plaintext": plaintext.hex(),
            "file": data.hex(),
        }
        if equivalent is not None:
            assert export_open(equivalent, data) == plaintext
            case["equivalent_password"] = equivalent
        valid.append(case)

    base = bytes.fromhex(valid[0]["file"])
    password = valid[0]["password"]
    invalid = []

    def bad(name: str, data: bytes, error: str, pw: str = password):
        try:
            export_open(pw, data)
        except ValueError as e:
            assert str(e) == error, (name, str(e), error)
        else:
            raise AssertionError(f"{name} 应当失败")
        invalid.append({"name": name, "password": pw, "file": data.hex(), "error": error})

    def flip(i: int) -> bytes:
        b = bytearray(base)
        b[i] ^= 0x01
        return bytes(b)

    bad("wrong_password", base, "decryption_failed", "plum orbit cactus velvet 42")
    bad("magic_changed", flip(0), "malformed")
    bad("version_2", base[:8] + b"\x02" + base[9:], "unsupported_version")
    bad("salt_changed", flip(9 + 13), "decryption_failed")
    # KDF 参数改成另一组合法的值：派生出的密钥与 AAD 都变了，认证失败
    bad("kdf_t_changed_within_range", base[:9] + kdf_encode(KDF_ALG_ARGON2ID, M_MIN, T_MIN + 1, 1, det("export/salt", 16)) + base[38:],
        "decryption_failed")
    bad("nonce_changed", flip(38), "decryption_failed")
    bad("ciphertext_changed", flip(62), "decryption_failed")
    bad("tag_changed", flip(len(base) - 1), "decryption_failed")
    bad("truncated_before_tag", base[:62 + 15], "malformed")
    bad("kdf_t_below_minimum", base[:9] + kdf_encode(KDF_ALG_ARGON2ID, M_MIN, T_MIN - 1, 1, det("export/salt", 16)) + base[38:],
        "kdf_invalid")
    bad("kdf_unknown_algorithm", base[:9] + kdf_encode(0x02, M_MIN, T_MIN, 1, det("export/salt", 16)) + base[38:],
        "kdf_invalid")
    return {
        "spec": "spec/export.md §3（草案）",
        "generator": "spec/reference/generate_vectors.py",
        "note": "所有字节串均为小写十六进制。测试输入由固定标签确定性派生，不是真实口令。valid：用 password（以及 "
                "equivalent_password，NFKD 后相同）打开 file 得到 plaintext；写出方用 kdf_params 与 nonce 应产生同样的 file。"
                "aad 为 file 的前 62 字节，key 为 HKDF 之后的密钥。invalid：读取必须失败，error 为期望的错误：malformed、"
                "unsupported_version、kdf_invalid（KDF 参数不合法，crypto §5.2）、decryption_failed（口令错误与文件被改动不区分）。"
                "超出本机 KDF 预算的文件也被拒绝，那是读取方的本机策略，不在向量中。",
        "valid": valid,
        "invalid": invalid,
    }


def build_export() -> str:
    return json.dumps(export_vectors(), ensure_ascii=False, indent=2) + "\n"


def build_attachment() -> str:
    return json.dumps(attachment_vectors(), ensure_ascii=False, indent=2) + "\n"


def build() -> str:
    self_check()
    doc = {
        "spec": "spec/crypto.md",
        "spec_version": "0.1",
        "generator": "spec/reference/generate_vectors.py",
        "note": "所有字节串均为小写十六进制。测试输入由固定标签确定性派生，不是真实密钥。",
        "secret_key": secret_key_vectors(),
        "kdf_params": kdf_vectors(),
        "two_skd": two_skd_vectors(),
        "padding": padding_vectors(),
        "envelope": envelope_vectors(),
        "keyset": keyset_vectors(),
    }
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="只比对，不写入")
    args = parser.parse_args()
    outputs = [(OUTPUT, build()), (ATTACHMENT_OUTPUT, build_attachment()), (EXPORT_OUTPUT, build_export())]
    if args.check:
        stale = [p for p, content in outputs if not p.exists() or p.read_text(encoding="utf-8") != content]
        for p in stale:
            print(f"{p} 与参考实现的输出不一致，请重新生成。", file=sys.stderr)
        if stale:
            return 1
        print("测试向量与参考实现一致。")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    for p, content in outputs:
        p.write_text(content, encoding="utf-8")
        print(f"已写入 {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
