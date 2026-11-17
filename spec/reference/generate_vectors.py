#!/usr/bin/env python3
"""Keevo 加密规范（spec/crypto.md）v0.1 的独立参考实现与测试向量生成器。

刻意不复用 Rust 实现的任何代码，只依赖：
  - argon2-cffi：Argon2 官方 C 参考实现的绑定
  - PyNaCl：libsodium 的绑定（XChaCha20-Poly1305）
  - Python 标准库：hashlib、hmac、unicodedata

用法：
  python3 -m venv .venv && .venv/bin/pip install --require-hashes -r spec/reference/requirements.txt
  .venv/bin/python spec/reference/generate_vectors.py            # 写入 spec/test-vectors/crypto-v1.json
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
    content = build()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != content:
            print(f"{OUTPUT} 与参考实现的输出不一致，请重新生成。", file=sys.stderr)
            return 1
        print("测试向量与参考实现一致。")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(content, encoding="utf-8")
    print(f"已写入 {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
