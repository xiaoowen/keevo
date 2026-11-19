#!/usr/bin/env python3
"""Keevo 本地通信协议（spec/ipc.md）的独立参考实现与测试向量生成器。

只依赖 Python 标准库（hashlib、hmac），刻意不复用 Rust 实现与任何第三方密码学库：
  - X25519：按 RFC 7748 实现，启动时用 RFC 7748 §5.2 与 §6.1 的向量自检；
  - ChaCha20-Poly1305：按 RFC 8439 实现，启动时用 RFC 8439 §2.8.2 的向量自检；
  - Noise：按 Noise Protocol Framework（第 34 版）实现 XX 与 IK，套件 25519_ChaChaPoly_SHA256。

覆盖：配对承诺（§4.2 第 1 步）、prologue（§4.1，含协议版本）、XX 配对与 IK 会话的全部握手消息、握手哈希、
SAS（§4.2 第 4 步）及其词表映射（sas-wordlist-v1.tsv）、握手之后每个方向的第一条传输消息。

用法：
  python3 spec/reference/ipc_vectors.py            # 写入 spec/test-vectors/ipc-v1.json
  python3 spec/reference/ipc_vectors.py --check    # 只校验已提交的文件是否一致

所有输入（静态密钥、临时密钥、配对随机数）都由固定标签经 SHA-256 派生，输出可复现。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "spec" / "test-vectors" / "ipc-v1.json"
WORDLIST = ROOT / "spec" / "sas-wordlist-v1.tsv"

# ---------------------------------------------------------------- X25519（RFC 7748）

P25519 = 2**255 - 19


def x25519(k: bytes, u: bytes) -> bytes:
    kb = bytearray(k)
    kb[0] &= 248
    kb[31] &= 127
    kb[31] |= 64
    scalar = int.from_bytes(kb, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        bit = (scalar >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a = (x2 + z2) % P25519
        aa = a * a % P25519
        b = (x2 - z2) % P25519
        bb = b * b % P25519
        e = (aa - bb) % P25519
        c = (x3 + z3) % P25519
        d = (x3 - z3) % P25519
        da = d * a % P25519
        cb = c * b % P25519
        x3 = (da + cb) ** 2 % P25519
        z3 = x1 * (da - cb) ** 2 % P25519
        x2 = aa * bb % P25519
        z2 = e * (aa + 121665 * e) % P25519
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P25519 - 2, P25519) % P25519).to_bytes(32, "little")


def public_key(private: bytes) -> bytes:
    return x25519(private, (9).to_bytes(32, "little"))


# ---------------------------------------------------------------- ChaCha20-Poly1305（RFC 8439）


def _rotl(v: int, c: int) -> int:
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    words = lambda b: [int.from_bytes(b[i : i + 4], "little") for i in range(0, len(b), 4)]  # noqa: E731
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574, *words(key), counter, *words(nonce)]
    s = state[:]
    for _ in range(10):
        _quarter(s, 0, 4, 8, 12)
        _quarter(s, 1, 5, 9, 13)
        _quarter(s, 2, 6, 10, 14)
        _quarter(s, 3, 7, 11, 15)
        _quarter(s, 0, 5, 10, 15)
        _quarter(s, 1, 6, 11, 12)
        _quarter(s, 2, 7, 8, 13)
        _quarter(s, 3, 4, 9, 14)
    return b"".join(((a + b) & 0xFFFFFFFF).to_bytes(4, "little") for a, b in zip(s, state))


def chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        block = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[i : i + 64], block))
    return bytes(out)


def poly1305(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i : i + 16] + b"\x01", "little")
        acc = (acc + n) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b: bytes) -> bytes:
    return b"\x00" * (-len(b) % 16)


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    otk = chacha20_block(key, 0, nonce)[:32]
    ct = chacha20(key, 1, nonce, plaintext)
    mac = aad + _pad16(aad) + ct + _pad16(ct) + len(aad).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
    return ct + poly1305(otk, mac)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    ct, tag = ciphertext[:-16], ciphertext[-16:]
    otk = chacha20_block(key, 0, nonce)[:32]
    mac = aad + _pad16(aad) + ct + _pad16(ct) + len(aad).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
    if not hmac.compare_digest(poly1305(otk, mac), tag):
        raise ValueError("认证失败")
    return chacha20(key, 1, nonce, ct)


def self_test() -> None:
    # RFC 7748 §5.2 第一组
    k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    assert x25519(k, u).hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    # RFC 7748 §6.1 Alice / Bob
    a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    assert public_key(a).hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert x25519(a, public_key(b)).hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    # RFC 8439 §2.8.2
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
        b"sunscreen would be it."
    )
    ct = aead_encrypt(key, nonce, pt, aad)
    assert ct[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691"
    assert ct[:16].hex() == "d31a8d34648e60db7b86afbc53ef7ec2"
    assert aead_decrypt(key, nonce, ct, aad) == pt


# ---------------------------------------------------------------- Noise（25519_ChaChaPoly_SHA256）


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def hmac256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf2(ck: bytes, ikm: bytes) -> tuple[bytes, bytes]:
    temp = hmac256(ck, ikm)
    o1 = hmac256(temp, b"\x01")
    return o1, hmac256(temp, o1 + b"\x02")


class CipherState:
    def __init__(self, k: bytes | None = None) -> None:
        self.k = k
        self.n = 0

    def _nonce(self) -> bytes:
        return b"\x00" * 4 + self.n.to_bytes(8, "little")

    def encrypt(self, ad: bytes, pt: bytes) -> bytes:
        if self.k is None:
            return pt
        ct = aead_encrypt(self.k, self._nonce(), pt, ad)
        self.n += 1
        return ct

    def decrypt(self, ad: bytes, ct: bytes) -> bytes:
        if self.k is None:
            return ct
        pt = aead_decrypt(self.k, self._nonce(), ct, ad)
        self.n += 1
        return pt


class Handshake:
    """一方的 Noise 握手状态。pattern 为 "XX" 或 "IK"。"""

    PATTERNS = {
        "XX": (None, [["e"], ["e", "ee", "s", "es"], ["s", "se"]]),
        "IK": ("rs", [["e", "es", "s", "ss"], ["e", "ee", "se"]]),
    }

    def __init__(self, pattern: str, initiator: bool, s: bytes, e: bytes, prologue: bytes, rs: bytes | None = None):
        name = f"Noise_{pattern}_25519_ChaChaPoly_SHA256".encode()
        self.h = name if len(name) == 32 else (name.ljust(32, b"\x00") if len(name) < 32 else sha256(name))
        self.ck = self.h
        self.cs = CipherState()
        self.initiator = initiator
        self.s, self.s_pub = s, public_key(s)
        self.e, self.e_pub = e, public_key(e)
        self.rs, self.re = rs, None
        self.mix_hash(prologue)
        pre, self.messages = self.PATTERNS[pattern]
        if pre == "rs":
            # 响应方的静态公钥是预先知道的（<- s）
            self.mix_hash(rs if initiator else self.s_pub)
        self.index = 0

    def mix_hash(self, data: bytes) -> None:
        self.h = sha256(self.h, data)

    def mix_key(self, ikm: bytes) -> None:
        self.ck, k = hkdf2(self.ck, ikm)
        self.cs = CipherState(k)

    def encrypt_and_hash(self, pt: bytes) -> bytes:
        ct = self.cs.encrypt(self.h, pt)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ct: bytes) -> bytes:
        pt = self.cs.decrypt(self.h, ct)
        self.mix_hash(ct)
        return pt

    def _dh(self, token: str) -> bytes:
        # token 的第一个字母指发起方的密钥，第二个指响应方的密钥
        mine = {"e": self.e, "s": self.s}
        theirs = {"e": self.re, "s": self.rs}
        a, b = token
        return x25519(mine[a], theirs[b]) if self.initiator else x25519(mine[b], theirs[a])

    def write(self, payload: bytes) -> bytes:
        out = b""
        for token in self.messages[self.index]:
            if token == "e":
                out += self.e_pub
                self.mix_hash(self.e_pub)
            elif token == "s":
                out += self.encrypt_and_hash(self.s_pub)
            else:
                self.mix_key(self._dh(token))
        self.index += 1
        return out + self.encrypt_and_hash(payload)

    def read(self, message: bytes) -> bytes:
        rest = message
        for token in self.messages[self.index]:
            if token == "e":
                self.re, rest = rest[:32], rest[32:]
                self.mix_hash(self.re)
            elif token == "s":
                n = 48 if self.cs.k is not None else 32
                self.rs = self.decrypt_and_hash(rest[:n])
                rest = rest[n:]
            else:
                self.mix_key(self._dh(token))
        self.index += 1
        return self.decrypt_and_hash(rest)

    def split(self) -> tuple[CipherState, CipherState]:
        k1, k2 = hkdf2(self.ck, b"")
        c1, c2 = CipherState(k1), CipherState(k2)
        # 发起方用 c1 发送、c2 接收
        return (c1, c2) if self.initiator else (c2, c1)


# ---------------------------------------------------------------- Keevo 的约定


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac256(salt or b"\x00" * 32, ikm)
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac256(prk, t + info + bytes([i]))
        out += t
        i += 1
    return out[:length]


def prologue(version: int, purpose: str, origin: str) -> bytes:
    return f"keevo/v{version}/ipc".encode() + b"\x00" + purpose.encode() + b"\x00" + origin.encode()


def commitment(static_public: bytes, third: bytes) -> bytes:
    return sha256(b"keevo/v1/ipc-pair-commit", static_public, third)


def sas(handshake_hash: bytes) -> bytes:
    return hkdf_sha256(handshake_hash, b"", b"keevo/v1/ipc-sas", 6)


def derive(label: str) -> bytes:
    return sha256(b"keevo-ipc-vector/", label.encode())


def words(sas_bytes: bytes) -> list[dict[str, str]]:
    table = [line.split("\t") for line in WORDLIST.read_text(encoding="utf-8").splitlines()]
    assert len(table) == 256
    return [{"zh": table[b][2], "en": table[b][1]} for b in sas_bytes]


ORIGIN = "chrome-extension://boojggkmhkakoacccigoiibnlkffcpof/"


def run(name: str, pattern: str, version: int, payloads: list[bytes], transport: list[tuple[str, bytes]]) -> dict:
    ext_s, ext_e = derive(f"{name}/extension-static"), derive(f"{name}/extension-ephemeral")
    svc_s, svc_e = derive(f"{name}/service-static"), derive(f"{name}/service-ephemeral")
    purpose = "pair" if pattern == "XX" else "session"
    pro = prologue(version, purpose, ORIGIN)
    rs = public_key(svc_s) if pattern == "IK" else None
    i = Handshake(pattern, True, ext_s, ext_e, pro, rs=rs)
    r = Handshake(pattern, False, svc_s, svc_e, pro)
    messages = []
    for idx, payload in enumerate(payloads):
        sender, receiver = (i, r) if idx % 2 == 0 else (r, i)
        ct = sender.write(payload)
        assert receiver.read(ct) == payload
        messages.append({"sender": "initiator" if sender is i else "responder", "payload": payload.hex(), "message": ct.hex()})
    assert i.h == r.h
    assert r.rs == public_key(ext_s) and i.rs == public_key(svc_s)
    i_send, i_recv = i.split()
    r_send, r_recv = r.split()
    frames = []
    for who, pt in transport:
        send, recv = (i_send, r_recv) if who == "initiator" else (r_send, i_recv)
        ct = send.encrypt(b"", pt)
        assert recv.decrypt(b"", ct) == pt
        frames.append({"sender": who, "plaintext": pt.decode(), "message": ct.hex()})
    out = {
        "name": name,
        "pattern": f"Noise_{pattern}_25519_ChaChaPoly_SHA256",
        "protocol_version": version,
        "extension_origin": ORIGIN,
        "prologue": pro.hex(),
        "initiator_static_private": ext_s.hex(),
        "initiator_static_public": public_key(ext_s).hex(),
        "initiator_ephemeral_private": ext_e.hex(),
        "responder_static_private": svc_s.hex(),
        "responder_static_public": public_key(svc_s).hex(),
        "responder_ephemeral_private": svc_e.hex(),
        "messages": messages,
        "handshake_hash": i.h.hex(),
        "transport": frames,
    }
    if pattern == "XX":
        s = sas(i.h)
        out["sas"] = s.hex()
        out["sas_words"] = words(s)
    return out


def pairing(name: str, version: int, display_name: str) -> tuple[dict, dict]:
    ext_pub = public_key(derive(f"{name}/extension-static"))
    third = derive(f"{name}/pair-nonce") + display_name.encode()
    commit = commitment(ext_pub, third)
    vector = run(
        name,
        "XX",
        version,
        [commit, b"", third],
        [("responder", b'{"event":"paired"}'), ("initiator", b'{"id":1,"method":"status"}')],
    )
    return vector, {"name": name, "extension_static_public": ext_pub.hex(), "third": third.hex(), "commitment": commit.hex()}


def build() -> dict:
    xx1, c1 = pairing("xx-pair-v1", 1, "Chrome · 个人")
    xx2, c2 = pairing("xx-pair-v2", 2, "Chrome · 工作")
    long_name = "名" * 85 + "x"  # 256 字节：显示名原始字节的上限
    ext_pub = public_key(derive("commitment-max/extension-static"))
    third = derive("commitment-max/pair-nonce") + long_name.encode()
    assert len(long_name.encode()) == 256
    c3 = {"name": "commitment-max-name", "extension_static_public": ext_pub.hex(), "third": third.hex(), "commitment": commitment(ext_pub, third).hex()}
    ik1 = run(
        "ik-session-v1",
        "IK",
        1,
        [b"", b""],
        [
            ("initiator", b'{"id":1,"method":"candidates","params":{"url":"https://github.com/login"}}'),
            ("responder", b'{"id":1,"result":{"items":[{"item_id":"00112233445566778899aabbccddeeff","title":"GitHub","subtitle":"octocat"}]}}'),
        ],
    )
    ik2 = run(
        "ik-session-v2",
        "IK",
        2,
        [b"", b""],
        [
            ("initiator", b'{"id":1,"method":"save","params":{"url":"https://news.example/login","username":"reader","password":"p"}}'),
            ("responder", b'{"id":1,"result":{"item_id":"00112233445566778899aabbccddeeff"}}'),
        ],
    )
    return {
        "description": "Keevo IPC 跨实现测试向量（spec/ipc.md），由 spec/reference/ipc_vectors.py 生成，只依赖 Python 标准库。"
        "所有十六进制均为小写；Noise 消息是握手或传输层的原始字节（不含 base64 与控制层 JSON）。",
        "commitments": [c1, c2, c3],
        "handshakes": [xx1, xx2, ik1, ik2],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="只校验已提交的文件")
    args = parser.parse_args()
    self_test()
    text = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if args.check:
        if OUT.read_text(encoding="utf-8") != text:
            print(f"✗ {OUT.relative_to(ROOT)} 与参考实现的输出不一致", file=sys.stderr)
            return 1
        print(f"✓ {OUT.relative_to(ROOT)} 与参考实现一致")
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"已写入 {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
