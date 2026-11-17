#!/usr/bin/env python3
"""检查密码学边界：除 keevo-crypto 外，workspace 中任何 crate 都不得直接依赖密码学原语库。

规则来源：docs/architecture.md §3、spec/crypto.md §10。
确需例外时（例如将来 keevo-ssh 依赖 ssh-key），在 ALLOWED 中登记并在 PR 中说明理由。
"""

from __future__ import annotations

import json
import subprocess
import sys

BOUNDARY_CRATE = "keevo-crypto"

# 密码学原语与底层构造。只列"原语"，不列 zeroize 这类内存卫生工具。
FORBIDDEN = {
    "aead", "aes", "aes-gcm", "aes-gcm-siv", "argon2", "aws-lc-rs", "blake2", "blake3",
    "chacha20", "chacha20poly1305", "cipher", "crypto-bigint", "crypto-common", "curve25519-dalek",
    "digest", "ecdsa", "ed25519", "ed25519-dalek", "elliptic-curve", "getrandom", "hkdf", "hmac",
    "hpke", "libsodium-sys", "ml-dsa", "ml-kem", "opaque-ke", "openssl", "p256", "p384", "pbkdf2",
    "poly1305", "rand", "rand_chacha", "rand_core", "ring", "rsa", "scrypt", "sha1", "sha2",
    "sha3", "snow", "sodiumoxide", "universal-hash", "x25519-dalek",
}

# 例外登记：{crate 名: {允许直接依赖的原语库}}
ALLOWED: dict[str, set[str]] = {}


def main() -> int:
    meta = json.loads(
        subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--no-deps"])
    )
    violations = []
    for pkg in meta["packages"]:
        name = pkg["name"]
        if name == BOUNDARY_CRATE:
            continue
        allowed = ALLOWED.get(name, set())
        for dep in pkg["dependencies"]:
            dep_name = dep.get("rename") or dep["name"]
            if dep["name"] in FORBIDDEN and dep["name"] not in allowed:
                kind = dep.get("kind") or "normal"
                violations.append(f"{name} 直接依赖了 {dep_name}（{kind}）")
    if violations:
        print("违反密码学边界，只有 keevo-crypto 可以直接依赖密码学原语库：", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1
    print(f"密码学边界检查通过（{len(meta['packages'])} 个 crate）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
