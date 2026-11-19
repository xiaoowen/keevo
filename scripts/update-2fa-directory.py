#!/usr/bin/env python3
"""更新安全中心"未开启两步验证"使用的网站列表（docs/product.md §5.6）。

从 2fa.directory 的公开数据（MIT 许可，https://github.com/2factorauth/twofactorauth）下载支持一次性密码
（TOTP）的网站，写入 crates/keevo-core/src/security/totp_sites.txt：每行一个域名，排序去重。
Keevo 运行时不联网：只在维护者运行这个脚本时下载，结果随源码一起审查与提交。

用法：python3 -I scripts/update-2fa-directory.py
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys
import urllib.request

SOURCE = "https://api.2fa.directory/v4/totp.json"
OUT = pathlib.Path(__file__).resolve().parent.parent / "crates/keevo-core/src/security/totp_sites.txt"
DOMAIN = re.compile(r"^[a-z0-9.-]+\.[a-z0-9-]+$")


def main() -> int:
    req = urllib.request.Request(SOURCE, headers={"User-Agent": "keevo-maintenance-script"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 — 固定的 https 地址
        raw = resp.read()
    data = json.loads(raw)
    domains = sorted({d.lower() for d, v in data.items() if "totp" in v.get("methods", []) and DOMAIN.match(d.lower())})
    if len(domains) < 500:
        print(f"数据异常：只有 {len(domains)} 个网站", file=sys.stderr)
        return 1
    OUT.write_text("\n".join(domains) + "\n")
    print(f"已写入 {len(domains)} 个网站；原始数据 SHA-256 {hashlib.sha256(raw).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
