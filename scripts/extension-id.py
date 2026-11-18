#!/usr/bin/env python3
"""由扩展清单中的公钥计算 Chrome 扩展 ID：公钥 DER 的 SHA-256 取前 16 字节，每个十六进制数字映射到 a–p。"""
import base64
import hashlib
import json
import sys

key = json.load(open(sys.argv[1], encoding="utf-8"))["key"]
digest = hashlib.sha256(base64.b64decode(key)).hexdigest()[:32]
print("".join(chr(ord("a") + int(c, 16)) for c in digest))
