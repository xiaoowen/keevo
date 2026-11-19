# 测试用私钥

只用于 `keevo-ssh` 的单元测试，不对应任何真实账户。由下面的命令生成（2026-11-19），口令都是 `correct horse`：

| 文件 | 命令 |
|---|---|
| `ed25519-aes256-ctr` | `ssh-keygen -t ed25519 -N 'correct horse' -C enc256@keevo` |
| `ed25519-aes128-ctr` | 同上，另加 `-Z aes128-ctr`，注释 `enc128@keevo` |
| `ed25519-aes192-ctr` | 同上，另加 `-Z aes192-ctr`，注释 `enc192@keevo` |
| `ed25519-aes256-gcm` | 同上，另加 `-Z aes256-gcm@openssh.com`（不支持的加密方式） |
| `rsa-aes256-ctr` | `ssh-keygen -t rsa -b 2048 -N 'correct horse'`（不支持的算法） |
| `rsa-legacy-encrypted.pem` | `ssh-keygen -t rsa -b 2048 -N 'correct horse' -m PEM`（旧式加密的 PEM） |
| `ec.pem` | `ssh-keygen -t ecdsa -b 256 -N '' -m PEM`（SEC1 PEM，不支持的算法） |
| `ed25519-pkcs8.pem` | `openssl genpkey -algorithm ed25519`（未加密的 PKCS#8） |
