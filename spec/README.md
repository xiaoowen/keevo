# Keevo 规范

这里是 Keevo 的**可审计规范**。任何人都应该能只凭这些文档，写出与 Keevo 互通的实现。

| 规范 | 版本 | 状态 | 测试向量 |
|---|---|---|---|
| [crypto.md](crypto.md)：账户密钥、KDF、2SKD、密钥集、加密信封 | 0.1 | 草案，待外部评审 | [test-vectors/crypto-v1.json](test-vectors/crypto-v1.json) |
| [revisions.md](revisions.md)：修订图、记录、HLC、合并 | 0.1 | 草案，待评审 | JSON 向量计划中；参考实现带多设备随机模拟测试 |
| [vault-format.md](vault-format.md)：条目与保险库的明文结构 | 0.1 | 草案，待评审 | 计划中（M1.1） |
| [ipc.md](ipc.md)：桌面应用与扩展、CLI 的本地通信 | 0.1 | 草案，待评审 | 计划中（扩展侧实现落地后提供跨实现向量） |

## 规则

1. **规范先行**：改动先落在规范与测试向量上，实现随后跟进，两者在同一个 PR 中提交。
2. **测试向量来自独立实现**：
   - `reference/generate_vectors.py` 基于 argon2-cffi（Argon2 官方 C 实现）与 libsodium，不复用 Rust 代码。
   - 生成前，它会先用 RFC 中的测试向量做自检。
3. **符合性**：实现必须逐字节复现全部测试向量。CI 会重新运行参考实现，确认已提交的向量没有被手工修改。
4. **版本**：
   - 0.x 阶段允许不兼容变更。
   - 1.0 之后，任何格式变更都必须引入新的版本号，并保留对旧版本的读取能力。

## 重新生成测试向量

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes --no-deps -r spec/reference/requirements.txt
.venv/bin/python -I spec/reference/generate_vectors.py
```
