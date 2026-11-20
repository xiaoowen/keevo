# Keevo 规范

这里是 Keevo 的**可审计规范**。任何人都应该能只凭这些文档，写出与 Keevo 互通的实现。

**评审者请先读 [REVIEW.md](REVIEW.md)**：评审范围、阅读顺序、重点问题清单与反馈方式。

| 规范 | 版本 | 状态 | 测试向量 |
|---|---|---|---|
| [crypto.md](crypto.md)：账户密钥、KDF、2SKD、密钥集、加密信封、附件 | 1.7 | **已冻结**（§8.7 本机密钥包裹、§8.8 本机记录是本机格式，不在冻结范围内；§8.9 附件是草案） | [test-vectors/crypto-v1.json](test-vectors/crypto-v1.json)；[attachment-v1.json](test-vectors/attachment-v1.json)（§8.9 附件，草案） |
| [revisions.md](revisions.md)：修订图、记录、HLC、合并 | 1.3 | **已冻结**（§7.3 附件内容的回收是草案） | [test-vectors/revisions-v1.json](test-vectors/revisions-v1.json)（24 个合并场景） |
| [vault-format.md](vault-format.md)：条目与保险库的明文结构 | 1.6 | **已冻结**（§2.5 条目详情 v2 是草案） | [test-vectors/vault-format-v1.json](test-vectors/vault-format-v1.json)（规范编码、正向与负向解码）；[vault-format-v2.json](test-vectors/vault-format-v2.json)（附件字段） |
| [ipc.md](ipc.md)：浏览器扩展与桌面应用的本地通信 | 2.3 | **协议 v1 已冻结**；协议 v2（§5.5，保存与更新）与 v3（§5.6，搜索、打开、解锁）尚未冻结 | [test-vectors/ipc-v1.json](test-vectors/ipc-v1.json)（配对承诺、XX 与 IK 的 v1 / v2 握手、SAS 与词表映射、传输消息）；SAS 词表 v1：[sas-wordlist-v1.tsv](sas-wordlist-v1.tsv) |
| [secret-refs.md](secret-refs.md)：`keevo://` 密钥引用的语法与解析 | 0.1 | 草案（M1.4） | 单元测试（`keevo-core` 的 `secret_ref`） |
| [cli.md](cli.md)：命令行工具与 Vault Service 的协议、终端会话授权 | 0.2 | 草案（M1.4） | 集成测试（`keevo-service` 的 `cli`） |
| [ssh-agent.md](ssh-agent.md)：SSH Agent 的消息、密钥、授权策略 | 0.5 | 草案（M1.4） | Ed25519：RFC 8032 已知答案；与 OpenSSH 的互通测试（`ssh-add`、`ssh-keygen -Y`）；导入：`ssh-keygen` 与 `openssl` 生成的私钥（`crates/keevo-ssh/src/testdata/`） |
| [export.md](export.md)：导出文件（Keevo 加密文件、JSON、CSV） | 0.3 | 草案（M1.5） | [test-vectors/export-v1.json](test-vectors/export-v1.json)（加密文件，独立实现生成）；单元测试（`keevo-crypto` 的 `export`、`keevo-core` 的 `import`：导出后再导入）；Bitwarden 有密码保护的导出：`openssl` 与 Python 独立生成的样例（`crates/keevo-core/src/import/testdata/`） |

2026-11-18 冻结，此前经过四轮模型评审，报告与处理记录在 [docs/reviews/](../docs/reviews/)。

## 冻结清单

"冻结"指：下列格式的字节、接受规则与合并语义从此固定。任何改变都必须使用新的线上版本标识，并让新实现继续读取旧格式（见"版本规则"）。

| 格式 | 线上版本标识 | 定义 |
|---|---|---|
| 账户密钥的显示编码 | `K1-` 前缀 | crypto §4 |
| KDF 参数编码 | `alg = 0x01`（Argon2id v0x13） | crypto §5.1–§5.2 |
| 双因子密钥派生 | 域标签 `keevo/v1/…` | crypto §6 |
| 账户密钥集 | 版本字节 `0x01`，145 字节 | crypto §7 |
| 加密信封 | `version = 0x01`，`alg = 0x01` | crypto §8.1–§8.5 |
| 各对象各部分的信封上下文 | 随信封 v1 | crypto §8.6 |
| `object_type`、`part` 的已分配取值 | 随信封 v1 | crypto §9 |
| 条目详情、条目概要、保险库元数据 | 文档字段 `"v": 1` | vault-format §1–§5 |
| 修订图、记录版本、HLC、合并与删除语义 | 随条目详情 v1 | revisions §2–§7 |
| 浏览器 IPC：分帧、配对（XX + 承诺 + SAS）、会话（IK）、消息与错误码 | `hello` 中的 `v = 1`；prologue 与 HKDF 标签 `keevo/v1/ipc…` | ipc §2–§5 |

**不属于格式、可以随实现变化的**：KDF 的本机自动执行预算（crypto §5.3）、排序键的生成算法（vault-format §2.4）、条目类型的默认字段模板、历史保留的数值（revisions §7.2）、SAS 词表（ipc §4.2 的显示映射，单独版本化，当前为 v1）。

**不在 1.0 范围内的格式**：下列格式尚未定义。将来定义时各自使用新的版本标识，不改变上表中已冻结的内容。

| 格式 | 将来的版本标识 | 计划 |
|---|---|---|
| 附件引用与附件分块 | 条目详情 `"v": 2`；`part = Chunk` 的内容 | M1.5 已有草案（vault-format §2.5、crypto §8.9），评审后冻结 |
| 同步日志段、快照、设备证书、Ed25519 签名 | 各自的格式版本；`object_type` 0x05–0x07 | M2 |
| 保险库元数据改用记录映射 | 保险库元数据 `"v": 2` | M2 |
| CLI 会话授权、更多推送事件 | 新的握手用途或 IPC 协议 v2 | M1.4 起 |

## 版本规则

1. **三种版本号彼此独立**：
   - **规范文档的版本**：`1.x` 中的 `x` 只用于不改变格式的澄清、补充向量和修正笔误；任何改变格式的修订，都伴随下面某个线上版本标识的提升。
   - **线上版本标识**：信封的 `version` 与 `alg`、密钥集的版本字节、文档的 `"v"`、IPC 的 `v` 等，各自独立提升。
   - **域分隔标签**中的 `v1`（如 `keevo/v1/aad`）是协议常量，不随文档版本变化。
2. **改变格式时**：新的版本标识必须与旧的区分开；实现必须继续读取全部已冻结的旧版本，必要时提供迁移。不允许"不兼容但仍叫 v1"。
3. **v1 没有扩展点**：未知字段、未知取值、未知消息一律拒绝。扩展只能通过新版本完成。
4. **本机存储**：SQLite schema（`crates/keevo-store`）、本机密钥包裹（crypto §8.7）与本机记录（crypto §8.8）不属于共享格式，由实现自行版本化与迁移；它们不得改变共享格式中的对象、身份或密钥。

## 其他规则

1. **规范先行**：改动先落在规范与测试向量上，实现随后跟进，两者在同一个 PR 中提交。
2. **测试向量来自独立实现**：
   - `reference/generate_vectors.py`（加密）基于 argon2-cffi（Argon2 官方 C 实现）与 libsodium，不复用 Rust 代码。生成前，它会先用 RFC 中的测试向量做自检。
   - `reference/format_vectors.py`（明文格式与合并）只用 Python 标准库，只依据规范文字编写。生成每个向量时都核对该场景的预期结论（例如"因果上更晚的修改胜出"），另带随机多设备模拟检查交换律与结合律。
3. **符合性**：实现必须逐字节复现全部测试向量。CI 会重新运行参考实现，确认已提交的向量没有被手工修改。

## 重新生成测试向量

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes --no-deps -r spec/reference/requirements.txt
.venv/bin/python -I spec/reference/generate_vectors.py
python3 -I spec/reference/format_vectors.py --self-test   # 只用标准库，不需要虚拟环境
```
