# Keevo 加密规范

- **版本**：0.4（草案）
- **状态**：已按 2026-11-18 三轮模型评审修订（[第一轮](../docs/reviews/2026-11-18-model-review-response.md)、[第二轮](../docs/reviews/2026-11-18-model-review-round2-response.md)、[第三轮](../docs/reviews/2026-11-18-model-review-round3-response.md)处理记录）。§8.6 本机密钥包裹单独保持草案，M1.1 定稿。评审通过前，格式可能有不兼容的变更。
- **参考实现**：`crates/keevo-crypto`（Rust）
- **独立实现**：`spec/reference/generate_vectors.py`（Python，基于 argon2-cffi 与 libsodium），用来生成测试向量。
- **测试向量**：`spec/test-vectors/crypto-v1.json`

任何实现都必须通过全部测试向量，才算符合本规范。

## 1. 范围

v0.1 覆盖 M1 本地保险库所需的全部内容：

- 账户密钥（Secret Key）的生成、编码与解析
- KDF 参数的编码与校验
- 双因子密钥派生（2SKD）
- 账户密钥集的格式与封装
- 加密信封（Envelope）：头部、AAD、长度填充、加解密流程

尚未覆盖，见 §11：附件分块加密、签名、同步文件格式。

## 2. 约定

- `‖` 表示字节串拼接。
- 所有多字节整数一律采用**大端序**。
- 带引号的标签（如 `"keevo/v1/auk"`）表示该 ASCII 字符串的字节，不含结尾的 NUL。
- `Z(n)` 表示 n 个 0x00 字节。
- **ID**：
  - 所有 ID 都是 16 字节，由 CSPRNG 生成，包括 `account_id`、`vault_id`、`object_id`、`rev_id`。
  - 密钥 ID（`kid`）也是 16 字节，推导规则见各节。
  - ID 不是秘密，但也不得包含任何可推断用户信息的内容。
- **随机数**：一律来自操作系统 CSPRNG。在 Rust 中使用 `getrandom`。

## 3. 原语

| 用途 | 原语 | 规范 |
|---|---|---|
| 口令派生 | Argon2id，版本 0x13 | RFC 9106 |
| 密钥派生 | HKDF-SHA-256 | RFC 5869 |
| 哈希 | SHA-256 | FIPS 180-4 |
| 对称 AEAD | XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha-03 |
| Unicode 规范化 | NFKD（口令）、NFKC（账户密钥输入） | UAX #15 |

**实现约束**：除本表所列原语之外，不得引入其他密码学构造。

## 4. 账户密钥（Secret Key）

### 4.1 生成

账户密钥 `SK` 是 16 字节（128 位）随机数，在创建账户的设备上生成，从不离开用户的控制范围。

### 4.2 显示编码

**字母表**：Crockford Base32，`0123456789ABCDEFGHJKMNPQRSTVWXYZ`。

**编码步骤**：

```
d[0..26] = 把 130 位整数 0b00 ‖ SK 从高位起每 5 位切成一组    // 26 个符号；d[0] 只含 3 个有效位，必在 0–7 之间
c[0..2]  = RS2(d)                                            // 2 个校验符号，见下文
s        = Base32(d ‖ c)                                     // 28 个字符
显示     = "K1-" ‖ s[0..7] ‖ "-" ‖ s[7..14] ‖ "-" ‖ s[14..21] ‖ "-" ‖ s[21..28]
```

- `Base32` 把每个 5 位符号映射为字母表中对应的字符。
- 显示形式示例：`K1-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX`，共 34 个字符。
- 前缀 `K1` 标识编码版本。

**校验符号 RS2**：GF(32) 上的系统 Reed–Solomon 码。

- 有限域：GF(2⁵)，本原多项式 p(x) = x⁵ + x² + 1（`0x25`），α = 2。
- 生成多项式：g(x) = (x + α)(x + α²) = x² + 6x + 8。
- `RS2(d)` 是 d(x)·x² mod g(x) 的两个系数，高次在前，其中 d[0] 是 d(x) 的最高次系数。用移位寄存器计算：

```
r1 = r0 = 0
对 d 中的每个符号 m（从 d[0] 开始）：
    f  = m ⊕ r1
    r1 = r0 ⊕ (f · 6)
    r0 = f · 8                // · 为 GF(32) 乘法
RS2(d) = [r1, r0]
```

- **检错能力**：码长 28 ≤ 31，最小距离为 3，因此**任意 1 个或 2 个字符的错误都能被检出**，包括相邻两字符互换。
- **为什么不用哈希截断**：截断的哈希只能以概率检错（例如 10 位约有 1/1024 漏检）。RS 码能给出确定的保证。

### 4.3 解析

按以下步骤解析，每步失败时返回对应的错误码：

1. 对输入做 **NFKC** 规范化。这样中文输入法下输入的全角字符（如 `Ｋ１－`）会变为 ASCII。
2. 把 ASCII 字母转为大写。
3. 删除所有 `-` 和 ASCII 空白字符（空格、`\t`、`\r`、`\n`）。
4. 按长度处理：
   - 长度为 30：必须以 `K1` 开头，否则返回 `wrong_prefix`；去掉前 2 个字符。
   - 长度为 28：视为没有前缀，继续。
   - 其他长度：返回 `wrong_length`。
5. 容错替换：`O` → `0`，`I` → `1`，`L` → `1`。
6. 每个字符都必须在字母表中，否则返回 `invalid_character`。注意 `U` 不在字母表中。
7. 首字符的值必须 ≤ 7，否则返回 `non_canonical`。
8. 解码前 26 个字符得到 `SK`，再按 §4.2 计算校验位；不一致则返回 `checksum_mismatch`。

## 5. KDF 参数

### 5.1 编码

KDF 参数共 29 字节：

```
kdf_params = alg (1) ‖ m_kib (4) ‖ t (4) ‖ p (4) ‖ salt (16)
```

| 字段 | 含义 |
|---|---|
| `alg` | `0x01` 表示 Argon2id v0x13；其他值返回 `unsupported_algorithm` |
| `m_kib` | 内存，单位 KiB |
| `t` | 迭代次数 |
| `p` | 并行度（lane 数） |
| `salt` | 16 字节随机数，创建账户和修改主密码时重新生成 |

长度不是 29 字节时返回 `malformed`。

### 5.2 默认值与界限

| 参数 | 默认值 | 下限 | 上限 |
|---|---|---|---|
| `m_kib` | 262144（256 MiB） | 65536（64 MiB） | 4194304（4 GiB） |
| `t` | 3 | 3 | 32 |
| `p` | 4 | 1 | 16 |

- **下限与上限都硬编码在客户端里**。参数越界时：
  - 低于下限，返回 `below_minimum`。
  - 高于上限，返回 `above_maximum`。
- **为什么要有上限**：KDF 参数以明文存放在同步文件中。上限是**格式**允许的范围，为将来的硬件留了余量；它本身不足以防止资源耗尽，见 §5.3。
- **参数校准**：客户端可以按设备性能上调默认值，但永远不得低于下限。
- **防降级**：KDF 参数纳入密钥集的 AAD（§7.3）。任何篡改都会导致解密失败——但失败发生在 KDF **执行之后**。

### 5.3 本机自动执行预算

KDF 参数在认证之前就要使用，被篡改的参数可以让设备在认证失败前先耗费大量内存与时间（评审 2026-11-18 F3）。因此客户端另设一个更低的**自动执行预算**：

| 参数 | 预算 |
|---|---|
| `m_kib` | ≤ 1048576（1 GiB） |
| `t` | ≤ 10 |
| `p` | ≤ 8 |

- 参数在格式范围内、但超出预算时，返回 `kdf_needs_confirmation`，**不执行任何派生**。
- 界面向用户展示具体参数，说明"解锁参数异常地高，可能被篡改，继续解锁会占用大量内存并耗时较长"。
- **确认绑定到具体参数**：用户确认的是界面展示的那一组参数。派生前再次读取参数，若已不是这一组（例如确认期间被替换为更昂贵的参数），仍返回 `kdf_needs_confirmation`。
- **进程级串行**：同一进程内的 KDF 一律串行执行，与打开了多少个保险库实例无关（第二轮评审 G4）。参考实现把互斥放在 Argon2 调用本身。
- 上表是初始值，不是按设备实测的预算。M1.1 按设备内存与性能校准，并保证不低于默认参数；调高默认值时必须同步检查预算。

## 6. 双因子密钥派生（2SKD）

**输入**：
- 主密码 `password`（Unicode 字符串）
- 账户密钥 `SK`
- `account_id`
- `kdf_params`

```
P    = UTF-8(NFKD(password))
K_p  = Argon2id(password = P, salt = kdf_params.salt,
                m = m_kib, t = t, p = p, tag_length = 32)            // 不使用 secret 与 associated data
K_s  = HKDF-SHA-256(IKM = SK,         salt = account_id, info = "keevo/v1/secret-key", L = 32)
AUK  = HKDF-SHA-256(IKM = K_p ‖ K_s,  salt = account_id, info = "keevo/v1/auk",        L = 32)
kid(AUK) = HKDF-SHA-256(IKM = AUK,    salt = account_id, info = "keevo/v1/auk-kid",    L = 16)
```

- `P` 为空时返回 `empty_password`；`P` 超过 4096 字节时返回 `password_too_long`。
- `AUK`、`K_p`、`K_s`、`P` 都是秘密，用后必须立即清零。
- **`kid(AUK)` 的作用**：让"主密码错误"在解密前就能被识别。它不会额外降低安全性，因为攻击者本来就能用 AEAD 校验来验证口令猜测，而每次猜测的主要成本始终是 Argon2id。
- **预留的派生标签**：`"keevo/v1/opaque"` 留给将来的服务端认证，见 `docs/future/self-hosted-server.md`。

## 7. 账户密钥集

### 7.1 内容

密钥集 v1 的明文共 145 字节：

```
keyset_v1 = 0x01
          ‖ ask_kid (16)  ‖ ask (32)        // 账户对称密钥：包裹保险库密钥
          ‖ syk_kid (16)  ‖ syk (32)        // 账户同步密钥：M2 同步文件的外层加密
          ‖ sign_kid (16) ‖ sign_seed (32)  // 账户签名密钥：Ed25519 私钥种子（RFC 8032），M2 启用
```

- 三把密钥和它们的 `kid` 都在创建账户时随机生成。
- **为什么 M1 就生成 `syk` 与 `sign_seed`**：开启同步时不必修改密钥集格式。
- **解析要求**：版本字节不是 `0x01`，或长度不是 145 字节时，返回 `malformed`。

### 7.2 绑定值

```
binding = SHA-256("keevo/v1/keyset-binding" ‖ epoch (8 字节) ‖ kdf_params (29 字节))
```

`epoch` 从 1 开始，每次修改主密码或轮换密钥时加 1。

**绑定值不提供新鲜度**（评审 2026-11-18 C2）：它防止 KDF 参数被单独篡改、防止旧密文被改标为新的 `epoch`；但一整套旧账户文件（旧参数、旧 `epoch`、旧信封）仍能通过认证。拒绝回滚需要上层保存可信的最大 `epoch`：
- 已加入的设备在本地保存见过的最大 `epoch`，读到更小的值时拒绝并提示（M2，`docs/sync.md` §5 的高水位线）；
- 首次从同步文件夹恢复的设备没有可信的历史值，只能信任当时读到的最新文件。界面需提示"如果你最近修改过主密码，请确认这里要求的是新密码"。

### 7.3 封装

用 `AUK` 按 §8 封装密钥集，上下文如下：

| AAD 字段 | 值 |
|---|---|
| `kid` | `kid(AUK)` |
| `object_type` | `0x01`（AccountKeyset） |
| `part` | `0x01`（Content） |
| `part_index` | 0 |
| `account_id` | `account_id` |
| `vault_id` | `Z(16)` |
| `object_id` | `account_id` |
| `rev_id` | `Z(16)` |
| `binding` | §7.2 |

## 8. 加密信封（Envelope v1）

### 8.1 格式

```
envelope = version (1) = 0x01
         ‖ alg (1)     = 0x01             // XChaCha20-Poly1305
         ‖ kid (16)                       // 加密所用密钥的 ID
         ‖ nonce (24)                     // 每次加密都随机生成
         ‖ ciphertext                     // 含 16 字节 Poly1305 tag
```

- 头部共 42 字节。
- 信封总长度 = 42 + 填充后长度 + 16。

### 8.2 AAD

AAD 是定长的 132 字节，保证编码唯一：

```
aad = "keevo/v1/aad"          (12)
    ‖ version (1) ‖ alg (1) ‖ kid (16)
    ‖ object_type (1) ‖ part (1) ‖ part_index (4)
    ‖ account_id (16) ‖ vault_id (16) ‖ object_id (16) ‖ rev_id (16)
    ‖ binding (32)
```

- **不适用的字段一律填 0**：例如账户级对象的 `vault_id` 填 `Z(16)`；没有类型专属绑定值时，`binding` 填 `Z(32)`。
- **头部也被认证**：`version`、`alg`、`kid` 同时出现在头部与 AAD 中，头部的任何改动都会导致认证失败。

### 8.3 长度填充

加密前先对明文 `M` 做填充：

```
n          = 4 + len(M)
padded_len = 256                    若 n ≤ 256
           = Padmé(n)               否则
padded     = len(M) (4 字节) ‖ M ‖ Z(padded_len − n)

Padmé(n):  E = ⌊log2 n⌋;  S = ⌊log2 E⌋ + 1;  mask = 2^(E−S) − 1
           返回 (n + mask) & ~mask
```

- `len(M)` 上限为 16 MiB，超过时返回 `too_large`。更大的数据走附件分块加密（§11）。
- **解填充必须严格校验**以下三点，任一不满足都返回 `malformed`：
  - `4 + len(M) ≤ 总长度`
  - 总长度恰好等于 `padded_len(4 + len(M))`
  - 填充字节全为 0

### 8.4 加密

```
seal(key, ctx, M):
  nonce    ← CSPRNG(24)
  header   = 0x01 ‖ 0x01 ‖ key.kid ‖ nonce
  ct       = XChaCha20-Poly1305-Encrypt(key.bytes, nonce, aad(ctx, key.kid), pad(M))
  返回 header ‖ ct
```

### 8.5 解密

```
open(key, ctx, envelope):
  1. 长度 < 42 + 256 + 16，或 > MAX_ENVELOPE_LEN 时，返回 malformed
  2. version ≠ 0x01 时，返回 unsupported_version
  3. alg ≠ 0x01 时，返回 unsupported_algorithm
  4. 头部的 kid ≠ key.kid 时，返回 key_id_mismatch
  5. 解密并认证；失败时返回 decryption_failed
  6. 严格解填充（§8.3）
```

- `MAX_ENVELOPE_LEN = 42 + padded_len(4 + 16 MiB) + 16 = 17301562` 字节，即明文上限对应的最长合法信封。长度检查必须在复制或认证密文**之前**完成，防止未认证的输入触发大块内存分配（评审 2026-11-18 F3）。
- 读取入口也要在读入内存**之前**检查长度（第二轮评审 G4）：
  - **数据库**：按单列检查，信封列不超过 `MAX_ENVELOPE_LEN`，ID 恰好 16 字节，KDF 参数恰好 29 字节，父修订列表不超过上限（`revisions.md` §7.1），元数据值不超过 4096 字节。整个数据库当然可以超过一个信封。
  - **保证条件**：长度检查必须在读入内容之前、并且与读取**在同一个快照中**完成（第三轮评审 H3）。否则另一个连接可以在检查与读取之间换掉内容。参考实现把两条语句放在同一个读事务里；检查语句只在 WHERE 子句中计算 `length()`，不读取 BLOB 内容。
  - **同步文件夹**：按单个文件检查，上限由同步格式定义（M2）。
- 错误信息中不得包含任何密钥或明文内容。
- 上层应把 `key_id_mismatch` 与 `decryption_failed` 视为同一类安全事件：可能是密码错误，也可能是数据被篡改。

### 8.6 本机密钥包裹（不参与同步；单独保持草案，M1.1 定稿）

Keevo 不绑定开发者团队，用不了数据保护钥匙串（ADR-0003）。只存在本机的密钥材料改由 Secure Enclave 密钥包裹后存成文件。这一格式只在本机使用，不进入同步数据，版本与迁移由本机负责。

本节不随共享格式（信封、条目、修订）一起冻结，在 M1.1 实现与验证 Touch ID 时定稿（第三轮评审 §4.3）。

**用途**：

| `purpose` | 材料 | 明文布局 | Secure Enclave 密钥的访问控制 |
|---|---|---|---|
| 0x01 | AUK（Touch ID 解锁） | AUK 原始字节（32）；kid 可由 AUK 重新派生，不存 | `privateKeyUsage` + `biometryCurrentSet` |
| 0x02 | 账户密钥（Secret Key） | 128 位原始值（16），不是显示编码 | `privateKeyUsage` |
| 0x03 | Vault Service 的 Noise 静态私钥 | X25519 私钥（32） | `privateKeyUsage` |
| 0x04 | 设备标记（revisions.md §8） | `device_id`（16） | `privateKeyUsage` |

- 每个用途使用各自的 Secure Enclave P-256 密钥，blob 存在同一目录下；所有 Secure Enclave 密钥的可访问性均为 `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`，锁屏时不可用。
- 明文长度按上表固定，长度不符即视为损坏。包裹文件总长度不超过 1 + 1 + 65 + 12 + 32 + 16 = 127 字节，读入前先检查。

**格式**：

```
wrapped = 0x01 (version) ‖ purpose (1) ‖ eph_pub (65，X9.63 未压缩) ‖ nonce (12) ‖ ciphertext ‖ tag (16)
shared  = ECDH(Secure Enclave 私钥, eph_pub)
key     = HKDF-SHA-256(IKM = shared, salt = account_id, info = "keevo/v1/local-wrap" ‖ purpose, L = 32)
aad     = "keevo/v1/local-wrap" ‖ version ‖ purpose ‖ account_id (16) ‖ device_id (16)
ciphertext ‖ tag = AES-256-GCM(key, nonce, plaintext, aad)
```

- `shared` 是 P-256 ECDH 结果的 x 坐标，32 字节大端定长，保留前导零（CryptoKit `SharedSecret` 的原始表示），不再经过其他派生。
- `eph_pub` 必须是曲线上的有效点，否则视为损坏。
- 每次包裹都生成新的临时密钥与 `nonce`。
- **失败与恢复**：解包失败（blob 无法使用、认证失败、版本或用途不符、长度不符）时停止使用这份材料，不尝试修复。各用途的恢复不同：

  | 用途 | 恢复 |
  |---|---|
  | AUK | 用主密码与账户密钥解锁，再重新包裹 |
  | 账户密钥 | 用户从应急包输入账户密钥 |
  | Noise 静态私钥 | 生成新的服务身份；已配对的扩展需要重新配对，界面说明原因 |
  | 设备标记 | 生成新的 `device_id`（revisions.md §8） |

- **用户取消不是失败**：用户取消 Touch ID 或认证超时时，什么都不改变，下次照常尝试；不能因此判定材料失效、改变身份或覆盖文件。
- **`device_id` 变化时**：其他包裹的 AAD 绑定旧 `device_id`，必须重新包裹。顺序是：解锁后取得全部材料的明文 → 用新 `device_id` 写出全部新包裹（写临时文件、`fsync`、改名替换） → 最后写设备标记。中途失败时旧文件保持原样，下次启动重新执行。

**保护范围**（第二轮评审 §4.2，已实测）：
- **提供**：Secure Enclave 私钥不以原始形式离开芯片；把 blob 与包裹文件复制到另一台 Mac 无法解开，因此不随备份迁移出可用的密钥。
- **不提供**（对不要求用户在场的用途 0x02–0x04）：同用户的其他进程在本机上可以使用这把 Secure Enclave 密钥解包，不会有任何提示。这与 `docs/security.md` A7 的假设一致，对这些材料而言，相比普通文件只多了"不能离机使用"这一项。
- 用途 0x01 需要用户在场，但 blob 不绑定应用身份：同用户进程可以自己发起一次 Touch ID 请求，提示文字可以伪造。

## 9. 枚举

### 9.1 `object_type`

| 值 | 名称 | 用途 |
|---|---|---|
| 0x01 | AccountKeyset | 账户密钥集 |
| 0x02 | Vault | 保险库元数据与保险库密钥 |
| 0x03 | Item | 条目 |
| 0x04 | Attachment | 附件 |
| 0x05 | SyncSegment | 同步日志段（M2） |
| 0x06 | SyncSnapshot | 同步快照（M2） |
| 0x07 | DeviceName | 加密的设备名（M2） |

### 9.2 `part`

| 值 | 名称 | 用途 |
|---|---|---|
| 0x01 | Content | 单一部分的对象，如密钥集、日志段 |
| 0x02 | WrappedKey | 被包裹的子密钥 |
| 0x03 | Overview | 条目概要 |
| 0x04 | Details | 条目详情 |
| 0x05 | Chunk | 附件分块，`part_index` 为块序号 |

**被包裹密钥的明文格式**：`child_kid (16) ‖ child_key (32)`。

## 10. 实现要求

- **密钥类型**：
  - 必须在释放时清零。
  - 不得实现任何可能输出密钥字节的接口，包括格式化输出、序列化、日志。
- **中间值**：`K_p`、`K_s`、填充后的明文缓冲区等，用后立即清零。
- **已知缺口**：Noise 依赖（snow 0.10.0 的默认解析器）内部的 DH 私钥与 ChaCha 密钥是普通数组，释放时没有清零。Keevo 用 `Zeroizing` 包装自己持有的静态私钥，但不能清除传入依赖后产生的副本。计划在 M1.3 改为基于已审计原语、带清零的自定义解析器；在此之前，"密钥释放时清零"不覆盖 IPC 握手与会话密钥。
- **代码边界**：只有 `keevo-crypto` 可以直接依赖密码学原语库，由 CI 检查。
- **nonce**：只能随机生成。测试代码可以注入固定 nonce，但这个能力不得出现在公开 API 中。

## 11. 未决事项

| 事项 | 计划 |
|---|---|
| 附件分块加密（STREAM 构造） | v0.2，M1 期间 |
| Ed25519 公钥派生与签名格式 | v0.3，M2 |
| 同步日志段、快照、设备证书格式 | v0.3，M2，见 `docs/sync.md` |
| 算法升级流程（新 `alg` 取值） | 有需要时再定义 |
| 密钥集 v2：共享用的混合 KEM 密钥对 | M4+ |

## 12. 变更记录

| 版本 | 日期 | 说明 |
|---|---|---|
| 0.1 | 2026-11-17 | 首个草案 |
| 0.2 | 2026-11-18 | 按模型评审修订：新增 §5.3 本机自动执行预算与 `kdf_needs_confirmation`（F3）；§8.5 增加信封长度上限，并要求在复制密文前检查（F3）；§7.2 说明绑定值不提供新鲜度（C2）；§10 记录 Noise 依赖未清零的缺口。字节格式与测试向量不变 |
| 0.3 | 2026-11-18 | 按第二轮模型评审修订：§5.3 的确认绑定到具体参数、KDF 进程级串行、预算待按设备校准；§8.5 的读取入口改为在读入前按单列检查长度（G4）；新增 §8.6 本机密钥包裹格式及其保护范围。字节格式与测试向量不变 |
| 0.4 | 2026-11-18 | 按第三轮模型评审修订：§8.5 写明长度检查须与读取在同一快照（H3）；§8.6 明确单独保持草案，补充各用途的明文布局、ECDH 输出与公钥检查、总长度上限、可访问性、失败与恢复、用户取消、`device_id` 变化时的重新包裹顺序。字节格式与测试向量不变 |
