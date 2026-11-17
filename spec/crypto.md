# Keevo 加密规范

- **版本**：0.1（草案）
- **状态**：待外部评审。评审通过前，格式可能有不兼容的变更。
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
- **为什么要有上限**：KDF 参数以明文存放在同步文件中，上限可以防止被篡改的参数让设备耗尽内存。
- **参数校准**：客户端可以按设备性能上调默认值，但永远不得低于下限。
- **防降级**：KDF 参数纳入密钥集的 AAD（§7.3）。任何篡改都会导致解密失败。

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
  1. 长度 < 42 + 256 + 16 时，返回 malformed
  2. version ≠ 0x01 时，返回 unsupported_version
  3. alg ≠ 0x01 时，返回 unsupported_algorithm
  4. 头部的 kid ≠ key.kid 时，返回 key_id_mismatch
  5. 解密并认证；失败时返回 decryption_failed
  6. 严格解填充（§8.3）
```

- 错误信息中不得包含任何密钥或明文内容。
- 上层应把 `key_id_mismatch` 与 `decryption_failed` 视为同一类安全事件：可能是密码错误，也可能是数据被篡改。

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
