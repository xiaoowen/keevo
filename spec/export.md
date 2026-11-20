# Keevo 导出文件

- **版本**：0.2
- **状态**：草案（M1.5）。评审后与其他格式一起冻结。
- **参考实现**：
  - `crates/keevo-crypto` 的 `export` 模块（加密文件的封装与打开）
  - `crates/keevo-core` 的 `export` 模块（写出）与 `import::keevo`（读入）
- **相关**：[crypto.md](crypto.md) §5（KDF 参数）、§6（口令的 NFKD 规范化）；[vault-format.md](vault-format.md)（字段类型与用途的取值）

导出文件用于把条目带到另一台 Mac、另一个 Keevo 账户，或其他密码管理器。它不是备份：备份是数据库的副本，
与保险库同等加密（[docs/sync.md](../docs/sync.md) §2）；导出文件只有条目的**当前内容**，没有历史版本、
并发版本、删除记录与本机状态（浏览器配对、SSH Agent 的授权与策略）。

## 1. 三种格式

| 格式 | 扩展名 | 内容 | 保护 |
|---|---|---|---|
| Keevo 加密文件（推荐） | `.keevo-export` | §2 的 JSON，按 §3 加密 | 导出密码（§3"导出密码"，与主密码无关） |
| JSON（明文） | `.json` | §2 的 JSON | 无 |
| CSV（明文） | `.csv` | 只有登录：`name,url,username,password,note,totp` | 无 |

明文导出前，Keevo 重新验证用户（Touch ID 或主密码），并提示明文文件的风险（设计稿"导出明文：重新验证"）。
不导出最近删除中的条目。

**不导出的内容**：附件（§2）；归档状态（`archived`）；条目的安全提醒设置（`security_alerts`）；SSH Agent 的策略
（本机记录，`ssh-agent.md` §4.1）；历史版本、并发版本与删除记录。归档的条目照常导出，导入后不再是归档状态。

## 2. JSON

UTF-8，一个对象：

```json
{
  "format": "keevo-export",
  "version": 1,
  "exported_at": "2026-11-19T14:32:00Z",
  "vaults": [
    {
      "name": "个人",
      "items": [
        {
          "type": "login",
          "title": "GitHub",
          "favorite": true,
          "tags": ["工作"],
          "sections": ["安全"],
          "fields": [
            { "kind": "text", "label": "用户名", "purpose": "username", "value": "octocat" },
            { "kind": "concealed", "label": "密码", "purpose": "password", "value": "…" },
            { "kind": "url", "label": "网站", "value": "https://github.com" },
            { "section": 0, "kind": "recovery_codes", "label": "恢复码", "codes": [{ "code": "…", "used": false }] }
          ]
        }
      ]
    }
  ]
}
```

| 键 | 说明 |
|---|---|
| `format` | 固定为 `keevo-export` |
| `version` | 本格式的版本，当前为 `1`。读取方遇到不认识的版本时拒绝 |
| `exported_at` | 导出时间，UTC，RFC 3339，只供显示 |
| `vaults[].name` | 保险库名称 |
| `items[].type` | 条目类型，取值同 vault-format（`login`、`email_account`、`secure_note`、`ssh_key`、`api_credential`、`database`、`environment`、`two_factor`） |
| `items[].title` | 标题 |
| `items[].favorite` | 收藏；为 `false` 时省略 |
| `items[].tags` | 标签；为空时省略 |
| `items[].sections` | 分区名称，按显示顺序；为空时省略 |
| `fields[]` | 字段，按显示顺序：先默认分区，再按分区顺序 |
| `fields[].section` | 所在分区在 `sections` 中的下标；默认分区省略 |
| `fields[].kind`、`label`、`purpose` | 取值同 vault-format；`purpose` 为空时省略 |
| `fields[].value` | 文本字段的值 |
| `fields[].entries` | `kv_list` 字段：`[{ "key", "value", "concealed" }]` |
| `fields[].codes` | `recovery_codes` 字段：`[{ "code", "used" }]` |

`value`、`entries`、`codes` 恰好出现一个，并与 `kind` 一致：`kv_list` 用 `entries`，`recovery_codes` 用 `codes`，
其余文本类型用 `value`。读取方：
- 三者都没有的字段：忽略；
- 出现多个、或与 `kind` 不一致（包括 `kind` 为 `attachment`）的字段：不导入这个字段，在条目备注中说明个数，其余照常导入；
- **不认识的成员**：忽略。本格式用于交换，`version` 不变的修改只会增加读取方可以忽略的成员；影响含义的修改提升 `version`。
- **值原样导入**：秘密字段（`concealed`、多行文本、SSH 私钥）的首尾空白是值的一部分，不去掉；其余字段去掉首尾空白。

**上限**（读取方，`crates/keevo-core` 的 `import` 模块）：文件 512 MiB；JSON 至多 400 万个节点（解析之前计数，
不为恶意文件建立巨大的解析树）；50,000 个条目，超过即停止；每个条目 1000 个字段、200 个分区、100 个标签，超出的部分
不导入，在条目备注中说明。

**附件不导出**：导出文件只有文本内容。附件字段不出现在 JSON 中，需要时请在 Keevo 中逐个保存附件。

导入时，字段与分区按文件中的顺序重新编号（新的 ID 与排序键）；文件中有多个保险库时，每个条目加上标签
`Keevo · <保险库名>`，以便区分。

## 3. 加密文件

```
magic "KEEVOEXP"（8 字节）
version 0x01（1 字节）
KdfParams（29 字节，crypto §5.1 的编码）
nonce（24 字节，随机）
密文 || 认证标签（16 字节）
```

- `k = Argon2id(NFKD(导出密码), KdfParams)`，32 字节；口令的规范化与长度限制同 crypto §6。
- `key = HKDF-SHA256(ikm = k, salt = 空, info = "keevo/v1/export")`，32 字节。
- 算法为 XChaCha20-Poly1305；AAD 为密文之前的全部 62 字节（magic、version、KdfParams、nonce）。
- 明文为 §2 的 JSON，最长 256 MiB。
- 写出时使用新的随机 salt 与 crypto §5.2 的**默认** KDF 参数，不得上调：读取方会拒绝超出自己预算的文件（下一条），
  写出方上调参数，文件就可能在另一台设备上打不开。
- 读取时，KDF 参数超出本机自动执行预算（crypto §5.3）的文件直接拒绝，不询问：导出文件来自外部，
  不应让它决定消耗多少内存。认证失败时不区分"密码错误"与"文件被改动"。

**导出密码**：文件只受这个密码保护，没有账户密钥这一层，离线猜测的代价只有一次 Argon2id。因此要求：
- 至少 10 个字符（Unicode 标量）；
- 不全是空白；
- 强度评估（zxcvbn 的算法，`crates/keevo-core` 的 `strength` 模块）达到最高档"很强"（4 分，估计的猜测次数不少于 10¹⁰）。

界面实时显示强度，达到要求之前不能导出（第五轮预审 K4）。读入时不检查导出密码的强度。

## 4. CSV

第一行为表头 `name,url,username,password,note,totp`，之后每个登录一行（RFC 4180：含逗号、引号、换行或首尾
空格的字段用双引号括起，引号写作 `""`）。取每个登录的第一个网址、用途为用户名 / 密码 / 备注的第一个字段，
以及第一个一次性密码字段（`otpauth://` URI 或 Base32 密钥）。其他类型的条目与其余字段不导出。

**公式注入**（CWE-1236）：以 `=`、`+`、`-`、`@` 开头的值原样写出。在电子表格中打开时，这样的值可能被当作公式，
例如把同一行的密码拼进一个链接（第五轮预审 K18）。转义（例如在前面加 `'`）会改变值，导入其他密码管理器后密码就不对了，
因此不转义。CSV 只用于导入其他密码管理器：导出前的风险提示中说明"不要用电子表格打开"（设计稿"预审修复"）。

## 5. 更新记录

| 版本 | 日期 | 内容 |
|---|---|---|
| 0.1 | 2026-11-19 | 初稿：JSON v1、加密文件 v1、CSV |
| 0.2 | 2026-11-20 | 按第五轮预审：导出密码要求"很强"、不全是空白（K4）；写明不导出的内容、字段数据与 `kind` 不一致和出现多个时的处理、不认识的成员、值原样导入与读取方的上限（K8、K10、K20）；写出方只用默认 KDF 参数（K20）；CSV 的公式注入与取舍（K18）。未决：独立实现生成的导出测试向量 |
