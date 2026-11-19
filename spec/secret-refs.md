# 密钥引用（`keevo://`）

- **版本**：0.1（草案，M1.4）
- **用途**：在代码库、配置文件、`.env.keevo` 模板中指向保险库里的一个值，运行时由 `keevo` CLI 解析（`spec/cli.md`）。引用本身不含秘密，可以提交到 git。
- **原则**：名称有歧义时报错，从不猜测（`docs/product.md` §5.5）。

## 1. 语法

```
keevo-ref = "keevo://" vault "/" item [ "/" section ] "/" field [ "?" query ]
query     = param *( "&" param )
param     = ( "attribute=" ( "value" / "otp" ) ) / ( "profile=" segment )
```

- **段**（`vault`、`item`、`section`、`field`、`profile` 的值）：RFC 3986 的 `pchar` 序列，按 UTF-8 做百分号解码。
  - 段内出现的 `/`、`?`、`#`、`%`、`&`、`=` 必须编码（`%2F` 等）；空格可以写成 `%20`，也可以原样出现。
  - 解码后不得为空，不得含控制字符（U+0000–U+001F、U+007F），不得是非法的 UTF-8。
  - 解码后每段最多 256 字节；整个引用最多 2048 字节。
- **形态**：
  - 只有 3 段时为 `vault/item/field`，4 段时为 `vault/item/section/field`；其他段数是 `bad_ref`。
  - scheme 必须是小写的 `keevo`；不允许 `#` 片段。
- **参数**：
  - `attribute=value`（默认）取字段的值；`attribute=otp` 取一次性密码字段的当前验证码。
  - `profile=<名称>` 指定分区，等价于第 4 段；两者同时出现是 `bad_ref`。名称取自环境变量条目的"开发""预发布""生产"等分区，因此 `profile=生产` 与 `/生产/` 相同。
  - 参数名不认识、同一参数出现两次、`attribute` 的值不认识：`bad_ref`。

**示例**：

```
keevo://个人/GitHub/密码
keevo://dev/postgres-local/connection_string
keevo://dev/my-app/生产/DATABASE_URL
keevo://dev/my-app/DATABASE_URL?profile=生产
keevo://个人/GitHub/一次性密码?attribute=otp
keevo://dev/OpenAI%20API/Secret
keevo://4f1c…（32 位十六进制）/9a0b…/Secret
```

## 2. 名称匹配

每一段在一组候选（保险库、条目、分区、字段）中按以下顺序查找，第一步有结果就停止：

1. **ID**：段是 32 位小写十六进制，且等于某个候选的 ID。
2. **完全相同**：段与候选的显示名在 Unicode NFC 规范化之后逐字节相同。
3. **忽略大小写**：两边都转为 Unicode 小写之后相同。

结果为 0 个时返回 `not_found`；多于 1 个时返回 `ambiguous`，并列出候选的 ID，供用户改写为 ID 形式。实现不得按顺序、修改时间或相似度挑选其中一个。

## 3. 解析

1. **保险库**：在全部保险库中按名称匹配。
2. **条目**：在该保险库中**不在回收站**的条目里，按标题匹配。
3. **分区**（给出时）：在条目的分区中按名称匹配。之后的字段只在这个分区中查找。
4. **字段**：同时在下面两类候选中匹配，合计恰好 1 个时取它：
   - 字段：按显示名（在给定的分区中，或者在全部分区中，包括默认分区）；
   - 键值对（`kv_list`）中的一项：按键名。键名是环境变量名，只做完全相同的比较（第 2 步），不忽略大小写。
5. **虚拟字段**：第 4 步没有任何结果时，`database` 条目接受 `connection_string`（也接受"连接串"），由引擎、主机、端口、数据库、用户名、密码、SSL 模式与连接参数生成连接 URI（§4）。

**取值**：

| 目标 | `attribute=value` | `attribute=otp` |
|---|---|---|
| 文本类字段（含 `concealed`、`ssh_private_key`、`totp` 的原文） | 字段文本 | 只有 `totp` 字段可以：当前验证码；其他字段 `unsupported_field` |
| 键值对中的一项 | 值 | `unsupported_field` |
| `recovery_codes` | `unsupported_field` | `unsupported_field` |
| 虚拟字段 `connection_string` | 连接 URI | `unsupported_field` |

值为空时返回空字符串，不是错误。一次性密码配置不合法时返回 `invalid_otp`。

## 4. 连接串

`引擎` 字段（不区分大小写）决定格式；用户名、密码、数据库名按 RFC 3986 百分号编码：

| 引擎 | 格式 |
|---|---|
| `PostgreSQL`、`Postgres` | `postgresql://用户:密码@主机:端口/数据库?sslmode=<SSL 模式>&<连接参数>` |
| `MySQL`、`MariaDB` | `mysql://用户:密码@主机:端口/数据库?ssl-mode=<SSL 模式>&<连接参数>` |
| `MongoDB` | `mongodb://用户:密码@主机:端口/数据库?<连接参数>` |
| `Redis` | `redis://用户:密码@主机:端口/数据库`；SSL 模式不为空且不为 `disable` 时用 `rediss://` |
| 其他 | `unsupported_field` |

- 字段为空时省略对应部分（没有端口就不写 `:端口`，没有用户名就不写 `用户:密码@`，没有数据库就不写 `/数据库`）。主机为空时返回 `unsupported_field`。
- "连接参数"是 `key=value&key=value` 形式的原文，直接追加在查询串末尾。
- 主机是 IPv6 字面量（含 `:`）时加方括号。

## 5. 生成引用

界面中的"复制 `keevo://` 引用"：

- 使用保险库名、条目标题、（需要时）分区名与字段名；某一段按名称不能唯一确定时，改用这一段的 ID。
- 字段名在条目中不唯一、但在所在分区中唯一时，加上分区段。
- 键值对的一项用它的键名作为字段段，并总是带上分区段。

## 6. 错误码

| 错误 | 含义 |
|---|---|
| `bad_ref` | 语法错误 |
| `not_found` | 某一段没有匹配 |
| `ambiguous` | 某一段匹配多于 1 个，附候选 ID |
| `unsupported_field` | 字段类型不支持所请求的取值 |
| `invalid_otp` | 一次性密码配置不合法 |

## 7. 变更记录

| 版本 | 日期 | 说明 |
|---|---|---|
| 0.1 | 2026-11-19 | 首个草案（M1.4） |
