# Keevo 保险库明文格式

- **版本**：1.2
- **状态**：**已冻结**（2026-11-18，经四轮模型评审）。冻结范围与版本规则见 [README.md](README.md)
- **参考实现**：`crates/keevo-format`
- **独立实现与测试向量**：`spec/reference/format_vectors.py`（Python 标准库，只依据本规范编写）生成 `spec/test-vectors/vault-format-v1.json`
- **相关文档**：[revisions.md](revisions.md)（合并规则）、[crypto.md](crypto.md)（加密封装）

本规范定义修订内容**加密前**的明文结构。所有明文都是 UTF-8 JSON，再按 crypto.md §8 封装为信封。

## 1. 通用约定

| 项 | 约定 |
|---|---|
| ID | 32 个**小写**十六进制字符（16 字节） |
| HLC | 16 个小写十六进制字符（64 位）。用字符串而不是数字，是为了避免 JavaScript 等环境丢失超过 2⁵³ 的精度 |
| 只接受规范编码 | 每个文档必须**恰好是它的规范编码**（见下文），否则返回 `malformed`。因此字段顺序、空白、转义、数字写法都只有一种合法写法；未知字段、可选字段写成 `null`、结构体写成数组等也都被拒绝。格式演进通过提升 `v` 来完成 |
| 版本字段 | 每个文档都带 `"v": 1`；不认识的版本返回 `unsupported_version` |
| 重复键 | JSON 对象中出现重复的键时返回 `malformed`。不同实现对重复键可能保留第一个或最后一个，因此一律拒绝 |
| 整数 | 条目详情与概要中的所有整数（包括概要的 `trashed_at`），范围均为 ±(2⁵³−1)，超出时返回 `value_too_large` |
| 记录值大小 | 单个记录值的规范编码不超过 256 KiB，超出时返回 `value_too_large`；更大的内容用附件 |
| 记录键数 | 每个条目最多 4096 个记录键（`records` 与 `concurrent` 的键取并集），超出时返回 `too_many_keys` |
| 错误信息 | 不得包含任何明文内容，只报告位置 |

### 1.1 规范编码

规范编码同时用于两件事：
- 解码时的接受规则：文档必须恰好是它的规范编码（第四轮评审 J7）；
- 合并时比较同一修订的不同内容（revisions.md §5.1）。比较的对象是单个记录版本的值，墓碑的比较编码是 4 个 ASCII 字节 `null`。

**规则**：

- **对象**：字段按 §1.2 结构表列出的顺序输出。可选字段缺省时**不输出**，不能写成 `null`。
- **映射**：`records` 与 `concurrent` 的键按记录键排序：先按种类（`attr` < `tag` < `section` < `field`），同种类再按名称的 UTF-8 字节序（`attr`、`tag`）或 ID 的字节序（`section`、`field`）。`concurrent` 为空时整个字段不输出。
- **数组**：保持原顺序。
- **空白**：不输出任何空白。
- **字符串**：用 UTF-8 输出，只转义 `"`、`\` 与 U+0000–U+001F：U+0008、U+0009、U+000A、U+000C、U+000D 依次写成 `\b`、`\t`、`\n`、`\f`、`\r`，其余写成 `\u00xx`（小写十六进制）；其他字符一律不转义。
- **整数**：不带前导零的十进制；`0` 不带符号；负数带 `-`。不允许小数点、指数、`+` 号。
- **布尔值**：`true` / `false`。

**错误的先后**：
0. 文档是 JSON 对象，且 `v` 是能用 64 位有符号整数表示的整数、但不是本版本：`unsupported_version`，先于结构检查。新版本的文档可能带有本版本不认识的字段，否则会被误报为 `malformed`。`v` 缺失或不是这样的整数时，按第 1 步处理；
1. 不是合法 JSON，或结构不符合 §1.2（缺少必选字段、类型不对、未知字段、不能用 64 位有符号整数表示的数字）：`malformed`。记录键的**语法**属于结构：种类前缀必须是 `attr`、`tag`、`section`、`field` 之一，`section`、`field` 后面必须是 ID；
2. 不是规范编码：`malformed`；
3. 不满足语义规则：返回对应的错误码，例如整数超出 ±(2⁵³−1) 返回 `value_too_large`，属性名或标签名不合法（§2"名称限制"）返回 `invalid_key`。

同一份文档违反同一步中的多条规则时，返回其中哪一个不作规定；测试向量只用违反一条规则的文档，以及专门检验上述先后的文档。

### 1.2 结构表

字段按表中顺序输出；"可选"表示缺省时不输出。

| 结构 | 字段（按顺序） | 说明 |
|---|---|---|
| 条目详情 | `v`、`type`、`records`、`concurrent`（可选） | §2 |
| 记录版本 | `hlc`、`rev`、`val`（可选，缺省即墓碑） | `val` 不能写成 `null` |
| 记录值 | 恰好一种：`{"text": 字符串}`、`{"bool": 布尔}`、`{"int": 整数}`、`"tag"`、`{"section": 分区}`、`{"field": 字段}` | `"tag"` 只能是这个字符串 |
| 分区 | `label`、`order` | |
| 字段 | `section`（可选）、`order`、`kind`、`label`、`purpose`（可选）、`data` | |
| 字段数据 | 恰好一种：`{"text": 字符串}`、`{"kv": [键值项, …]}`、`{"codes": [恢复码, …]}` | |
| 键值项 | `key`、`value`、`concealed` | |
| 恢复码 | `code`、`used` | |
| 条目概要 | `v`、`type`、`title`、`subtitle`、`urls`、`tags`、`favorite`、`archived`、`trashed_at`（可选）、`updated`、`conflicts`（可选，只在为 `true` 时输出） | §3 |
| 保险库元数据 | `v`、`name`、`updated` | §5 |

## 2. 条目详情（Item details，part = Details）

```json
{
  "v": 1,
  "type": "login",
  "records": {
    "attr:title": { "hlc": "0000018f3a2b0000", "rev": "<id>", "val": { "text": "GitHub" } },
    "attr:favorite": { "hlc": "…", "rev": "<id>", "val": { "bool": true } },
    "attr:trashed": { "hlc": "…", "rev": "<id>", "val": { "int": 1763366400000 } },
    "tag:work": { "hlc": "…", "rev": "<id>", "val": "tag" },
    "section:<id>": { "hlc": "…", "rev": "<id>", "val": { "section": { "label": "服务器", "order": "0000001024" } } },
    "field:<id1>": {
      "hlc": "…",
      "rev": "<id>",
      "val": {
        "field": {
          "section": "<id>",
          "order": "0000000000",
          "kind": "concealed",
          "label": "密码",
          "purpose": "password",
          "data": { "text": "…" }
        }
      }
    },
    "field:<id2>": { "hlc": "…", "rev": "<id>" }
  },
  "concurrent": {
    "attr:title": [
      { "hlc": "…", "rev": "<id>", "val": { "text": "GitHub（工作）" } }
    ]
  }
}
```

- **记录键与合并语义**：见 revisions.md §4。
- **示例只是示意**：省略号与 `<id>` 等占位符都不是合法值，不能用作测试向量。
- **墓碑**：省略 `val` 的记录就是墓碑（上例 `records` 的最后一项）。
- **`concurrent`**：并发版本映射（revisions.md §4.3），没有并发版本时省略。
  - 每个列表非空、按 `rev` 严格升序，不得含与 `records` 中同键版本相同的 `rev`，否则返回 `malformed`。
  - 值的类型规则与 `records` 相同。
  - 只有删除状态键 `attr:trashed`、`attr:purged` 可以只出现在 `concurrent` 中而不在 `records` 中（撤销删除后），其他键返回 `malformed`。
- **键与值的类型必须对应**，否则返回 `value_kind_mismatch`：

| 键 | 允许的 `val` |
|---|---|
| `attr:<name>` | `{"text": …}`、`{"bool": …}`、`{"int": …}` |
| `tag:<name>` | `"tag"` |
| `section:<id>` | `{"section": {…}}` |
| `field:<id>` | `{"field": {…}}` |

- **名称限制**：
  - 属性名只能包含 `[a-z0-9_]`，长度 1–64。
  - 标签名长度 1–256 字节。
- **字段**：
  - `section` 省略表示默认分区。
  - `purpose` 可省略。

### 2.1 已定义的属性

| 名称 | 值 | 含义 |
|---|---|---|
| `title` | text | 标题 |
| `favorite` | bool | 收藏 |
| `archived` | bool | 归档 |
| `trashed` | int | 移入回收站的时间（Unix 毫秒）；不在回收站时为墓碑或不存在 |
| `purged` | bool | **保留**，客户端不得写入或删除，写入接口返回 `reserved_key`。合并时由墓碑修订产生（revisions.md §5.2）。文档中只允许两种形态，其他形态解码时返回 `reserved_key`：`records` 中只能是墓碑（恢复已确定）；`concurrent` 中只能是墓碑，或 `hlc = 0`、值为 `true` 的删除版本（删除被撤销） |

### 2.2 条目类型 `type`

`login`、`email_account`、`secure_note`、`ssh_key`、`api_credential`、`database`、`environment`、`two_factor`。

条目类型创建后不可更改。多个头的类型不一致时，返回 `item_type_mismatch`。

### 2.3 字段类型 `kind` 与数据 `data`

| `kind` | `data` |
|---|---|
| `kv_list` | `{"kv": [{"key": "API_KEY", "value": "…", "concealed": true}, …]}` |
| `recovery_codes` | `{"codes": [{"code": "…", "used": false}, …]}` |
| 其他：`text`、`multiline`、`concealed`、`email`、`url`、`phone`、`date`、`month_year`、`select`、`totp`、`ssh_private_key`、`reference` | `{"text": "…"}` |

- `kind` 与 `data` 的形态不对应时返回 `value_kind_mismatch`，与键和值的类型不对应同属一类。
- **`totp` 的文本**：`otpauth://totp/…` URI（Key Uri Format：`secret` 为 Base32 密钥，可选 `issuer`、`algorithm` = `SHA1`/`SHA256`/`SHA512`、`digits` = 6–8、`period` = 1–3600 秒），或者只是一个 Base32 密钥，此时按 SHA1、6 位、30 秒计算。验证码按 RFC 6238 计算。这是文本内容的约定，不改变解码规则：内容不合法的 `totp` 字段照常解码，只是算不出验证码。

- **附件不在 v1 中**：附件引用与分块格式定稿后，以新的字段类型随条目详情 v2 加入；读取 v2 的实现必须继续读取 v1。v1 中出现其他 `kind` 时返回 `malformed`。

- **默认隐藏的字段类型**：`concealed`、`ssh_private_key`、`recovery_codes`。
- **`purpose` 取值**：`username`、`password`、`otp`、`notes`。

### 2.4 排序键

- **格式**：排序键是 1–64 个字符的字符串，字母表为 `[0-9A-Za-z]`（ASCII），按字节序比较；相同时按字段或分区 ID 排序。不符合时返回 `value_kind_mismatch`。
- **生成算法不属于格式**：参考实现目前使用定宽十进制字符串（如 `"0000001024"`）；M1.1 可以改用分数索引，只要生成的键仍在这个字母表内，并且严格位于相邻两个键之间。已有的十进制键继续有效，不需要迁移。

## 3. 条目概要（Item overview，part = Overview）

```json
{
  "v": 1,
  "type": "login",
  "title": "GitHub",
  "subtitle": "octocat",
  "urls": ["https://github.com/login"],
  "tags": ["work"],
  "favorite": false,
  "archived": false,
  "trashed_at": 1763366400000,
  "updated": "0000018f3a2b0000",
  "conflicts": true
}
```

**概要不参与合并**。每次写入修订时，按以下规则从详情计算：

| 字段 | 计算规则 |
|---|---|
| `subtitle` | 按排序键取第一个 `purpose = username` 的字段；没有时取第一个 `kind = email` 的字段；都没有时为空串 |
| `urls` | 按排序键收集全部 `kind = url` 的字段 |
| `tags` | 全部未删除的标签，按键排序 |
| `trashed_at` | 不在回收站时省略 |
| `updated` | 全部记录（含墓碑）的最大 HLC |
| `conflicts` | 详情中存在待处理的冲突（revisions.md §5.5）时为 `true`，否则省略 |

## 4. 被包裹的条目密钥（part = WrappedKey）

格式见 crypto.md §9.2。**每个修订都会用该修订的 `rev_id` 重新包裹同一把条目密钥**，因为 AAD 中包含 `rev_id`。

## 5. 保险库元数据（Vault，part = Overview）

```json
{ "v": 1, "name": "个人", "updated": "0000018f3a2b0000" }
```

- v1 是单一文档，用保险库密钥加密；各部分的封装上下文见 crypto.md §8.6。
- 保险库密钥由账户对称密钥（ASK）包裹，存于保险库修订的 `wrapped_key_ct`。
- 并发重命名的合并规则留到 M2。届时保险库改用记录映射，那是保险库元数据 v2，不改变本文档 v1 的定义；读取 v2 的实现必须继续读取 v1。

## 6. 未决事项

以下事项不改变本规范 1.0 已冻结的格式；会改变格式的，以新的文档版本（`v`）定义：

| 事项 | 计划 |
|---|---|
| 分数索引的生成算法（不属于格式，见 §2.4） | M1.1 |
| 附件引用与分块：条目详情 v2 | 与附件分块加密一起定义 |
| 条目类型模板（每种类型的默认字段；只是客户端的默认值，不属于格式） | M1.2 |
| 保险库元数据改用记录映射：保险库元数据 v2 | M2 |

## 7. 变更记录

| 版本 | 日期 | 说明 |
|---|---|---|
| 0.1 | 2026-11-17 | 首个草案 |
| 0.2 | 2026-11-18 | 条目详情新增 `concurrent`（并发版本），条目概要新增 `conflicts`。当时尚未冻结，因此 `"v"` 保持为 1 |
| 0.3 | 2026-11-18 | 定义规范编码；拒绝重复键；限定整数范围与单个记录值大小；新增保留属性 `purged`，只有删除状态键可以只有并发版本 |
| 0.4 | 2026-11-18 | 按第三轮模型评审修订：规范编码只用于单个记录版本的值，墓碑编码为 `null`；整数范围同样适用于概要；每个条目最多 4096 个记录键；写明 `purged` 允许的形态（H4、H7） |
| 1.0 | 2026-11-18 | 冻结。按第四轮模型评审：解码只接受规范编码，新增 §1.1 规范编码的完整规则与错误先后、§1.2 结构表（J7）；附件不在 v1 中，`kind` 去掉 `file`；排序键定义字母表与长度，生成算法不属于格式；保险库元数据 v2 与附件以新的文档版本定义，删除"v1 在发布前仍可调整"的说法（J8） |
| 1.1 | 2026-11-18 | 新增测试向量（规范编码、条目详情、概要与保险库元数据的正向与负向解码），由独立的 Python 实现生成。编写独立实现时发现三处未写清的地方，按以下方式澄清：§1.1 错误先后新增第 0 步，版本检查先于结构检查；记录键的语法属于结构（`malformed`），属性名与标签名的规则属于语义（`invalid_key`）；§2.3 写明 `kind` 与 `data` 不对应返回 `value_kind_mismatch`。接受与拒绝的文档集合不变，只是部分被拒绝的文档的错误码由此确定 |
| 1.2 | 2026-11-18 | §2.3 写明 `totp` 字段文本的约定（`otpauth://totp/` URI 或 Base32 密钥），此前未作规定。解码规则不变 |
