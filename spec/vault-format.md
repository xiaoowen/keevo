# Keevo 保险库明文格式

- **版本**：0.3（草案）
- **状态**：已按 2026-11-18 两轮模型评审修订
- **参考实现**：`crates/keevo-format`
- **相关文档**：[revisions.md](revisions.md)（合并规则）、[crypto.md](crypto.md)（加密封装）

本规范定义修订内容**加密前**的明文结构。所有明文都是 UTF-8 JSON，再按 crypto.md §8 封装为信封。

## 1. 通用约定

| 项 | 约定 |
|---|---|
| ID | 32 个**小写**十六进制字符（16 字节） |
| HLC | 16 个小写十六进制字符（64 位）。用字符串而不是数字，是为了避免 JavaScript 等环境丢失超过 2⁵³ 的精度 |
| 未知字段 | 一律拒绝（`deny_unknown_fields`）。格式演进通过提升 `v` 来完成 |
| 版本字段 | 每个文档都带 `"v": 1`；不认识的版本返回 `unsupported_version` |
| 重复键 | JSON 对象中出现重复的键时返回 `malformed`。不同实现对重复键可能保留第一个或最后一个，因此一律拒绝 |
| 整数 | 范围为 ±(2⁵³−1)，超出时返回 `value_too_large` |
| 记录值大小 | 单个记录值的规范编码不超过 256 KiB，超出时返回 `value_too_large`；更大的内容用附件 |
| 错误信息 | 不得包含任何明文内容，只报告位置 |

**规范编码**：合并在同一修订出现不同内容时，要比较记录值的字节（revisions.md §5.1）。规范编码是对**解析后的值**重新编码的结果，与收到的原始字节无关：
- 对象的字段按本规范示例中列出的顺序输出；值缺省（如省略的 `purpose`、`section`）的字段不输出；
- 不输出任何空白；
- 字符串用 UTF-8 输出，只转义 `"`、`\` 与 U+0000–U+001F：U+0008、U+0009、U+000A、U+000C、U+000D 依次写成 `\b`、`\t`、`\n`、`\f`、`\r`，其余写成 `\u00xx`（小写十六进制）；
- 整数用不带前导零的十进制；布尔值为 `true` / `false`。

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
    "field:<id>": {
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
    "field:<id>": { "hlc": "…", "rev": "<id>" }
  },
  "concurrent": {
    "attr:title": [
      { "hlc": "…", "rev": "<id>", "val": { "text": "GitHub（工作）" } }
    ]
  }
}
```

- **记录键与合并语义**：见 revisions.md §4。
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
| `purged` | bool | **保留**，客户端不得直接写入。合并时由墓碑修订产生（revisions.md §5.2）；只会以并发版本（删除被撤销）或墓碑（恢复已确定）的形式出现在文档中 |

### 2.2 条目类型 `type`

`login`、`email_account`、`secure_note`、`ssh_key`、`api_credential`、`database`、`environment`、`two_factor`。

条目类型创建后不可更改。多个头的类型不一致时，返回 `item_type_mismatch`。

### 2.3 字段类型 `kind` 与数据 `data`

| `kind` | `data` |
|---|---|
| `kv_list` | `{"kv": [{"key": "API_KEY", "value": "…", "concealed": true}, …]}` |
| `recovery_codes` | `{"codes": [{"code": "…", "used": false}, …]}` |
| 其他：`text`、`multiline`、`concealed`、`email`、`url`、`phone`、`date`、`month_year`、`select`、`totp`、`ssh_private_key`、`reference`、`file` | `{"text": "…"}` |

- **默认隐藏的字段类型**：`concealed`、`ssh_private_key`、`recovery_codes`。
- **`purpose` 取值**：`username`、`password`、`otp`、`notes`。

### 2.4 排序键

v0.1 的参考实现使用定宽十进制字符串（如 `"0000001024"`），按字节序比较；相同时按字段 ID 排序。M1.1 会改为分数索引，届时补充具体算法。按字节序比较这一规则不变。

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

- v0.1 暂为单一文档，用保险库密钥加密。
- 保险库密钥由账户对称密钥（ASK）包裹，存于保险库修订的 `wrapped_key_ct`。
- 并发重命名的合并规则留到 M2；届时保险库也将改用记录映射。

## 6. 未决事项

| 事项 | 计划 |
|---|---|
| 分数索引算法 | M1.1 |
| 附件引用字段（`file`）的数据结构 | 与附件分块加密一起定义（crypto.md v0.2） |
| 条目类型模板（每种类型的默认字段） | M1.2 |
| 保险库元数据改用记录映射 | M2 |
| 本规范的测试向量 | M1.1 |

## 7. 变更记录

| 版本 | 日期 | 说明 |
|---|---|---|
| 0.1 | 2026-11-17 | 首个草案 |
| 0.2 | 2026-11-18 | 条目详情新增 `concurrent`（并发版本），条目概要新增 `conflicts`。v1 在 M1 发布前仍可调整，因此 `"v"` 保持为 1；不含这两个字段的文档照常解析 |
| 0.3 | 2026-11-18 | 定义规范编码；拒绝重复键；限定整数范围与单个记录值大小；新增保留属性 `purged`，只有删除状态键可以只有并发版本 |
