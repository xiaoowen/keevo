//! 命令行工具与 Vault Service 的消息（`spec/cli.md` §3–§4）。CLI 与服务共用这些类型。
//!
//! 帧与浏览器协议的 socket 帧相同（[`crate::frame::read_socket_frame`]），内容是 JSON。

use serde::{Deserialize, Serialize};

/// 协议版本。
pub const CLI_PROTOCOL_VERSION: u32 = 1;
/// CLI 在握手中自报的客户端名。
pub const CLI_CLIENT: &str = "keevo-cli";
/// 一次 `resolve` 最多的引用数。
pub const MAX_REFS: usize = 256;

/// CLI 的首帧。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientHello {
    /// 协议版本。
    pub v: u32,
    /// 固定为 [`CLI_CLIENT`]。
    pub client: String,
    /// CLI 的版本（只用于显示与排错）。
    pub version: String,
}

/// 服务对首帧的回答。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerHello {
    /// 协议版本。
    pub v: u32,
    /// 是否接受。
    pub ok: bool,
    /// Keevo 的版本。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// 不接受的原因。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `create` 中的一个字段。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldArg {
    /// 分区名称（可选）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// 字段名。
    pub label: String,
    /// 值。
    pub value: String,
}

/// `edit` 中的一项修改。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetArg {
    /// 字段名或 ID。
    pub field: String,
    /// 新值。
    pub value: String,
}

/// 请求（§4）。`op` 决定种类，`id` 原样出现在响应中。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// 连接、锁定与授权状态。
    Status {
        /// 请求编号。
        id: u32,
    },
    /// 立即锁定。
    Lock {
        /// 请求编号。
        id: u32,
    },
    /// 解析引用。
    Resolve {
        /// 请求编号。
        id: u32,
        /// `keevo://` 引用。
        refs: Vec<String>,
    },
    /// 列出条目。
    Items {
        /// 请求编号。
        id: u32,
        /// 只列出这个保险库（名称或 ID）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vault: Option<String>,
        /// 搜索词（语法同应用）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        query: Option<String>,
    },
    /// 一个条目的详情。
    Item {
        /// 请求编号。
        id: u32,
        /// `保险库/条目` 或条目 ID。
        item: String,
        /// 是否包含隐藏字段的值。
        #[serde(default)]
        reveal: bool,
    },
    /// 一次性密码。
    Totp {
        /// 请求编号。
        id: u32,
        /// `保险库/条目` 或条目 ID。
        item: String,
    },
    /// 新建条目。
    Create {
        /// 请求编号。
        id: u32,
        /// 保险库（名称或 ID）。
        vault: String,
        /// 条目类型（`login` 等）。
        #[serde(rename = "type")]
        item_type: String,
        /// 标题。
        title: String,
        /// 字段。
        #[serde(default)]
        fields: Vec<FieldArg>,
    },
    /// 修改条目。
    Edit {
        /// 请求编号。
        id: u32,
        /// `保险库/条目` 或条目 ID。
        item: String,
        /// 新标题。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        /// 字段修改。
        #[serde(default)]
        set: Vec<SetArg>,
    },
}

impl Request {
    /// 请求编号。
    #[must_use]
    pub fn id(&self) -> u32 {
        match self {
            Self::Status { id }
            | Self::Lock { id }
            | Self::Resolve { id, .. }
            | Self::Items { id, .. }
            | Self::Item { id, .. }
            | Self::Totp { id, .. }
            | Self::Create { id, .. }
            | Self::Edit { id, .. } => *id,
        }
    }

    /// 是否需要终端会话授权（§4、§5）。
    #[must_use]
    pub fn needs_authorization(&self) -> bool {
        !matches!(self, Self::Status { .. } | Self::Lock { .. })
    }
}

/// 失败的响应，或 `resolve` 中某一项的失败。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    /// 错误码（§6）。
    pub error: String,
    /// 给人看的说明。
    #[serde(default)]
    pub message: String,
}

/// `status` 的结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResult {
    /// 是否已锁定。
    pub locked: bool,
    /// 这个终端会话是否已授权。
    pub authorized: bool,
    /// 授权剩余的秒数。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
}

/// `resolve` 中一个引用的结果：成功时有 `value`，失败时有 `error`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedValue {
    /// 值。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// 错误码。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// 错误说明。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// `resolve` 的结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveResult {
    /// 与请求中的 `refs` 一一对应。
    pub values: Vec<ResolvedValue>,
}

/// 条目列表中的一项。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemSummary {
    /// 条目 ID。
    pub id: String,
    /// 保险库名称。
    pub vault: String,
    /// 标题。
    pub title: String,
    /// 类型。
    #[serde(rename = "type")]
    pub item_type: String,
    /// 副标题。
    pub subtitle: String,
    /// 标签。
    pub tags: Vec<String>,
    /// 是否收藏。
    pub favorite: bool,
}

/// `items` 的结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemsResult {
    /// 条目。
    pub items: Vec<ItemSummary>,
}

/// 条目中的一个字段。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldInfo {
    /// 字段 ID。
    pub id: String,
    /// 分区名称；默认分区省略。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// 字段名。
    pub label: String,
    /// 字段类型。
    pub kind: String,
    /// 是否为隐藏字段。
    pub concealed: bool,
    /// 值。隐藏字段只在 `reveal` 时出现；键值对与恢复码按行展开为文本。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// `item` 的结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemResult {
    /// 条目 ID。
    pub id: String,
    /// 保险库名称。
    pub vault: String,
    /// 标题。
    pub title: String,
    /// 类型。
    #[serde(rename = "type")]
    pub item_type: String,
    /// 标签。
    pub tags: Vec<String>,
    /// 字段。
    pub fields: Vec<FieldInfo>,
}

/// `totp` 的结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpResult {
    /// 验证码。
    pub code: String,
    /// 剩余秒数。
    pub remaining: u32,
}

/// `create` 的结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateResult {
    /// 新条目的 ID。
    pub id: String,
}

/// 把成功的结果编码为响应：`{"id": …, "ok": true, "result": …}`（§3）。
///
/// # Errors
/// 结果无法序列化时返回错误。
pub fn encode_ok<T: Serialize>(id: u32, result: &T) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "id": id,
        "ok": true,
        "result": serde_json::to_value(result)?,
    }))
}

/// 把失败编码为响应：`{"id": …, "ok": false, "error": …, "message": …}`。
///
/// # Errors
/// 不会失败（字段都是字符串）。
pub fn encode_err(id: u32, error: &str, message: &str) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "id": id,
        "ok": false,
        "error": error,
        "message": message,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    id: u32,
    ok: bool,
    #[serde(default)]
    result: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

/// 解码响应：成功时按 `T` 解析 `result`，失败时返回 [`ErrorBody`]。
///
/// # Errors
/// JSON 不合法、`id` 不符或结构不对时返回 `Err(…)`。
pub fn decode_response<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    expected_id: u32,
) -> Result<Result<T, ErrorBody>, serde_json::Error> {
    use serde::de::Error as _;
    let env: Envelope = serde_json::from_slice(bytes)?;
    if env.id != expected_id {
        return Err(serde_json::Error::custom("response id mismatch"));
    }
    if env.ok {
        Ok(Ok(serde_json::from_value(
            env.result.unwrap_or(serde_json::Value::Null),
        )?))
    } else {
        Ok(Err(ErrorBody {
            error: env.error.unwrap_or_else(|| "failed".into()),
            message: env.message.unwrap_or_default(),
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_and_reject_unknown_fields() {
        let req = Request::Resolve {
            id: 7,
            refs: vec!["keevo://a/b/c".into()],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"op":"resolve","id":7,"refs":["keevo://a/b/c"]}"#);
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), req);
        assert!(serde_json::from_str::<Request>(r#"{"op":"status","id":1,"x":1}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"op":"nope","id":1}"#).is_err());
        assert!(!Request::Status { id: 1 }.needs_authorization());
        assert!(req.needs_authorization());
    }

    #[test]
    fn responses_round_trip() {
        let bytes = encode_ok(
            3,
            &TotpResult {
                code: "123456".into(),
                remaining: 12,
            },
        )
        .unwrap();
        let r: TotpResult = decode_response(&bytes, 3).unwrap().unwrap();
        assert_eq!(r.code, "123456");
        assert!(decode_response::<TotpResult>(&bytes, 4).is_err());
        let bytes = encode_err(5, "denied", "拒绝").unwrap();
        let e = decode_response::<TotpResult>(&bytes, 5)
            .unwrap()
            .unwrap_err();
        assert_eq!(e.error, "denied");
        let bytes = encode_ok(6, &()).unwrap();
        decode_response::<serde_json::Value>(&bytes, 6)
            .unwrap()
            .unwrap();
    }
}
