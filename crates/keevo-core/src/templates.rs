//! 条目类型模板（`docs/product.md` §5.3）：新建条目时的默认分区与字段。
//!
//! 模板只是客户端的默认值，不属于格式（`spec/vault-format.md` §6）：用户之后可以任意增删改。

use keevo_format::{FieldData, FieldKind, ItemType, Purpose};

use crate::vault::NewField;

/// 一个模板：分区名称，以及每个字段所在的分区（下标；`None` 为默认分区）。
pub struct Template {
    /// 条目类型。
    pub item_type: ItemType,
    /// 分区名称，按顺序。
    pub sections: Vec<String>,
    /// 字段与其所在的分区，按顺序。
    pub fields: Vec<(Option<usize>, NewField)>,
}

/// 预设：同一类型的不同起点。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    /// 该类型的默认模板。
    Default,
    /// API 凭证中的"API 密钥"：Key ID + Secret。
    ApiKey,
    /// API 凭证中的"访问令牌"：只有一个令牌。
    AccessToken,
}

fn text(kind: FieldKind, label: &str, purpose: Option<Purpose>) -> NewField {
    NewField {
        kind,
        label: label.into(),
        purpose,
        data: FieldData::Text("".into()),
    }
}

fn kv(label: &str) -> NewField {
    NewField {
        kind: FieldKind::KvList,
        label: label.into(),
        purpose: None,
        data: FieldData::Kv(Vec::new()),
    }
}

fn codes(label: &str) -> NewField {
    NewField {
        kind: FieldKind::RecoveryCodes,
        label: label.into(),
        purpose: None,
        data: FieldData::Codes(Vec::new()),
    }
}

/// 某个类型的模板。不适用于该类型的预设按默认模板处理。
#[must_use]
pub fn template(item_type: ItemType, preset: Preset) -> Template {
    use FieldKind as K;
    use Purpose as P;
    let (sections, fields): (Vec<&str>, Vec<(Option<usize>, NewField)>) = match (item_type, preset)
    {
        (ItemType::Login, _) => (
            vec![],
            vec![
                (None, text(K::Text, "用户名", Some(P::Username))),
                (None, text(K::Concealed, "密码", Some(P::Password))),
                (None, text(K::Url, "网站", None)),
                (None, text(K::Totp, "一次性密码", Some(P::Otp))),
                (None, text(K::Multiline, "备注", Some(P::Notes))),
            ],
        ),
        (ItemType::EmailAccount, _) => (
            vec!["服务器", "恢复"],
            vec![
                (None, text(K::Email, "邮箱地址", Some(P::Username))),
                (None, text(K::Concealed, "密码", Some(P::Password))),
                (None, text(K::Text, "提供商", None)),
                (Some(0), text(K::Text, "IMAP 服务器", None)),
                (Some(0), text(K::Text, "IMAP 端口", None)),
                (Some(0), text(K::Text, "SMTP 服务器", None)),
                (Some(0), text(K::Text, "SMTP 端口", None)),
                (Some(0), text(K::Select, "加密方式", None)),
                (Some(1), text(K::Email, "恢复邮箱", None)),
                (Some(1), text(K::Phone, "恢复手机", None)),
                (Some(1), codes("恢复码")),
            ],
        ),
        (ItemType::SecureNote, _) => (
            vec![],
            vec![(None, text(K::Multiline, "正文", Some(P::Notes)))],
        ),
        (ItemType::SshKey, _) => (
            vec!["关联"],
            vec![
                (None, text(K::SshPrivateKey, "私钥", None)),
                (None, text(K::Multiline, "公钥", None)),
                (None, text(K::Text, "指纹", None)),
                (None, text(K::Select, "算法", None)),
                (None, text(K::Text, "注释", None)),
                (None, text(K::Concealed, "口令", Some(P::Password))),
                (Some(0), text(K::Text, "主机", None)),
            ],
        ),
        (ItemType::ApiCredential, Preset::AccessToken) => (
            vec![],
            vec![
                (None, text(K::Text, "提供商", None)),
                (None, text(K::Concealed, "令牌", Some(P::Password))),
                (None, text(K::Text, "作用域", None)),
                (None, text(K::Date, "过期时间", None)),
            ],
        ),
        (ItemType::ApiCredential, _) => (
            vec!["有效期"],
            vec![
                (None, text(K::Text, "提供商", None)),
                (None, text(K::Text, "Key ID", Some(P::Username))),
                (None, text(K::Concealed, "Secret", Some(P::Password))),
                (None, text(K::Select, "凭证种类", None)),
                (None, text(K::Text, "作用域", None)),
                (None, text(K::Url, "端点", None)),
                (None, text(K::Select, "环境", None)),
                (Some(0), text(K::Date, "签发时间", None)),
                (Some(0), text(K::Date, "过期时间", None)),
            ],
        ),
        (ItemType::Database, _) => (
            vec!["SSH 隧道"],
            vec![
                (None, text(K::Select, "引擎", None)),
                (None, text(K::Text, "主机", None)),
                (None, text(K::Text, "端口", None)),
                (None, text(K::Text, "数据库", None)),
                (None, text(K::Text, "用户名", Some(P::Username))),
                (None, text(K::Concealed, "密码", Some(P::Password))),
                (None, text(K::Select, "SSL 模式", None)),
                (None, text(K::Text, "连接参数", None)),
                (Some(0), text(K::Text, "跳板机", None)),
                (Some(0), text(K::Reference, "SSH 密钥", None)),
            ],
        ),
        (ItemType::Environment, _) => (
            vec!["开发", "预发布", "生产"],
            vec![
                (None, text(K::Text, "项目", None)),
                (Some(0), kv("变量")),
                (Some(1), kv("变量")),
                (Some(2), kv("变量")),
            ],
        ),
        (ItemType::TwoFactor, _) => (
            vec![],
            vec![
                (None, text(K::Text, "发行方", None)),
                (None, text(K::Text, "账户名", Some(P::Username))),
                (None, text(K::Totp, "一次性密码", Some(P::Otp))),
                (None, codes("恢复码")),
            ],
        ),
    };
    Template {
        item_type,
        sections: sections.into_iter().map(str::to_owned).collect(),
        fields,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [ItemType; 8] = [
        ItemType::Login,
        ItemType::EmailAccount,
        ItemType::SecureNote,
        ItemType::SshKey,
        ItemType::ApiCredential,
        ItemType::Database,
        ItemType::Environment,
        ItemType::TwoFactor,
    ];

    #[test]
    fn every_type_has_a_consistent_template() {
        for t in ALL {
            let tpl = template(t, Preset::Default);
            assert_eq!(tpl.item_type, t);
            assert!(!tpl.fields.is_empty(), "{t:?}");
            for (section, field) in &tpl.fields {
                assert!(
                    section.is_none_or(|i| i < tpl.sections.len()),
                    "{t:?}：分区下标越界"
                );
                let structured = matches!(field.kind, FieldKind::KvList | FieldKind::RecoveryCodes);
                assert_eq!(
                    structured,
                    !matches!(field.data, FieldData::Text(_)),
                    "{t:?}：{} 的数据形态",
                    field.label
                );
            }
            // 每个分区至少有一个字段
            for i in 0..tpl.sections.len() {
                assert!(
                    tpl.fields.iter().any(|(s, _)| *s == Some(i)),
                    "{t:?}：空分区"
                );
            }
        }
        let token = template(ItemType::ApiCredential, Preset::AccessToken);
        assert!(token.fields.iter().any(|(_, f)| f.label == "令牌"));
        assert_eq!(
            template(ItemType::Login, Preset::AccessToken).fields.len(),
            5,
            "不适用的预设按默认处理"
        );
    }
}
