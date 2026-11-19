//! 协议 v2 的写操作（`spec/ipc.md` §5.5）：在持有保险库锁的情况下执行状态机交来的 [`WriteRequest`]。

use keevo_core::{
    Edit, FieldData, FieldKind, ItemType, NewField, Purpose, RecordKey, RecordValue, Vault,
};
use keevo_ipc::message::ErrorCode;
use keevo_ipc::service::{VaultBackend, WriteOp, WriteRequest};

use crate::backend::{CoreBackend, parse_id};

/// 执行写操作，返回条目 ID（十六进制）。保存的条目放在第一个保险库中，网址只保存规范化后的站点。
/// 更新前重新核对条目仍与站点匹配（等待用户确认期间条目可能已被修改）；新密码与原来相同时不写入。
pub(crate) fn apply(vault: &mut Vault, request: &WriteRequest) -> Result<String, ErrorCode> {
    if !vault.is_unlocked() {
        return Err(ErrorCode::Locked);
    }
    match &request.op {
        WriteOp::Save {
            title,
            username,
            password,
        } => {
            let vault_id = vault
                .vaults()
                .ok()
                .and_then(|v| v.first().map(|v| v.id))
                .ok_or(ErrorCode::NotFound)?;
            let field = |kind, label: &str, purpose, value: &str| NewField {
                kind,
                label: label.into(),
                purpose,
                data: FieldData::Text(value.into()),
            };
            let fields = vec![
                field(FieldKind::Text, "用户名", Some(Purpose::Username), username),
                field(
                    FieldKind::Concealed,
                    "密码",
                    Some(Purpose::Password),
                    password.expose(),
                ),
                field(FieldKind::Url, "网站", None, &request.site),
            ];
            vault
                .create_item(vault_id, ItemType::Login, title, fields)
                .map(|id| id.to_hex())
                .map_err(|_| ErrorCode::NotFound)
        }
        WriteOp::Update {
            item_id, password, ..
        } => {
            if CoreBackend::new(vault).item_matches(item_id, &request.site) != Some(true) {
                return Err(ErrorCode::UrlMismatch);
            }
            let id = parse_id(item_id).ok_or(ErrorCode::NotFound)?;
            let view = vault.item(id).map_err(|_| ErrorCode::NotFound)?;
            let current = view
                .doc
                .records
                .iter()
                .find_map(|(k, v)| match (k, &v.value) {
                    (RecordKey::Field(field_id), Some(RecordValue::Field(f)))
                        if f.purpose == Some(Purpose::Password) =>
                    {
                        Some((*field_id, f.text() == Some(password.expose())))
                    }
                    _ => None,
                });
            let edit = match current {
                Some((_, true)) => return Ok(item_id.clone()),
                Some((field_id, false)) => Edit::SetFieldData {
                    field_id,
                    data: FieldData::Text(password.expose().into()),
                },
                // 条目还没有密码字段：新增一个
                None => Edit::AddField(NewField {
                    kind: FieldKind::Concealed,
                    label: "密码".into(),
                    purpose: Some(Purpose::Password),
                    data: FieldData::Text(password.expose().into()),
                }),
            };
            vault
                .update_item(id, vec![edit])
                .map(|()| item_id.clone())
                .map_err(|_| ErrorCode::NotFound)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use keevo_core::{KdfParams, Store};
    use keevo_ipc::message::SecretText;

    use super::*;

    fn vault() -> Vault {
        let params = KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [5; 16]).unwrap();
        Vault::create_with_store(Store::open_in_memory().unwrap(), "pw", params)
            .unwrap()
            .0
    }

    fn request(op: WriteOp) -> WriteRequest {
        WriteRequest {
            extension_public: [1; 32],
            pairing_name: "Chrome".into(),
            browser: "com.google.Chrome".into(),
            site: "https://github.com".into(),
            op,
        }
    }

    fn password_of(vault: &Vault, id: &str) -> String {
        CoreBackend::new(vault)
            .fill(id)
            .map(|d| d.password.clone())
            .unwrap()
    }

    /// v3 search：标题开头匹配的排在前面，也按用户名与网站主机名匹配；只返回概要。
    #[test]
    fn search_ranks_title_prefix_first() {
        let mut v = vault();
        let save = |v: &mut Vault, site: &str, title: &str, user: &str| {
            apply(
                v,
                &WriteRequest {
                    site: site.into(),
                    ..request(WriteOp::Save {
                        title: title.into(),
                        username: user.into(),
                        password: SecretText::new("pw"),
                    })
                },
            )
            .unwrap()
        };
        save(&mut v, "https://github.com", "github.com", "octocat");
        save(&mut v, "https://gitlab.com", "GitLab", "me@example.com");
        save(&mut v, "https://code.example", "My Git server", "dev");
        save(&mut v, "https://news.example", "news.example", "reader");
        let backend = CoreBackend::new(&v);
        let titles = |q: &str| {
            backend
                .search(q)
                .into_iter()
                .map(|c| c.title)
                .collect::<Vec<_>>()
        };
        assert_eq!(titles("git"), ["github.com", "GitLab", "My Git server"]);
        assert_eq!(titles("READER"), ["news.example"]);
        assert_eq!(
            titles("code.example"),
            ["My Git server"],
            "按网站主机名匹配"
        );
        assert!(titles("nothing").is_empty());
        assert!(!backend.touch_id(), "新保险库没有启用 Touch ID");
    }

    #[test]
    fn save_then_update_keeps_history() {
        let mut v = vault();
        let id = apply(
            &mut v,
            &request(WriteOp::Save {
                title: "github.com".into(),
                username: "octocat".into(),
                password: SecretText::new("first"),
            }),
        )
        .unwrap();
        let backend = CoreBackend::new(&v);
        assert_eq!(
            backend.item_matches(&id, "https://github.com/login"),
            Some(true)
        );
        assert_eq!(
            backend.describe(&id),
            Some(("github.com".into(), "octocat".into()))
        );
        assert_eq!(password_of(&v, &id), "first");
        let revisions = v.revision_count(parse_id(&id).unwrap()).unwrap();

        let update = |pw: &str| {
            request(WriteOp::Update {
                item_id: id.clone(),
                title: String::new(),
                username: String::new(),
                password: SecretText::new(pw),
            })
        };
        assert_eq!(apply(&mut v, &update("second")).unwrap(), id);
        assert_eq!(password_of(&v, &id), "second");
        let after = v.revision_count(parse_id(&id).unwrap()).unwrap();
        assert_eq!(after, revisions + 1, "旧密码留在修订历史中");
        apply(&mut v, &update("second")).unwrap();
        assert_eq!(
            v.revision_count(parse_id(&id).unwrap()).unwrap(),
            after,
            "密码相同时不写入"
        );

        // 网址不匹配、条目不存在、锁定
        let mut wrong = update("x");
        wrong.site = "https://evil.example".into();
        assert_eq!(apply(&mut v, &wrong), Err(ErrorCode::UrlMismatch));
        let missing = request(WriteOp::Update {
            item_id: "00".repeat(16),
            title: String::new(),
            username: String::new(),
            password: SecretText::new("x"),
        });
        assert_eq!(apply(&mut v, &missing), Err(ErrorCode::UrlMismatch));
        v.lock();
        assert_eq!(apply(&mut v, &update("x")), Err(ErrorCode::Locked));
    }
}
