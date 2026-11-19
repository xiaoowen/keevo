//! 1Password 的 1PUX：一个 zip，`export.data` 为 JSON：`accounts[].vaults[].items[]`，每个条目有
//! `categoryUuid`、`overview`（标题、网址、标签）与 `details`（`loginFields`、`sections`、`notesPlain`）。
//! `files/` 中是附件（暂不导入，在备注中说明）。
//!
//! 类别：001 登录、005 密码 → 登录；003 安全笔记；111 电子邮件账户；112 API 凭证；102 数据库；
//! 114 SSH 密钥；其余（银行卡、身份、护照等）作为安全笔记导入，字段逐个保留。
//! 1Password 的保险库名作为标签（"1Password · 保险库名"），归档的条目加标签"已归档"。

use keevo_format::{FieldKind, ItemType, Purpose};
use serde_json::Value;

use super::{Builder, ImportError, Parsed, zip};

/// `export.data` 解压后的上限。
const MAX_DATA: usize = 256 * 1024 * 1024;

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn array<'a>(v: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    v.get(key).and_then(Value::as_array).into_iter().flatten()
}

pub(super) fn parse(data: &[u8]) -> Result<Parsed, ImportError> {
    let json = zip::read(data, "export.data", MAX_DATA)?.ok_or(ImportError::NotRecognized)?;
    let doc: Value = serde_json::from_slice(&json).map_err(|_| ImportError::Malformed)?;
    drop(json);
    let accounts = doc
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or(ImportError::NotRecognized)?;
    let mut out = Parsed::default();
    for account in accounts {
        for vault in array(account, "vaults") {
            let vault_name = str_of(vault.get("attrs").unwrap_or(&Value::Null), "name");
            for item in array(vault, "items") {
                if str_of(item, "state") == "deleted" {
                    continue;
                }
                let mut b = item_builder(item);
                if !vault_name.is_empty() {
                    b.tag(&format!("1Password · {vault_name}"));
                }
                if str_of(item, "state") == "archived" {
                    b.tag("已归档");
                }
                out.items.push(b.finish());
            }
        }
    }
    Ok(out)
}

/// (类型, 原类别)。
fn category(uuid: &str) -> (ItemType, Option<&'static str>) {
    match uuid {
        "001" | "005" => (ItemType::Login, None),
        "003" => (ItemType::SecureNote, None),
        "111" => (ItemType::EmailAccount, None),
        "112" => (ItemType::ApiCredential, None),
        "102" => (ItemType::Database, None),
        "114" => (ItemType::SshKey, None),
        "002" => (ItemType::SecureNote, Some("credit_card")),
        "004" => (ItemType::SecureNote, Some("identity")),
        "006" => (ItemType::SecureNote, Some("document")),
        "100" => (ItemType::SecureNote, Some("software_license")),
        "101" => (ItemType::SecureNote, Some("bank_account")),
        "103" => (ItemType::SecureNote, Some("driver_license")),
        "105" => (ItemType::SecureNote, Some("membership")),
        "106" => (ItemType::SecureNote, Some("passport")),
        "109" => (ItemType::SecureNote, Some("wireless_router")),
        "110" => (ItemType::SecureNote, Some("server")),
        "115" => (ItemType::SecureNote, Some("crypto_wallet")),
        _ => (ItemType::SecureNote, Some("other")),
    }
}

/// 特定类别中，1Password 字段 ID 对应的 Keevo 模板字段：(名称, 类型, 用途)。
fn known_field(
    item_type: ItemType,
    id: &str,
) -> Option<(&'static str, FieldKind, Option<Purpose>)> {
    use FieldKind as K;
    use Purpose as P;
    Some(match (item_type, id) {
        (ItemType::Database, "database_type") => ("引擎", K::Select, None),
        (ItemType::Database, "hostname") => ("主机", K::Text, None),
        (ItemType::Database, "port") => ("端口", K::Text, None),
        (ItemType::Database, "database") => ("数据库", K::Text, None),
        (ItemType::Database, "username") => ("用户名", K::Text, Some(P::Username)),
        (ItemType::Database, "password") => ("密码", K::Concealed, Some(P::Password)),
        (ItemType::Database, "options") => ("连接参数", K::Text, None),
        (ItemType::ApiCredential, "username") => ("Key ID", K::Text, Some(P::Username)),
        (ItemType::ApiCredential, "credential") => ("Secret", K::Concealed, Some(P::Password)),
        (ItemType::ApiCredential, "type") => ("凭证种类", K::Select, None),
        (ItemType::ApiCredential, "hostname") => ("端点", K::Url, None),
        (ItemType::ApiCredential, "validFrom") => ("签发时间", K::Date, None),
        (ItemType::ApiCredential, "expires") => ("过期时间", K::Date, None),
        (ItemType::EmailAccount, "pop_username") => ("邮箱地址", K::Email, Some(P::Username)),
        (ItemType::EmailAccount, "pop_password") => ("密码", K::Concealed, Some(P::Password)),
        (ItemType::EmailAccount, "pop_server") => ("IMAP 服务器", K::Text, None),
        (ItemType::EmailAccount, "pop_port") => ("IMAP 端口", K::Text, None),
        (ItemType::EmailAccount, "smtp_server") => ("SMTP 服务器", K::Text, None),
        (ItemType::EmailAccount, "smtp_port") => ("SMTP 端口", K::Text, None),
        (ItemType::EmailAccount, "provider") => ("提供商", K::Text, None),
        _ => return None,
    })
}

fn item_builder(item: &Value) -> Builder {
    let overview = item.get("overview").unwrap_or(&Value::Null);
    let details = item.get("details").unwrap_or(&Value::Null);
    let (item_type, original) = category(str_of(item, "categoryUuid"));
    let mut b = Builder::new(item_type, str_of(overview, "title"));
    if let Some(code) = original {
        b = b.original(code);
    }
    // 登录字段：用户名与密码
    for f in array(details, "loginFields") {
        let value = str_of(f, "value");
        match (str_of(f, "designation"), str_of(f, "fieldType")) {
            ("username", _) => b.add(
                None,
                FieldKind::Text,
                "用户名",
                Some(Purpose::Username),
                value,
            ),
            ("password", _) => b.add(
                None,
                FieldKind::Concealed,
                "密码",
                Some(Purpose::Password),
                value,
            ),
            (_, "P") => b.add(None, FieldKind::Concealed, str_of(f, "name"), None, value),
            // 其余的登录表单字段（复选框、记住我等）没有意义，跳过
            (_, "T" | "E" | "U") if !value.is_empty() => {
                b.add(None, FieldKind::Text, str_of(f, "name"), None, value);
            }
            _ => {}
        }
    }
    // "密码"类别的密码在 details.password
    b.add(
        None,
        FieldKind::Concealed,
        "密码",
        Some(Purpose::Password),
        str_of(details, "password"),
    );
    // 网址：overview.urls 中有全部网址，旧版本只有 overview.url
    let mut urls: Vec<&str> = array(overview, "urls").map(|u| str_of(u, "url")).collect();
    if urls.is_empty() {
        urls.push(str_of(overview, "url"));
    }
    for url in urls {
        b.add(None, FieldKind::Url, "网站", None, url);
    }
    for section in array(details, "sections") {
        let title = str_of(section, "title");
        for f in array(section, "fields") {
            field(&mut b, item_type, title, f);
        }
    }
    b.note(str_of(details, "notesPlain"));
    for tag in array(overview, "tags").filter_map(Value::as_str) {
        b.tag(tag);
    }
    b.favorite(
        item.get("favIndex")
            .and_then(Value::as_u64)
            .is_some_and(|n| n > 0),
    );
    if details.get("documentAttributes").is_some() {
        b.attachments(1);
    }
    b
}

fn field(b: &mut Builder, item_type: ItemType, section_title: &str, f: &Value) {
    let label = str_of(f, "title");
    let id = str_of(f, "id");
    let Some(value) = f.get("value").and_then(Value::as_object) else {
        return;
    };
    let Some((vtype, v)) = value.iter().next() else {
        return;
    };
    if let Some((name, kind, purpose)) = known_field(item_type, id) {
        b.add(None, kind, name, purpose, &plain(kind, v));
        return;
    }
    let section = b.section(section_title);
    match vtype.as_str() {
        "totp" => b.add_totp(section, label, v.as_str().unwrap_or_default()),
        "sshKey" => {
            b.add(
                None,
                FieldKind::SshPrivateKey,
                "私钥",
                None,
                str_of(v, "privateKey"),
            );
            let meta = v.get("metadata").unwrap_or(&Value::Null);
            b.add(
                None,
                FieldKind::Multiline,
                "公钥",
                None,
                str_of(meta, "publicKey"),
            );
            b.add(
                None,
                FieldKind::Text,
                "指纹",
                None,
                str_of(meta, "fingerprint"),
            );
        }
        "file" => b.attachments(1),
        "reference" => {}
        other => {
            let k = kind_of(other);
            b.add(section, k, label, None, &plain(k, v));
        }
    }
}

fn kind_of(kind: &str) -> FieldKind {
    match kind {
        "concealed" | "creditCardNumber" => FieldKind::Concealed,
        "email" => FieldKind::Email,
        "url" => FieldKind::Url,
        "phone" => FieldKind::Phone,
        "date" => FieldKind::Date,
        "monthYear" => FieldKind::MonthYear,
        "address" => FieldKind::Multiline,
        "menu" | "creditCardType" | "gender" => FieldKind::Select,
        _ => FieldKind::Text,
    }
}

/// 字段值的文本形式。日期为 Unix 秒，年月为 YYYYMM，地址为对象，电子邮件可能是对象。
fn plain(kind: FieldKind, v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => match kind {
            FieldKind::Date => n.as_i64().map_or_else(String::new, date),
            FieldKind::MonthYear => n
                .as_u64()
                .map_or_else(String::new, |ym| format!("{:04}-{:02}", ym / 100, ym % 100)),
            _ => n.to_string(),
        },
        Value::Bool(on) => if *on { "是" } else { "否" }.to_owned(),
        Value::Object(o) => {
            if let Some(email) = o.get("email_address").and_then(Value::as_str) {
                return email.to_owned();
            }
            ["street", "city", "state", "zip", "country"]
                .iter()
                .filter_map(|k| o.get(*k).and_then(Value::as_str))
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("\n")
        }
        _ => String::new(),
    }
}

/// Unix 秒 → `YYYY-MM-DD`（UTC）。
fn date(secs: i64) -> String {
    if !(-62_135_596_800..=253_402_300_799).contains(&secs) {
        return String::new();
    }
    super::date_from_days(secs.div_euclid(86_400))
}
