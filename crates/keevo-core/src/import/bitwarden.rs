//! Bitwarden 的 JSON 导出（含有密码保护的导出）。
//!
//! - 明文：`{"encrypted": false, "folders": [...], "items": [...]}`；组织导出用 `collections` 代替 `folders`。
//! - 有密码保护：`{"encrypted": true, "passwordProtected": true, "salt", "kdfType", "kdfIterations",
//!   "kdfMemory", "kdfParallelism", "encKeyValidation_DO_NOT_EDIT", "data"}`，`data` 解密后是明文导出
//!   （解密见 `keevo_crypto::BitwardenKey`）。
//! - "账户限制"的加密导出（没有 `passwordProtected`）只能由原来的账户解密，返回
//!   [`ImportError::AccountRestricted`]。
//!
//! 条目类型：1 登录、2 安全笔记、3 银行卡、4 身份、5 SSH 密钥。银行卡与身份作为安全笔记导入。

use std::collections::HashMap;

use base64::Engine;
use keevo_crypto::{BitwardenKdf, BitwardenKey, CryptoError};
use keevo_format::{FieldKind, ItemType, Purpose};
use serde_json::Value;
use zeroize::Zeroizing;

use super::{Builder, ImportError, Parsed};

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

pub(super) fn parse(data: &[u8], password: Option<&str>) -> Result<Parsed, ImportError> {
    let doc: Value = serde_json::from_slice(data).map_err(|_| ImportError::NotRecognized)?;
    if doc.get("encrypted").and_then(Value::as_bool) == Some(true) {
        if doc.get("passwordProtected").and_then(Value::as_bool) != Some(true) {
            return Err(ImportError::AccountRestricted);
        }
        let password = password.ok_or(ImportError::PasswordRequired)?;
        let plain = decrypt(&doc, password)?;
        let inner: Value = serde_json::from_slice(&plain).map_err(|_| ImportError::Malformed)?;
        return items(&inner);
    }
    items(&doc)
}

fn decrypt(doc: &Value, password: &str) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let num = |key: &str| {
        doc.get(key)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
    };
    let kdf = match num("kdfType") {
        Some(0) => BitwardenKdf::Pbkdf2 {
            iterations: num("kdfIterations").ok_or(ImportError::Malformed)?,
        },
        Some(1) => BitwardenKdf::Argon2id {
            memory_mib: num("kdfMemory").ok_or(ImportError::Malformed)?,
            iterations: num("kdfIterations").ok_or(ImportError::Malformed)?,
            parallelism: num("kdfParallelism").ok_or(ImportError::Malformed)?,
        },
        _ => return Err(ImportError::Malformed),
    };
    let key = BitwardenKey::derive(password, str_of(doc, "salt"), kdf).map_err(|e| match e {
        CryptoError::EmptyPassword => ImportError::WrongPassword,
        CryptoError::KdfAboveMaximum => ImportError::TooLarge,
        _ => ImportError::Malformed,
    })?;
    let open = |enc: &str| -> Result<Zeroizing<Vec<u8>>, ImportError> {
        let (iv, ct, mac) = enc_string(enc)?;
        key.decrypt(&iv, &ct, &mac).map_err(|e| match e {
            CryptoError::DecryptionFailed => ImportError::WrongPassword,
            _ => ImportError::Malformed,
        })
    };
    // 先验证密码（Bitwarden 自己也是这样做的），再解密数据
    open(str_of(doc, "encKeyValidation_DO_NOT_EDIT"))?;
    open(str_of(doc, "data")).map_err(|e| {
        if e == ImportError::WrongPassword {
            ImportError::Malformed
        } else {
            e
        }
    })
}

/// 加密字符串的三个部分：IV、密文、MAC。
type EncParts = (Vec<u8>, Vec<u8>, Vec<u8>);

/// 类型 2 的加密字符串：`2.<iv>|<密文>|<mac>`（Base64）。
fn enc_string(s: &str) -> Result<EncParts, ImportError> {
    let body = s.strip_prefix("2.").ok_or(ImportError::Malformed)?;
    let mut parts = body.split('|');
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut next = || {
        parts
            .next()
            .and_then(|p| b64.decode(p).ok())
            .ok_or(ImportError::Malformed)
    };
    Ok((next()?, next()?, next()?))
}

fn items(doc: &Value) -> Result<Parsed, ImportError> {
    let list = doc
        .get("items")
        .and_then(Value::as_array)
        .ok_or(ImportError::NotRecognized)?;
    // 文件夹与集合都变成标签
    let mut groups: HashMap<&str, &str> = HashMap::new();
    for key in ["folders", "collections"] {
        for g in doc.get(key).and_then(Value::as_array).into_iter().flatten() {
            groups.insert(str_of(g, "id"), str_of(g, "name"));
        }
    }
    let mut out = Parsed::default();
    for item in list {
        let name = str_of(item, "name");
        let mut b = match item.get("type").and_then(Value::as_u64) {
            Some(1) => login(item, name),
            Some(2) => Builder::new(ItemType::SecureNote, name),
            Some(3) => card(item, name),
            Some(4) => identity(item, name),
            Some(5) => ssh_key(item, name),
            _ => continue,
        };
        custom_fields(&mut b, item);
        b.note(str_of(item, "notes"));
        if let Some(folder) = groups.get(str_of(item, "folderId")) {
            b.tag(folder);
        }
        for id in item
            .get("collectionIds")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(name) = id.as_str().and_then(|id| groups.get(id)) {
                b.tag(name);
            }
        }
        b.favorite(item.get("favorite").and_then(Value::as_bool) == Some(true));
        let attachments = item
            .get("attachments")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        b.attachments(attachments);
        out.items.push(b.finish());
    }
    Ok(out)
}

fn login(item: &Value, name: &str) -> Builder {
    let mut b = Builder::new(ItemType::Login, name);
    let login = item.get("login").unwrap_or(&Value::Null);
    b.add(
        None,
        FieldKind::Text,
        "用户名",
        Some(Purpose::Username),
        str_of(login, "username"),
    );
    b.add(
        None,
        FieldKind::Concealed,
        "密码",
        Some(Purpose::Password),
        str_of(login, "password"),
    );
    for uri in login
        .get("uris")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        b.add(None, FieldKind::Url, "网站", None, str_of(uri, "uri"));
    }
    let totp = str_of(login, "totp");
    if !totp.trim().is_empty() {
        b.add_totp(None, "一次性密码", totp);
    }
    b
}

fn card(item: &Value, name: &str) -> Builder {
    let mut b = Builder::new(ItemType::SecureNote, name).original("credit_card");
    let c = item.get("card").unwrap_or(&Value::Null);
    b.add(
        None,
        FieldKind::Text,
        "持卡人",
        None,
        str_of(c, "cardholderName"),
    );
    b.add(None, FieldKind::Text, "品牌", None, str_of(c, "brand"));
    b.add(
        None,
        FieldKind::Concealed,
        "卡号",
        None,
        str_of(c, "number"),
    );
    let (m, y) = (str_of(c, "expMonth"), str_of(c, "expYear"));
    if !m.is_empty() || !y.is_empty() {
        b.add(
            None,
            FieldKind::Text,
            "有效期",
            None,
            &format!("{m:0>2}/{y}"),
        );
    }
    b.add(
        None,
        FieldKind::Concealed,
        "安全码",
        None,
        str_of(c, "code"),
    );
    b
}

fn identity(item: &Value, name: &str) -> Builder {
    let mut b = Builder::new(ItemType::SecureNote, name).original("identity");
    let i = item.get("identity").unwrap_or(&Value::Null);
    let full: Vec<&str> = ["firstName", "middleName", "lastName"]
        .iter()
        .map(|k| str_of(i, k))
        .filter(|s| !s.is_empty())
        .collect();
    b.add(None, FieldKind::Text, "称谓", None, str_of(i, "title"));
    b.add(None, FieldKind::Text, "姓名", None, &full.join(" "));
    b.add(None, FieldKind::Text, "用户名", None, str_of(i, "username"));
    b.add(None, FieldKind::Text, "公司", None, str_of(i, "company"));
    b.add(None, FieldKind::Email, "电子邮件", None, str_of(i, "email"));
    b.add(None, FieldKind::Phone, "电话", None, str_of(i, "phone"));
    let address: Vec<&str> = [
        "address1",
        "address2",
        "address3",
        "city",
        "state",
        "postalCode",
        "country",
    ]
    .iter()
    .map(|k| str_of(i, k))
    .filter(|s| !s.is_empty())
    .collect();
    b.add(
        None,
        FieldKind::Multiline,
        "地址",
        None,
        &address.join("\n"),
    );
    b.add(
        None,
        FieldKind::Concealed,
        "社会保障号",
        None,
        str_of(i, "ssn"),
    );
    b.add(
        None,
        FieldKind::Concealed,
        "护照号码",
        None,
        str_of(i, "passportNumber"),
    );
    b.add(
        None,
        FieldKind::Concealed,
        "驾照号码",
        None,
        str_of(i, "licenseNumber"),
    );
    b
}

fn ssh_key(item: &Value, name: &str) -> Builder {
    let mut b = Builder::new(ItemType::SshKey, name);
    let k = item.get("sshKey").unwrap_or(&Value::Null);
    b.add(
        None,
        FieldKind::SshPrivateKey,
        "私钥",
        None,
        str_of(k, "privateKey"),
    );
    b.add(
        None,
        FieldKind::Multiline,
        "公钥",
        None,
        str_of(k, "publicKey"),
    );
    b.add(
        None,
        FieldKind::Text,
        "指纹",
        None,
        str_of(k, "keyFingerprint"),
    );
    b
}

/// 自定义字段：0 文本、1 隐藏、2 布尔、3 链接（链接到其他字段，没有自己的值，跳过）。
fn custom_fields(b: &mut Builder, item: &Value) {
    let fields = item.get("fields").and_then(Value::as_array);
    if fields.is_none_or(Vec::is_empty) {
        return;
    }
    let section = b.section("自定义字段");
    for f in fields.into_iter().flatten() {
        let (label, value) = (str_of(f, "name"), str_of(f, "value"));
        match f.get("type").and_then(Value::as_u64) {
            Some(0) => b.add(section, FieldKind::Text, label, None, value),
            Some(1) => b.add(section, FieldKind::Concealed, label, None, value),
            Some(2) => b.add(
                section,
                FieldKind::Text,
                label,
                None,
                if value == "true" { "是" } else { "否" },
            ),
            _ => {}
        }
    }
}
