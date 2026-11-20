//! 浏览器与 LastPass 的 CSV。按表头的列名取值（不依赖列的顺序），不同来源的列名：
//!
//! - Chrome：`name,url,username,password,note`
//! - Safari：`Title,URL,Username,Password,Notes,OTPAuth`
//! - Firefox：`url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged`
//! - LastPass：`url,username,password,totp,extra,name,grouping,fav`；网址为 `http://sn` 的是安全笔记
//!
//! 也接受同样列名的其他 CSV（例如 Bitwarden 的 CSV）。

use keevo_format::{FieldKind, ItemType, Purpose};

use super::{Builder, ImportError, Parsed, Source, csv};

const TITLE: &[&str] = &["name", "title"];
const URL: &[&str] = &["url", "login_uri", "website", "uri"];
const USERNAME: &[&str] = &["username", "login_username", "login", "user"];
const PASSWORD: &[&str] = &["password", "login_password"];
const NOTES: &[&str] = &["note", "notes", "extra", "comments"];
const TOTP: &[&str] = &["otpauth", "totp", "login_totp"];
const FOLDER: &[&str] = &["grouping", "folder"];
const FAVORITE: &[&str] = &["fav", "favorite"];

pub(super) fn parse(source: Source, data: &[u8]) -> Result<Parsed, ImportError> {
    let text = core::str::from_utf8(data).map_err(|_| ImportError::NotRecognized)?;
    let mut rows = csv::parse(text)?.into_iter();
    let header: Vec<String> = rows
        .next()
        .ok_or(ImportError::Empty)?
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    let col = |names: &[&str]| header.iter().position(|h| names.contains(&h.as_str()));
    let (url, password) = (col(URL), col(PASSWORD));
    // 至少要有网址与密码两列，否则不是密码导出文件
    if url.is_none() || password.is_none() {
        return Err(ImportError::NotRecognized);
    }
    let (title, username, notes, totp, folder, favorite) = (
        col(TITLE),
        col(USERNAME),
        col(NOTES),
        col(TOTP),
        col(FOLDER),
        col(FAVORITE),
    );
    let mut out = Parsed::default();
    for row in rows {
        let get = |i: Option<usize>| i.and_then(|i| row.get(i)).map_or("", |s| s.as_str());
        let site = get(url);
        // LastPass 的安全笔记
        if source == Source::LastPass && site.trim() == "http://sn" {
            let mut b = Builder::new(ItemType::SecureNote, get(title));
            b.note(get(notes));
            lastpass_folder(&mut b, get(folder));
            b.favorite(get(favorite) == "1");
            out.push(b.finish())?;
            continue;
        }
        if site.trim().is_empty() && get(password).is_empty() && get(username).is_empty() {
            continue;
        }
        let mut b = Builder::new(ItemType::Login, get(title));
        b.add(
            None,
            FieldKind::Text,
            "用户名",
            Some(Purpose::Username),
            get(username),
        );
        b.add(
            None,
            FieldKind::Concealed,
            "密码",
            Some(Purpose::Password),
            get(password),
        );
        b.add(None, FieldKind::Url, "网站", None, site);
        if !get(totp).trim().is_empty() {
            b.add_totp(None, "一次性密码", get(totp));
        }
        b.note(get(notes));
        if source == Source::LastPass {
            lastpass_folder(&mut b, get(folder));
        } else {
            b.tag(get(folder));
        }
        b.favorite(matches!(get(favorite).trim(), "1" | "true" | "TRUE"));
        out.push(b.finish())?;
    }
    Ok(out)
}

/// LastPass 的文件夹以 `\` 分隔层级；共享文件夹形如 `Shared-名称`。
fn lastpass_folder(b: &mut Builder, folder: &str) {
    let folder = folder.trim();
    if !folder.is_empty() && folder != "(none)" {
        b.tag(&folder.replace('\\', "/"));
    }
}
