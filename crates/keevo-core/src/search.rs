//! 条目搜索与过滤语法（`docs/ux.md` §2"条目列表"）。
//!
//! 只使用条目概要（标题、副标题、网址、标签、类型、收藏、冲突）与保险库名称，不解密详情。
//!
//! **语法**：以空白分隔；`"…"` 括起来的是一个词。
//! - 普通词：必须出现在标题、副标题、网址、标签之一（不区分大小写）；多个词同时满足。
//! - `type:登录`、`type:ssh` 等：条目类型，接受英文、中文与常用简称。
//! - `tag:work`：带有该标签（不区分大小写，完整匹配）。
//! - `vault:开发`：保险库名称包含该词。
//! - `url:github.com`：某个网址包含该词。
//! - `is:fav`（`is:收藏`）、`is:conflict`（`is:冲突`）、`is:weak`（`is:弱密码`，安全中心检查完成后可用）。
//! - 在过滤前加 `-` 表示排除，例如 `-tag:archive`。
//! - 不认识的 `键:值` 按普通词处理，因此搜索 `https://` 这样的内容不受影响。
//!
//! **排序**：标题完全相同 > 标题以该词开头 > 标题中某个单词以它开头 > 标题包含 > 其他字段包含 >
//! 标题按顺序包含它的各个字符（模糊匹配）。分数相同时按标题排序（不区分大小写）。

use std::collections::HashMap;

use keevo_crypto::Id128;

use crate::vault::ItemSummary;
use keevo_format::ItemType;

/// 一个过滤条件。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Filter {
    Type(ItemType),
    Tag(String),
    Vault(String),
    Url(String),
    Favorite,
    Conflict,
    Weak,
}

/// 解析后的查询。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    terms: Vec<String>,
    filters: Vec<(bool, Filter)>,
}

impl Query {
    /// 解析查询文本。不会失败：无法识别的部分按普通词处理。
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut q = Self::default();
        for token in tokenize(text) {
            let (negated, body) = token
                .strip_prefix('-')
                .filter(|rest| rest.contains(':'))
                .map_or((false, token.as_str()), |rest| (true, rest));
            match body.split_once(':').and_then(|(k, v)| filter(k, v)) {
                Some(f) => q.filters.push((negated, f)),
                None => {
                    let term = token.to_lowercase();
                    if !term.is_empty() {
                        q.terms.push(term);
                    }
                }
            }
        }
        q
    }

    /// 是否为空查询（没有词也没有过滤）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.terms.is_empty() && self.filters.is_empty()
    }
}

fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in text.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    out.push(core::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn filter(key: &str, value: &str) -> Option<Filter> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let v = value.to_lowercase();
    match key.to_lowercase().as_str() {
        "type" | "类型" => item_type(&v).map(Filter::Type),
        "tag" | "标签" => Some(Filter::Tag(v)),
        "vault" | "保险库" => Some(Filter::Vault(v)),
        "url" | "网址" => Some(Filter::Url(v)),
        "is" => match v.as_str() {
            "fav" | "favorite" | "favourite" | "收藏" => Some(Filter::Favorite),
            "conflict" | "conflicts" | "冲突" => Some(Filter::Conflict),
            "weak" | "弱密码" | "弱" => Some(Filter::Weak),
            _ => None,
        },
        _ => None,
    }
}

fn item_type(v: &str) -> Option<ItemType> {
    Some(match v {
        "login" | "登录" => ItemType::Login,
        "email" | "email_account" | "mail" | "电子邮件" | "邮箱" => ItemType::EmailAccount,
        "note" | "secure_note" | "笔记" | "安全笔记" => ItemType::SecureNote,
        "ssh" | "ssh_key" | "ssh密钥" => ItemType::SshKey,
        "api" | "api_credential" | "token" | "api凭证" | "令牌" => ItemType::ApiCredential,
        "db" | "database" | "数据库" | "数据库凭证" => ItemType::Database,
        "env" | "environment" | "环境变量" => ItemType::Environment,
        "2fa" | "totp" | "otp" | "two_factor" | "双因素" | "双因素验证" => {
            ItemType::TwoFactor
        }
        _ => return None,
    })
}

/// 搜索索引：预先把需要比较的字段转成小写，每次按键只做比较。
pub struct SearchIndex {
    entries: Vec<Entry>,
}

struct Entry {
    id: Id128,
    item_type: ItemType,
    favorite: bool,
    conflicts: bool,
    /// 安全中心判定为弱密码（`is:weak`）；检查完成前全部为 `false`。
    weak: bool,
    title: String,
    others: Vec<String>,
    urls: Vec<String>,
    tags: Vec<String>,
    vault: String,
}

/// 一条结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    /// 条目 ID。
    pub id: Id128,
    /// 相关度，越大越靠前。
    pub score: u32,
}

impl SearchIndex {
    /// 由条目概要与保险库名称建立索引。
    #[must_use]
    pub fn new(items: &[ItemSummary], vault_names: &HashMap<Id128, String>) -> Self {
        let entries = items
            .iter()
            .map(|i| {
                let o = &i.overview;
                let urls: Vec<String> = o.urls.iter().map(|u| u.to_lowercase()).collect();
                let tags: Vec<String> = o.tags.iter().map(|t| t.to_lowercase()).collect();
                let mut others = vec![o.subtitle.to_lowercase()];
                others.extend(urls.iter().cloned());
                others.extend(tags.iter().cloned());
                Entry {
                    id: i.id,
                    item_type: o.item_type,
                    favorite: o.favorite,
                    conflicts: i.has_conflicts,
                    weak: false,
                    title: o.title.to_lowercase(),
                    others,
                    urls,
                    tags,
                    vault: vault_names
                        .get(&i.vault_id)
                        .map(|n| n.to_lowercase())
                        .unwrap_or_default(),
                }
            })
            .collect();
        Self { entries }
    }

    /// 记下安全中心判定为弱密码的条目（`is:weak`，`crate::security::Report::weak_items`）。
    pub fn set_weak(&mut self, weak: &std::collections::HashSet<Id128>) {
        for e in &mut self.entries {
            e.weak = weak.contains(&e.id);
        }
    }

    /// 条目数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 按查询筛选并排序。空查询返回全部条目，按标题排序。
    #[must_use]
    pub fn search(&self, query: &Query) -> Vec<Hit> {
        let mut hits: Vec<(Hit, &str)> = self
            .entries
            .iter()
            .filter(|e| query.filters.iter().all(|(neg, f)| e.matches(f) != *neg))
            .filter_map(|e| {
                let mut score = 0u32;
                for term in &query.terms {
                    score = score.saturating_add(e.score(term)?);
                }
                Some((Hit { id: e.id, score }, e.title.as_str()))
            })
            .collect();
        hits.sort_by(|(a, ta), (b, tb)| {
            b.score
                .cmp(&a.score)
                .then_with(|| ta.cmp(tb))
                .then(a.id.cmp(&b.id))
        });
        hits.into_iter().map(|(h, _)| h).collect()
    }
}

impl Entry {
    fn matches(&self, f: &Filter) -> bool {
        match f {
            Filter::Type(t) => self.item_type == *t,
            Filter::Tag(t) => self.tags.iter().any(|x| x == t),
            Filter::Vault(v) => self.vault.contains(v.as_str()),
            Filter::Url(u) => self.urls.iter().any(|x| x.contains(u.as_str())),
            Filter::Favorite => self.favorite,
            Filter::Conflict => self.conflicts,
            Filter::Weak => self.weak,
        }
    }

    /// 一个词的得分；完全不匹配时返回 `None`。
    fn score(&self, term: &str) -> Option<u32> {
        let t = self.title.as_str();
        if t == term {
            return Some(100);
        }
        if t.starts_with(term) {
            return Some(80);
        }
        if t.split(|c: char| !c.is_alphanumeric())
            .any(|w| w.starts_with(term))
        {
            return Some(60);
        }
        if t.contains(term) {
            return Some(40);
        }
        if self.others.iter().any(|o| o.contains(term)) {
            return Some(20);
        }
        if is_subsequence(term, t) {
            return Some(10);
        }
        None
    }
}

/// `needle` 的各个字符是否按顺序出现在 `haystack` 中。
fn is_subsequence(needle: &str, haystack: &str) -> bool {
    let mut h = haystack.chars();
    needle.chars().all(|c| h.any(|x| x == c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keevo_format::{Hlc, ItemOverview};

    #[allow(clippy::too_many_arguments)]
    fn summary(
        n: u8,
        item_type: ItemType,
        title: &str,
        subtitle: &str,
        urls: &[&str],
        tags: &[&str],
        fav: bool,
        vault: Id128,
    ) -> ItemSummary {
        ItemSummary {
            id: Id128::from_bytes([n; 16]),
            vault_id: vault,
            overview: ItemOverview {
                v: 1,
                item_type,
                title: title.into(),
                subtitle: subtitle.into(),
                urls: urls.iter().map(|s| (*s).to_owned()).collect(),
                tags: tags.iter().map(|s| (*s).to_owned()).collect(),
                favorite: fav,
                archived: false,
                trashed_at: None,
                updated: Hlc(0),
                conflicts: false,
            },
            has_conflicts: n == 6,
        }
    }

    fn index() -> SearchIndex {
        let personal = Id128::from_bytes([1; 16]);
        let dev = Id128::from_bytes([2; 16]);
        let items = vec![
            summary(
                1,
                ItemType::Login,
                "GitHub",
                "octocat",
                &["https://github.com/login"],
                &["work"],
                true,
                personal,
            ),
            summary(
                2,
                ItemType::Login,
                "GitLab 工作",
                "alice",
                &["https://gitlab.example.com"],
                &["Work"],
                false,
                dev,
            ),
            summary(
                3,
                ItemType::SshKey,
                "部署密钥 github",
                "",
                &[],
                &["deploy"],
                false,
                dev,
            ),
            summary(
                4,
                ItemType::SecureNote,
                "Wi-Fi 密码",
                "",
                &[],
                &[],
                false,
                personal,
            ),
            summary(
                5,
                ItemType::Database,
                "Postgres 生产",
                "admin",
                &[],
                &["prod"],
                false,
                dev,
            ),
            summary(
                6,
                ItemType::Login,
                "Gmail",
                "alice@gmail.com",
                &["https://mail.google.com"],
                &[],
                false,
                personal,
            ),
        ];
        let names = HashMap::from([(personal, "个人".to_owned()), (dev, "开发".to_owned())]);
        SearchIndex::new(&items, &names)
    }

    fn ids(index: &SearchIndex, q: &str) -> Vec<u8> {
        index
            .search(&Query::parse(q))
            .iter()
            .map(|h| h.id.as_bytes()[0])
            .collect()
    }

    #[test]
    fn ranking() {
        let ix = index();
        assert_eq!(ids(&ix, "github"), [1, 3], "标题完全相同排在单词开头之前");
        assert_eq!(ids(&ix, "git"), [1, 2, 3], "开头 > 单词开头；同分按标题");
        assert_eq!(
            ids(&ix, "alice"),
            [2, 6],
            "副标题包含；同分按标题（GitLab 在 Gmail 之前）"
        );
        assert_eq!(ids(&ix, "GMAIL"), [6], "不区分大小写");
        assert_eq!(ids(&ix, "gthb"), [1, 3], "模糊匹配");
        assert_eq!(ids(&ix, "生产"), [5], "中文");
        assert_eq!(ids(&ix, "git work"), [1, 2], "多个词同时满足");
        assert_eq!(ids(&ix, "\"wi-fi 密码\""), [4], "引号括起来的短语");
        assert_eq!(ids(&ix, "").len(), 6, "空查询返回全部");
    }

    #[test]
    fn filters() {
        let ix = index();
        assert_eq!(ids(&ix, "type:ssh"), [3]);
        assert_eq!(ids(&ix, "type:登录 is:fav"), [1]);
        assert_eq!(ids(&ix, "tag:work"), [1, 2], "标签不区分大小写、完整匹配");
        assert_eq!(ids(&ix, "tag:wor"), Vec::<u8>::new());
        assert_eq!(ids(&ix, "vault:开发 -type:db"), [2, 3], "排除");
        assert_eq!(ids(&ix, "url:google"), [6]);
        assert_eq!(ids(&ix, "is:冲突"), [6]);
        assert!(ids(&ix, "is:weak").is_empty(), "检查完成前没有弱密码");
        assert_eq!(ids(&ix, "type:db 生产"), [5]);
        assert_eq!(ids(&ix, "https://mail"), [6], "不认识的键按普通词处理");
        assert_eq!(
            ids(&ix, "type:unknown").len(),
            0,
            "类型名写错时当作普通词，没有条目包含它"
        );
        assert!(Query::parse("  ").is_empty());
        assert!(!Query::parse("is:fav").is_empty());
    }

    /// 1 万个条目时每次按键的耗时。用 `cargo test --release -p keevo-core search_performance -- --ignored --nocapture` 运行。
    #[test]
    #[ignore = "性能测量，需要 release 构建"]
    fn search_performance() {
        let vault = Id128::from_bytes([1; 16]);
        let items: Vec<ItemSummary> = (0..10_000u32)
            .map(|i| {
                let mut s = summary(
                    0,
                    ItemType::Login,
                    &format!("服务 {i} Example Account"),
                    &format!("user{i}@example.com"),
                    &["https://example.com/login"],
                    &["work", "team"],
                    i % 7 == 0,
                    vault,
                );
                s.id = Id128::from_bytes([u8::try_from(i % 251).unwrap(); 16]);
                s
            })
            .collect();
        let names = HashMap::from([(vault, "个人".to_owned())]);
        let start = std::time::Instant::now();
        let ix = SearchIndex::new(&items, &names);
        let build = start.elapsed();
        let mut worst = std::time::Duration::ZERO;
        for q in [
            "e",
            "ex",
            "exam",
            "example acc",
            "服务 99",
            "zzzz",
            "type:login is:fav",
            "eaa",
        ] {
            let t = std::time::Instant::now();
            let n = ix.search(&Query::parse(q)).len();
            let d = t.elapsed();
            worst = worst.max(d);
            #[allow(clippy::print_stdout)]
            {
                println!("{q:>16}: {n:>5} 条，{d:?}");
            }
        }
        #[allow(clippy::print_stdout)]
        {
            println!("建立索引 {build:?}，最慢一次 {worst:?}");
        }
        assert!(worst < std::time::Duration::from_millis(16));
    }
}
