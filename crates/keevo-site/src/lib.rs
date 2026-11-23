//! 可注册域名与"同站"判断（`docs/security.md` §12：同站的 iframe 不要求再次确认）。
//!
//! 规则来自 Public Suffix List：`public_suffix_list.dat` 原样取自 <https://publicsuffix.org/list/>（MPL-2.0），
//! ICANN 与私有两部分都用，因此 `github.io` 等私有后缀下的不同子域不算同站。算法按列表说明的"Formal Algorithm"：
//! 匹配的规则中最长的那条胜出，例外规则（`!`）优先于其他规则，没有规则匹配时默认最后一个标签是公共后缀。
//!
//! 保守之处（宁可不算同站）：
//! - 列表中的国际化规则是 Unicode 写法，而浏览器给出的主机是 punycode（`xn--`）。这里不做转换：含有 `xn--`
//!   标签的主机只在完全相同时才算同站，以免把某个国际化公共后缀下的不同网站误认为同站；
//! - IP 地址没有可注册域名，只在完全相同时算同站；
//! - 只有两边都是 HTTPS 才可能同站：HTTP 的页面可能在传输中被篡改。
//!
//! 更新列表：从 <https://publicsuffix.org/list/public_suffix_list.dat> 下载，原样替换 `src/public_suffix_list.dat`。
//! `build.rs` 在编译时去掉其中的注释，只嵌入规则。

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::OnceLock;

/// 规则，每行一条（`build.rs` 从 `public_suffix_list.dat` 中取出）。
const LIST: &str = include_str!(concat!(env!("OUT_DIR"), "/rules.txt"));

struct Rules {
    /// 普通规则，如 `com.cn`。
    normal: HashSet<&'static str>,
    /// 通配规则 `*.ck` 去掉 `*.` 之后的部分：`ck`。
    wildcard: HashSet<&'static str>,
    /// 例外规则 `!www.ck` 去掉 `!` 之后的部分：`www.ck`。
    exception: HashSet<&'static str>,
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut rules = Rules {
            normal: HashSet::new(),
            wildcard: HashSet::new(),
            exception: HashSet::new(),
        };
        for rule in LIST.lines() {
            if let Some(r) = rule.strip_prefix('!') {
                rules.exception.insert(r);
            } else if let Some(r) = rule.strip_prefix("*.") {
                rules.wildcard.insert(r);
            } else {
                rules.normal.insert(rule);
            }
        }
        rules
    })
}

fn is_ip(host: &str) -> bool {
    host.starts_with('[') || host.contains(':') || host.parse::<Ipv4Addr>().is_ok()
}

/// 主机的可注册域名（eTLD+1），如 `passport.aliyun.com` → `aliyun.com`、`a.sina.com.cn` → `sina.com.cn`。
/// 公共后缀本身、IP 地址、空主机或含空标签的主机没有可注册域名。主机应已规范化（小写、punycode）。
#[must_use]
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() || is_ip(&host) {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.iter().any(|l| l.is_empty()) {
        return None;
    }
    let n = labels.len();
    let rules = rules();
    let tail = |i: usize| labels.get(i..).map(|l| l.join(".")).unwrap_or_default();
    // 例外规则优先：公共后缀是例外规则去掉最左边的标签
    let exception = (0..n).find(|&i| rules.exception.contains(tail(i).as_str()));
    let suffix_len = if let Some(i) = exception {
        n.saturating_sub(i).saturating_sub(1)
    } else {
        let mut len = 1; // 默认规则 "*"
        for i in 0..n {
            let next = i.saturating_add(1);
            let wildcard = next < n && rules.wildcard.contains(tail(next).as_str());
            if wildcard || rules.normal.contains(tail(i).as_str()) {
                len = len.max(n.saturating_sub(i));
            }
        }
        len
    };
    if suffix_len >= n {
        return None;
    }
    Some(tail(n.saturating_sub(suffix_len).saturating_sub(1)))
}

/// 源（`https://host[:port]`）中的主机；不是 HTTPS 时为 `None`。
fn https_host(origin: &str) -> Option<&str> {
    let rest = origin.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = if authority.starts_with('[') {
        // IPv6 字面量：保留方括号，便于识别为 IP
        authority.get(..=authority.find(']')?)?
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    (!host.is_empty()).then_some(host)
}

/// 两个源是否同站：都是 HTTPS，并且可注册域名相同（端口不计入）。主机完全相同时也算同站。
#[must_use]
pub fn same_site(a: &str, b: &str) -> bool {
    let (Some(ha), Some(hb)) = (https_host(a), https_host(b)) else {
        return false;
    };
    let (ha, hb) = (ha.to_ascii_lowercase(), hb.to_ascii_lowercase());
    if ha == hb {
        return true;
    }
    if [&ha, &hb]
        .iter()
        .any(|h| h.split('.').any(|l| l.starts_with("xn--")))
    {
        return false;
    }
    match (registrable_domain(&ha), registrable_domain(&hb)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{registrable_domain, same_site};

    fn rd(host: &str) -> Option<String> {
        registrable_domain(host)
    }

    #[test]
    fn registrable_domains() {
        assert_eq!(rd("www.example.com").as_deref(), Some("example.com"));
        assert_eq!(rd("example.com").as_deref(), Some("example.com"));
        assert_eq!(rd("EXAMPLE.com.").as_deref(), Some("example.com"));
        assert_eq!(rd("com"), None);
        assert_eq!(rd("passport.aliyun.com").as_deref(), Some("aliyun.com"));
        // 多级公共后缀
        assert_eq!(rd("a.b.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(rd("co.uk"), None);
        assert_eq!(rd("mail.sina.com.cn").as_deref(), Some("sina.com.cn"));
        assert_eq!(rd("com.cn"), None);
        // 私有后缀
        assert_eq!(rd("alice.github.io").as_deref(), Some("alice.github.io"));
        assert_eq!(rd("github.io"), None);
        // 通配与例外：*.ck 与 !www.ck，*.kawasaki.jp 与 !city.kawasaki.jp
        assert_eq!(rd("b.ck"), None);
        assert_eq!(rd("a.b.ck").as_deref(), Some("a.b.ck"));
        assert_eq!(rd("www.ck").as_deref(), Some("www.ck"));
        assert_eq!(rd("x.www.ck").as_deref(), Some("www.ck"));
        assert_eq!(rd("test.kawasaki.jp"), None);
        assert_eq!(
            rd("a.test.kawasaki.jp").as_deref(),
            Some("a.test.kawasaki.jp")
        );
        assert_eq!(rd("city.kawasaki.jp").as_deref(), Some("city.kawasaki.jp"));
        // 列表中没有的顶级域：默认最后一个标签是公共后缀
        assert_eq!(
            rd("a.b.example-unknown-tld").as_deref(),
            Some("b.example-unknown-tld")
        );
        // 没有可注册域名
        assert_eq!(rd(""), None);
        assert_eq!(rd("a..com"), None);
        assert_eq!(rd("127.0.0.1"), None);
        assert_eq!(rd("[::1]"), None);
    }

    #[test]
    fn same_site_rules() {
        // 反馈：阿里云的登录框嵌在同站的页面中
        assert!(same_site(
            "https://account.aliyun.com",
            "https://passport.aliyun.com"
        ));
        assert!(same_site(
            "https://mail.qq.com",
            "https://xui.ptlogin2.qq.com"
        ));
        assert!(same_site(
            "https://a.example.com:8443",
            "https://b.example.com"
        ));
        assert!(same_site("https://example.com", "https://example.com"));
        // 不同网站
        assert!(!same_site("https://a.com.cn", "https://b.com.cn"));
        assert!(!same_site(
            "https://alice.github.io",
            "https://bob.github.io"
        ));
        assert!(!same_site("https://example.com", "https://example.org"));
        assert!(!same_site(
            "https://evil-aliyun.com",
            "https://passport.aliyun.com"
        ));
        // 必须都是 HTTPS
        assert!(!same_site(
            "http://account.aliyun.com",
            "https://passport.aliyun.com"
        ));
        assert!(!same_site("http://a.example.com", "http://b.example.com"));
        // IP 与 localhost：只有完全相同的主机
        assert!(!same_site("https://127.0.0.1", "https://localhost"));
        assert!(same_site("https://127.0.0.1:1", "https://127.0.0.1:2"));
        assert!(!same_site("https://[::1]", "https://[::2]"));
        // punycode：只有完全相同的主机
        assert!(!same_site(
            "https://a.xn--55qx5d.cn",
            "https://b.xn--55qx5d.cn"
        ));
        assert!(same_site(
            "https://a.xn--55qx5d.cn",
            "https://a.xn--55qx5d.cn"
        ));
        // 公共后缀本身不与任何网站同站
        assert!(!same_site("https://com.cn", "https://a.com.cn"));
        // 格式不对
        assert!(!same_site("", "https://example.com"));
        assert!(!same_site("https://", "https://example.com"));
    }
}
