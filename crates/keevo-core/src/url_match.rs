//! 网址匹配（`docs/architecture.md` §5.3），决定一个条目能否填充到某个页面。
//!
//! M0 规则（保守，宁可不匹配也不误匹配）：
//! - 只认 `http` 与 `https`；保存为 HTTPS 的条目不填充到 HTTP 页面（防协议降级）。
//! - 域名：页面主机等于保存的主机，或是它的子域（以 `.` 为界）。
//! - IP 地址与 `localhost`：主机与端口都必须完全一致，便于区分本地开发中的多个服务。
//! - 主机名由 WHATWG URL 解析器规范化（小写、IDNA 转 punycode），因此 `github.com@evil.example`、
//!   全角字符、同形字等都不会被误认为 `github.com`。
//!
//! M1.3 引入 Public Suffix List，并支持"主机精确匹配""前缀匹配""从不建议"等按网址设置的规则。

use url::{Host, Url};

/// 保存在条目中的网址能否用于填充当前页面。
#[must_use]
pub fn matches(saved: &str, page: &str) -> bool {
    let (Some(saved), Some(page)) = (parse(saved), parse(page)) else {
        return false;
    };
    if saved.scheme() == "https" && page.scheme() != "https" {
        return false;
    }
    match (saved.host(), page.host()) {
        (Some(Host::Domain(s)), Some(Host::Domain(p))) if !is_localhost(s) => {
            !s.is_empty()
                && (p == s
                    || p.strip_suffix(s)
                        .is_some_and(|prefix| prefix.ends_with('.')))
        }
        (Some(s), Some(p)) => {
            s == p && saved.port_or_known_default() == page.port_or_known_default()
        }
        _ => false,
    }
}

fn is_localhost(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost")
}

/// 解析网址。保存的网址可能省略协议（如 `github.com`），此时按 HTTPS 处理。
///
/// 带用户名或密码的网址一律拒绝：正常的网站网址不会包含它们，而补全协议时，`mailto:a@b.c`
/// 这类值会被解析成"用户名 mailto、主机 b.c"。
fn parse(input: &str) -> Option<Url> {
    let input = input.trim();
    let url = if input.contains("://") {
        Url::parse(input).ok()?
    } else {
        Url::parse(&format!("https://{input}")).ok()?
    };
    let plain = url.username().is_empty() && url.password().is_none();
    (plain && matches!(url.scheme(), "http" | "https")).then_some(url)
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn same_host_and_subdomains_match() {
        assert!(matches("https://github.com", "https://github.com/login"));
        assert!(matches("github.com", "https://github.com/session"));
        assert!(matches("https://github.com", "https://gist.github.com/"));
        assert!(matches("https://GitHub.COM/", "https://github.com:443/x"));
    }

    #[test]
    fn lookalikes_and_tricks_do_not_match() {
        for page in [
            "https://github.com.evil.example/login",
            "https://evilgithub.com/",
            "https://github.com@evil.example/",
            "https://evil.example/?https://github.com",
            "https://evil.example/#github.com",
            "https://xn--gthub-n4a.com/", // gіthub（西里尔字母 і）
            "https://gіthub.com/",
            "javascript:alert(1)//github.com",
            "data:text/html,github.com",
            "file:///github.com",
            "",
        ] {
            assert!(!matches("https://github.com", page), "{page}");
        }
    }

    #[test]
    fn https_items_are_not_filled_into_http_pages() {
        assert!(!matches("https://github.com", "http://github.com/login"));
        assert!(matches(
            "http://intranet.example",
            "http://intranet.example/"
        ));
        assert!(matches(
            "http://intranet.example",
            "https://intranet.example/"
        ));
    }

    #[test]
    fn ip_and_localhost_require_exact_port() {
        assert!(matches(
            "http://localhost:3000",
            "http://localhost:3000/login"
        ));
        assert!(!matches(
            "http://localhost:3000",
            "http://localhost:8080/login"
        ));
        assert!(matches("http://127.0.0.1:8080", "http://127.0.0.1:8080/"));
        assert!(!matches("http://127.0.0.1:8080", "http://127.0.0.2:8080/"));
        assert!(!matches("http://192.168.1.1", "http://192.168.1.10/"));
    }

    #[test]
    fn saved_value_without_a_usable_host_matches_nothing() {
        assert!(!matches("", "https://github.com"));
        assert!(!matches("not a url at all", "https://github.com"));
        assert!(!matches("mailto:a@b.c", "https://b.c"));
        assert!(!matches("https://user:pw@github.com", "https://github.com"));
        assert!(matches("github.com:8443", "https://github.com:8443/"));
    }
}
