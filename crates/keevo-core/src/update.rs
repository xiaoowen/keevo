//! 检查更新（`docs/governance.md` §5）：从 GitHub 的发布列表中挑出比当前版本新的版本。这里只做解析与比较，
//! 不联网；请求由应用发出，结果只用来提示用户，不下载、不安装（安装前按 `docs/alpha/install.md` 核对）。

use std::cmp::Ordering;

use serde::Deserialize;

/// 一个可以提示给用户的新版本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// 版本号（去掉标签的 `v` 前缀），如 `0.1.0-alpha.2`。
    pub version: String,
    /// 发布页，必定在 `https://github.com/<仓库>/releases/` 之下。
    pub url: String,
}

/// 语义化版本（SemVer 2.0）。忽略构建元数据（`+` 之后的部分）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    core: [u64; 3],
    pre: Vec<String>,
}

impl Version {
    /// 解析 `1.2.3`、`v1.2.3-alpha.1` 等；格式不对时为 `None`。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.strip_prefix('v').unwrap_or(text);
        let text = text.split_once('+').map_or(text, |(v, _)| v);
        let (core, pre) = match text.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (text, None),
        };
        let mut numbers = core.split('.');
        let mut next = || -> Option<u64> {
            let part = numbers.next()?;
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            part.parse().ok()
        };
        let parsed = [next()?, next()?, next()?];
        if numbers.next().is_some() {
            return None;
        }
        let pre = match pre {
            None => Vec::new(),
            Some(pre) => {
                let ids: Vec<String> = pre.split('.').map(str::to_owned).collect();
                let valid = |id: &String| {
                    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                };
                if !ids.iter().all(valid) {
                    return None;
                }
                ids
            }
        };
        Some(Self { core: parsed, pre })
    }

    /// 是否是预发布版本（如 `0.1.0-alpha.1`）。
    #[must_use]
    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core
            .cmp(&other.core)
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                // 正式版高于同一版本号的预发布版
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (a, b) in self.pre.iter().zip(&other.pre) {
                        let order = match (a.parse::<u64>(), b.parse::<u64>()) {
                            (Ok(x), Ok(y)) => x.cmp(&y),
                            // 数字标识低于字母数字标识
                            (Ok(_), Err(_)) => Ordering::Less,
                            (Err(_), Ok(_)) => Ordering::Greater,
                            (Err(_), Err(_)) => a.cmp(b),
                        };
                        if order != Ordering::Equal {
                            return order;
                        }
                    }
                    self.pre.len().cmp(&other.pre.len())
                }
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

/// 从 GitHub API `GET /repos/<仓库>/releases` 的响应中挑出最新的、比 `current` 新的版本。
///
/// - 草稿、标签不是语义化版本、发布页不在 `https://github.com/<repo>/releases/` 之下的跳过；
/// - 当前是正式版时只考虑正式版；当前是预发布版时也考虑更新的预发布版。
///
/// # Errors
/// 响应不是预期格式的 JSON 时返回错误（算作检查失败）。
pub fn newest(
    current: &str,
    releases_json: &str,
    repo: &str,
) -> Result<Option<Release>, serde_json::Error> {
    let releases: Vec<GitHubRelease> = serde_json::from_str(releases_json)?;
    let Some(current) = Version::parse(current) else {
        return Ok(None);
    };
    let prefix = format!("https://github.com/{repo}/releases/");
    Ok(releases
        .into_iter()
        .filter(|r| !r.draft && r.html_url.starts_with(&prefix))
        .filter_map(|r| Version::parse(&r.tag_name).map(|v| (v, r)))
        .filter(|(v, r)| current.is_prerelease() || (!v.is_prerelease() && !r.prerelease))
        .filter(|(v, _)| *v > current)
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, r)| Release {
            version: r
                .tag_name
                .strip_prefix('v')
                .unwrap_or(&r.tag_name)
                .to_owned(),
            url: r.html_url,
        }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{Release, Version, newest};

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn parse() {
        assert_eq!(v("v1.2.3"), v("1.2.3"));
        assert_eq!(v("1.2.3+build.5"), v("1.2.3"));
        assert!(v("0.1.0-alpha.1").is_prerelease());
        assert!(!v("0.1.0").is_prerelease());
        for bad in [
            "",
            "1.2",
            "1.2.3.4",
            "1.2.x",
            "1.2.3-",
            "1.2.3-alpha..1",
            "1.2.3-α",
            " 1.2.3",
            "-1.2.3",
        ] {
            assert!(Version::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn order() {
        // SemVer 2.0 §11 的示例
        let ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.1.0",
            "2.0.0",
        ];
        for pair in ordered.windows(2) {
            if let [a, b] = pair {
                assert!(v(a) < v(b), "{a} < {b}");
            }
        }
        assert!(v("0.1.0-alpha.10") > v("0.1.0-alpha.2"));
    }

    fn release(tag: &str, prerelease: bool, draft: bool) -> String {
        format!(
            r#"{{"tag_name":"{tag}","html_url":"https://github.com/o/r/releases/tag/{tag}","prerelease":{prerelease},"draft":{draft}}}"#
        )
    }

    #[test]
    fn newest_release() {
        let list = format!(
            "[{},{},{},{}]",
            release("v0.1.0-alpha.2", true, false),
            release("v0.1.0-alpha.3", true, true),
            release("v0.0.9", false, false),
            release("not-a-version", false, false),
        );
        assert_eq!(
            newest("0.1.0-alpha.1", &list, "o/r").unwrap(),
            Some(Release {
                version: "0.1.0-alpha.2".into(),
                url: "https://github.com/o/r/releases/tag/v0.1.0-alpha.2".into(),
            }),
            "草稿不算"
        );
        assert_eq!(
            newest("0.1.0-alpha.2", &list, "o/r").unwrap(),
            None,
            "已是最新"
        );
        // 正式版只看正式版
        let list = format!(
            "[{},{}]",
            release("v1.1.0-rc.1", true, false),
            release("v1.0.1", false, false)
        );
        assert_eq!(
            newest("1.0.0", &list, "o/r").unwrap().unwrap().version,
            "1.0.1"
        );
        assert_eq!(newest("1.0.1", &list, "o/r").unwrap(), None);
        // 发布页不在本仓库之下的跳过
        let foreign =
            r#"[{"tag_name":"v9.0.0","html_url":"https://example.com/o/r/releases/tag/v9.0.0"}]"#;
        assert_eq!(newest("1.0.0", foreign, "o/r").unwrap(), None);
        let other_repo =
            r#"[{"tag_name":"v9.0.0","html_url":"https://github.com/o/r2/releases/tag/v9.0.0"}]"#;
        assert_eq!(newest("1.0.0", other_repo, "o/r").unwrap(), None);
        // 格式不对算检查失败
        assert!(newest("1.0.0", "{}", "o/r").is_err());
        assert!(newest("1.0.0", "not json", "o/r").is_err());
    }
}
