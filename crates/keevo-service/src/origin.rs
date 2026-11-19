//! 请求的来源（`spec/cli.md` §5、`spec/ssh-agent.md` §4.2）：由 socket 对端的 pid 读取进程表，
//! 得到命令行、所在应用与会话键。不采信对端的自述。

use keevo_macos::process::ProcessInfo;

/// 祖先链的最大长度（防止进程表异常时无限循环）。
const MAX_DEPTH: usize = 64;
/// 命令行在界面中最多显示的字符数。
const MAX_COMMAND_CHARS: usize = 200;

/// 进程表。正式实现读取内核；测试中用固定的数据。
pub trait ProcessTable {
    /// 进程信息。
    fn info(&self, pid: u32) -> Option<ProcessInfo>;
    /// 命令行参数。
    fn args(&self, pid: u32) -> Option<Vec<String>>;
}

/// 读取内核的进程表。
pub struct SystemProcesses;

impl ProcessTable for SystemProcesses {
    fn info(&self, pid: u32) -> Option<ProcessInfo> {
        keevo_macos::process::process_info(pid)
    }
    fn args(&self, pid: u32) -> Option<Vec<String>> {
        keevo_macos::process::process_args(pid)
    }
}

/// 授权所依据的会话（§5 第 1 条）。启动时间参与比较，pid 被复用后不会继承授权。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey {
    /// 控制终端的设备号；没有终端时为 `None`。
    pub tty: Option<u32>,
    /// 锚定进程的 pid。
    pub pid: u32,
    /// 锚定进程的启动时间（Unix 微秒）。
    pub start_us: u64,
}

/// 没有控制终端时，会话锚定在哪个祖先上。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoTtyAnchor {
    /// 父进程（CLI：编辑器的任务等）。
    Parent,
    /// 最近的应用祖先（SSH：同一个应用发起的连接算同一会话）。
    App,
}

/// 一个请求的来源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// 发起请求的进程。
    pub pid: u32,
    /// 命令行（最多 200 个字符）。
    pub command: String,
    /// 所在的应用（祖先中最近的一个应用包），如 `iTerm`、`Terminal`、`Visual Studio Code`。
    pub app: Option<String>,
    /// 父进程名，如 `zsh`、`git`。
    pub parent_name: String,
    /// 父进程不是 shell 时，它的命令行（如 `git push`）。
    pub parent_command: Option<String>,
    /// 会话键。
    pub session: SessionKey,
}

const SHELLS: &[&str] = &[
    "zsh", "bash", "sh", "fish", "dash", "tcsh", "csh", "ksh", "nu", "login",
];

fn is_shell(name: &str) -> bool {
    let name = name.trim_start_matches('-');
    SHELLS.contains(&name)
}

/// 由可执行文件路径得到应用包名：取第一个 `.app/` 之前的那一段，例如
/// `/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/…` → `Visual Studio Code`。
fn app_name(path: &str) -> Option<String> {
    let idx = path.find(".app/")?;
    let head = path.get(..idx)?;
    let name = head.rsplit('/').next()?;
    (!name.is_empty()).then(|| name.to_owned())
}

/// 把参数拼成一行：含空白的参数加引号；超过上限时截断并加省略号。
#[must_use]
pub fn join_command(args: &[String], max_chars: usize) -> String {
    let mut out = String::new();
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if a.is_empty() || a.chars().any(char::is_whitespace) {
            out.push('\'');
            out.push_str(&a.replace('\'', "'\\''"));
            out.push('\'');
        } else {
            out.push_str(a);
        }
    }
    // 控制字符不进入界面
    let out: String = out
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if out.chars().count() > max_chars {
        let mut cut: String = out.chars().take(max_chars.saturating_sub(1)).collect();
        cut.push('…');
        cut
    } else {
        out
    }
}

/// 识别 `pid` 的来源。进程已退出时返回 `None`（请求一律拒绝）。
pub fn origin_of(table: &dyn ProcessTable, pid: u32, anchor: NoTtyAnchor) -> Option<Origin> {
    let me = table.info(pid)?;
    // 祖先链：me、父进程、祖父进程……直到 launchd（pid 1）
    let mut chain = vec![me.clone()];
    let mut current = me.clone();
    while chain.len() < MAX_DEPTH && current.ppid > 1 {
        let Some(parent) = table.info(current.ppid) else {
            break;
        };
        if chain.iter().any(|p| p.pid == parent.pid) {
            break;
        }
        chain.push(parent.clone());
        current = parent;
    }
    let app_index = chain
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(i, p)| p.path.as_deref().and_then(app_name).map(|n| (i, n)));
    let parent = chain.get(1);
    let session = match me.tty {
        Some(tty) => {
            // 最早一个使用同一终端的祖先（连续的一段）
            let anchor = chain
                .iter()
                .take_while(|p| p.tty == Some(tty))
                .last()
                .unwrap_or(&me);
            SessionKey {
                tty: Some(tty),
                pid: anchor.pid,
                start_us: anchor.start_us,
            }
        }
        None => {
            let anchor = match (anchor, &app_index) {
                (NoTtyAnchor::App, Some((i, _))) => chain.get(*i),
                _ => parent,
            }
            .unwrap_or(&me);
            SessionKey {
                tty: None,
                pid: anchor.pid,
                start_us: anchor.start_us,
            }
        }
    };
    let command = table
        .args(pid)
        .map(|a| join_command(&a, MAX_COMMAND_CHARS))
        .unwrap_or_else(|| me.name.clone());
    let parent_name = parent.map(|p| p.name.clone()).unwrap_or_default();
    let parent_command = parent
        .filter(|p| !is_shell(&p.name))
        .and_then(|p| table.args(p.pid))
        .map(|a| join_command(&a, 120));
    Some(Origin {
        pid,
        command,
        app: app_index.map(|(_, n)| n),
        parent_name,
        parent_command,
        session,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct Fake(HashMap<u32, (ProcessInfo, Vec<String>)>);

    impl ProcessTable for Fake {
        fn info(&self, pid: u32) -> Option<ProcessInfo> {
            self.0.get(&pid).map(|(i, _)| i.clone())
        }
        fn args(&self, pid: u32) -> Option<Vec<String>> {
            self.0.get(&pid).map(|(_, a)| a.clone())
        }
    }

    fn p(
        pid: u32,
        ppid: u32,
        tty: Option<u32>,
        name: &str,
        path: &str,
        args: &[&str],
    ) -> (u32, (ProcessInfo, Vec<String>)) {
        (
            pid,
            (
                ProcessInfo {
                    pid,
                    ppid,
                    start_us: u64::from(pid) * 1000,
                    tty,
                    name: name.into(),
                    path: Some(path.into()),
                },
                args.iter().map(|s| (*s).to_owned()).collect(),
            ),
        )
    }

    fn iterm() -> Fake {
        Fake(HashMap::from([
            p(
                100,
                1,
                None,
                "iTerm2",
                "/Applications/iTerm.app/Contents/MacOS/iTerm2",
                &["iTerm2"],
            ),
            p(
                200,
                100,
                Some(7),
                "login",
                "/usr/bin/login",
                &["login", "-fp", "me"],
            ),
            p(300, 200, Some(7), "-zsh", "/bin/zsh", &["-zsh"]),
            p(
                400,
                300,
                Some(7),
                "keevo",
                "/usr/local/bin/keevo",
                &[
                    "keevo",
                    "run",
                    "--env-file",
                    ".env.keevo",
                    "--",
                    "npm",
                    "run",
                    "dev",
                ],
            ),
            p(500, 300, Some(7), "git", "/usr/bin/git", &["git", "push"]),
            p(
                600,
                500,
                Some(7),
                "ssh",
                "/usr/bin/ssh",
                &["ssh", "git@github.com", "git-receive-pack 'me/repo.git'"],
            ),
            p(
                700,
                300,
                Some(9),
                "keevo",
                "/usr/local/bin/keevo",
                &["keevo", "read", "x"],
            ),
        ]))
    }

    #[test]
    fn terminal_sessions_are_anchored_at_the_oldest_process_on_the_tty() {
        let t = iterm();
        let cli = origin_of(&t, 400, NoTtyAnchor::Parent).unwrap();
        assert_eq!(cli.app.as_deref(), Some("iTerm"));
        assert_eq!(cli.parent_name, "-zsh");
        assert_eq!(cli.parent_command, None);
        assert_eq!(
            cli.command,
            "keevo run --env-file .env.keevo -- npm run dev"
        );
        assert_eq!(
            cli.session,
            SessionKey {
                tty: Some(7),
                pid: 200,
                start_us: 200_000
            }
        );

        // 同一个标签页里的 ssh 属于同一会话；父进程不是 shell 时显示它的命令行
        let ssh = origin_of(&t, 600, NoTtyAnchor::App).unwrap();
        assert_eq!(ssh.session, cli.session);
        assert_eq!(ssh.parent_command.as_deref(), Some("git push"));
        assert_eq!(
            ssh.command,
            "ssh git@github.com 'git-receive-pack '\\''me/repo.git'\\'''"
        );

        // 另一个终端设备：另一个会话
        let other = origin_of(&t, 700, NoTtyAnchor::Parent).unwrap();
        assert_ne!(other.session, cli.session);
    }

    #[test]
    fn without_a_tty_sessions_are_anchored_at_the_parent_or_the_app() {
        let t = Fake(HashMap::from([
            p(
                10,
                1,
                None,
                "Code",
                "/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
                &["Code"],
            ),
            p(
                20,
                10,
                None,
                "Code Helper",
                "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)",
                &["helper"],
            ),
            p(30, 20, None, "git", "/usr/bin/git", &["git", "fetch"]),
            p(
                40,
                30,
                None,
                "ssh",
                "/usr/bin/ssh",
                &["ssh", "git@github.com"],
            ),
            p(50, 20, None, "keevo", "/opt/keevo", &["keevo", "read", "x"]),
        ]));
        let ssh = origin_of(&t, 40, NoTtyAnchor::App).unwrap();
        assert_eq!(ssh.app.as_deref(), Some("Visual Studio Code"));
        assert_eq!(ssh.session.pid, 20);
        assert_eq!(ssh.session.tty, None);
        let cli = origin_of(&t, 50, NoTtyAnchor::Parent).unwrap();
        assert_eq!(cli.session.pid, 20);
        assert!(origin_of(&t, 99, NoTtyAnchor::Parent).is_none());
    }

    #[test]
    fn commands_are_quoted_and_truncated() {
        let long: Vec<String> = vec!["x".repeat(300)];
        let joined = join_command(&long, 20);
        assert_eq!(joined.chars().count(), 20);
        assert!(joined.ends_with('…'));
        assert_eq!(join_command(&["a\nb".into()], 20), "'a b'");
        assert_eq!(join_command(&["".into()], 20), "''");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reads_the_real_process_table() {
        let me = origin_of(&SystemProcesses, std::process::id(), NoTtyAnchor::Parent).unwrap();
        assert_eq!(me.pid, std::process::id());
        assert!(!me.command.is_empty());
    }
}
