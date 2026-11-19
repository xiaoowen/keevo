//! `keevo run` 与 `keevo inject`（`spec/cli.md` §7）。

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{IsTerminal, Read, Write};
use std::os::fd::AsFd;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use keevo_ipc::cli::{MAX_REFS, Request, ResolveResult};
use zeroize::Zeroizing;

use crate::client::{CliError, Client};
use crate::mask::Masker;

const SCHEME: &str = "keevo://";

/// 一个环境变量：原样的值，或待解析的引用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnvValue {
    /// 原样使用。
    Literal(String),
    /// `keevo://` 引用。
    Ref(String),
}

fn classify(value: &str) -> EnvValue {
    if value.starts_with(SCHEME) {
        EnvValue::Ref(value.to_owned())
    } else {
        EnvValue::Literal(value.to_owned())
    }
}

/// 解析 `--env-file`：每行 `KEY=VALUE`，忽略空行与 `#` 开头的行，允许行首 `export `，去掉两端成对的引号。
///
/// # Errors
/// 某一行没有 `=` 或变量名不合法时返回用法错误，附行号。
pub(crate) fn parse_env_file(text: &str, name: &str) -> Result<Vec<(String, EnvValue)>, CliError> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, value)) = line.split_once('=') else {
            return Err(CliError::Usage(format!(
                "{name} 第 {} 行应为 KEY=VALUE",
                n.saturating_add(1)
            )));
        };
        let key = key.trim();
        if !valid_key(key) {
            return Err(CliError::Usage(format!(
                "{name} 第 {} 行的变量名「{key}」不合法",
                n.saturating_add(1)
            )));
        }
        out.push((key.to_owned(), classify(unquote(value.trim()))));
    }
    Ok(out)
}

fn unquote(v: &str) -> &str {
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return v.get(1..v.len().saturating_sub(1)).unwrap_or(v);
        }
    }
    v
}

fn valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// 解析 `--env KEY=VALUE`。
///
/// # Errors
/// 没有 `=` 或变量名不合法时返回用法错误。
pub(crate) fn parse_env_arg(arg: &str) -> Result<(String, EnvValue), CliError> {
    let (key, value) = arg
        .split_once('=')
        .ok_or_else(|| CliError::Usage(format!("--env 应为 KEY=VALUE：{arg}")))?;
    if !valid_key(key) {
        return Err(CliError::Usage(format!("变量名「{key}」不合法")));
    }
    Ok((key.to_owned(), classify(value)))
}

/// 一次解析全部引用（一个 `resolve` 请求，最多 256 个一批）。任何一个失败都返回错误，列出全部失败。
///
/// # Errors
/// 连接、授权或解析失败。
pub(crate) fn resolve_all(
    client: &mut Client,
    refs: &[String],
) -> Result<BTreeMap<String, Zeroizing<String>>, CliError> {
    let mut unique: Vec<String> = refs.to_vec();
    unique.sort();
    unique.dedup();
    let mut out = BTreeMap::new();
    let mut failures = Vec::new();
    for chunk in unique.chunks(MAX_REFS) {
        let result: ResolveResult = client.call(|id| Request::Resolve {
            id,
            refs: chunk.to_vec(),
        })?;
        for (r, mut v) in chunk.iter().zip(result.values) {
            match v.value.take() {
                Some(value) => {
                    out.insert(r.clone(), Zeroizing::new(value));
                }
                None => failures.push(format!(
                    "{r}：{}",
                    v.message.or(v.error).unwrap_or_default()
                )),
            }
        }
    }
    if failures.is_empty() {
        Ok(out)
    } else {
        Err(CliError::Ref(failures.join("\n")))
    }
}

/// 运行子进程。`masking` 为假时子进程直接继承终端。返回子进程的退出码。
///
/// # Errors
/// 连接、解析或启动子进程失败。
pub(crate) fn run(
    client: &mut Client,
    vars: Vec<(String, EnvValue)>,
    command: &[String],
    masking: bool,
) -> Result<i32, CliError> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| CliError::Usage("缺少要运行的命令：keevo run [选项] -- <命令>".into()))?;
    // 当前环境中值为 keevo:// 的变量也解析；命令行给出的覆盖它们
    let mut merged: BTreeMap<String, EnvValue> = std::env::vars()
        .filter(|(_, v)| v.starts_with(SCHEME))
        .map(|(k, v)| (k, EnvValue::Ref(v)))
        .collect();
    for (k, v) in vars {
        merged.insert(k, v);
    }
    let refs: Vec<String> = merged
        .values()
        .filter_map(|v| match v {
            EnvValue::Ref(r) => Some(r.clone()),
            EnvValue::Literal(_) => None,
        })
        .collect();
    let resolved = if refs.is_empty() {
        BTreeMap::new()
    } else {
        resolve_all(client, &refs)?
    };
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in &merged {
        match v {
            EnvValue::Literal(s) => cmd.env(k, s),
            EnvValue::Ref(r) => cmd.env(k, resolved.get(r).map_or("", |s| s.as_str())),
        };
    }
    let masker_values: Vec<&str> = resolved.values().map(|s| s.as_str()).collect();
    let masker = Masker::new(masker_values.iter().copied());
    if !masking || masker.is_empty() {
        let status = cmd
            .status()
            .map_err(|e| CliError::Other(format!("无法运行 {program}：{e}")))?;
        return Ok(exit_code(status));
    }
    // 输出到终端的那一路改用伪终端（§7）：子进程看到的仍是终端，保留颜色、进度条与行缓冲；
    // 输出被重定向时用管道。打不开伪终端时退回管道
    let out_pty = std::io::stdout()
        .is_terminal()
        .then(|| Pty::open(std::io::stdout()).ok())
        .flatten();
    let err_pty = std::io::stderr()
        .is_terminal()
        .then(|| Pty::open(std::io::stderr()).ok())
        .flatten();
    let mut resize = Vec::new();
    let out_master = attach(&mut cmd, out_pty, Stream::Out, &mut resize);
    let err_master = attach(&mut cmd, err_pty, Stream::Err, &mut resize);
    let mut child = cmd
        .spawn()
        .map_err(|e| CliError::Other(format!("无法运行 {program}：{e}")))?;
    // 关闭父进程中的从端：子进程（及其后代）全部退出后，主端才会读到结束
    drop(cmd);
    let stop = Arc::new(AtomicBool::new(false));
    let watcher = (!resize.is_empty()).then(|| {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || follow_terminal_size(resize, &stop))
    });
    let out_source: Option<Box<dyn Read + Send>> = match out_master {
        Some(m) => Some(Box::new(m)),
        None => child.stdout.take().map(boxed),
    };
    let err_source: Option<Box<dyn Read + Send>> = match err_master {
        Some(m) => Some(Box::new(m)),
        None => child.stderr.take().map(boxed),
    };
    let out = out_source.map(|s| {
        let m = Masker::new(masker_values.iter().copied());
        std::thread::spawn(move || pump(s, std::io::stdout(), m))
    });
    let err = err_source.map(|s| {
        let m = Masker::new(masker_values.iter().copied());
        std::thread::spawn(move || pump(s, std::io::stderr(), m))
    });
    drop(resolved);
    let status = child.wait().map_err(|e| CliError::Other(e.to_string()));
    stop.store(true, Ordering::Relaxed);
    if let Some(w) = watcher {
        let _ = w.join();
    }
    let status = status?;
    for h in [out, err].into_iter().flatten() {
        let _ = h.join();
    }
    Ok(exit_code(status))
}

fn boxed<R: Read + Send + 'static>(r: R) -> Box<dyn Read + Send> {
    Box::new(r)
}

/// 一个伪终端。子进程的一路输出连到从端；keevo 从主端读取，遮蔽后写出。
struct Pty {
    master: File,
    slave: File,
    /// 主端的另一个句柄：随 keevo 所在终端的窗口大小调整伪终端的大小。
    resize: File,
}

impl Pty {
    /// 打开一个伪终端，窗口大小与 `like`（keevo 的输出所在的终端）一致。
    fn open(like: impl AsFd) -> std::io::Result<Self> {
        use rustix::fs::{Mode, OFlags};
        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
        // macOS 的 posix_openpt 不支持 O_CLOEXEC：之后立即设置，主端不传给子进程
        rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC)?;
        grantpt(&master)?;
        unlockpt(&master)?;
        let name = ptsname(&master, Vec::new())?;
        let slave = rustix::fs::open(
            name.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if let Ok(size) = rustix::termios::tcgetwinsize(&like) {
            let _ = rustix::termios::tcsetwinsize(&slave, size);
        }
        let master = File::from(master);
        Ok(Self {
            resize: master.try_clone()?,
            master,
            slave: File::from(slave),
        })
    }
}

#[derive(Clone, Copy)]
enum Stream {
    Out,
    Err,
}

/// 把子进程的一路输出接到伪终端的从端（`pty` 为 `None` 时接到管道）。返回要读取的主端；
/// 主端的另一个句柄放进 `resize`，用来跟随窗口大小。
fn attach(
    cmd: &mut Command,
    pty: Option<Pty>,
    stream: Stream,
    resize: &mut Vec<(Stream, File)>,
) -> Option<Master> {
    let Some(pty) = pty else {
        match stream {
            Stream::Out => cmd.stdout(Stdio::piped()),
            Stream::Err => cmd.stderr(Stdio::piped()),
        };
        return None;
    };
    match stream {
        Stream::Out => cmd.stdout(Stdio::from(pty.slave)),
        Stream::Err => cmd.stderr(Stdio::from(pty.slave)),
    };
    resize.push((stream, pty.resize));
    Some(Master(pty.master))
}

/// 子进程运行期间，每 200 毫秒把 keevo 所在终端的窗口大小同步到伪终端：
/// 子进程收到终端的 SIGWINCH 后，查询到的是新的大小。
fn follow_terminal_size(ptys: Vec<(Stream, File)>, stop: &AtomicBool) {
    let mut last: Vec<Option<(u16, u16)>> = vec![None; ptys.len()];
    while !stop.load(Ordering::Relaxed) {
        for ((stream, master), last) in ptys.iter().zip(last.iter_mut()) {
            let size = match stream {
                Stream::Out => rustix::termios::tcgetwinsize(std::io::stdout()),
                Stream::Err => rustix::termios::tcgetwinsize(std::io::stderr()),
            };
            if let Ok(size) = size {
                let now = (size.ws_row, size.ws_col);
                if *last != Some(now) {
                    *last = Some(now);
                    let _ = rustix::termios::tcsetwinsize(master, size);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// 伪终端的主端。
struct Master(File);

impl Read for Master {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.0.read(buf) {
            // 从端全部关闭后，读取主端返回 EIO（macOS 与 Linux）：即结束
            Err(e) if e.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) => Ok(0),
            other => other,
        }
    }
}

/// 被信号终止时为 128 + 信号编号（§7）。
fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|s| s.saturating_add(128)))
        .unwrap_or(1)
}

/// 把子进程的一路输出经遮蔽后写出。留着待定的字节在 100 毫秒内没有新数据时写出。
fn pump<R: Read + Send + 'static, W: Write>(mut from: R, mut to: W, mut masker: Masker) {
    let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match from.read(&mut buf) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Ok(0) | Err(_) => {
                    let _ = tx.send(None);
                    break;
                }
                Ok(n) => {
                    if tx.send(buf.get(..n).map(<[u8]>::to_vec)).is_err() {
                        break;
                    }
                }
            }
        }
    });
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Some(chunk)) => {
                let _ = to.write_all(&masker.push(&chunk));
                let _ = to.flush();
            }
            Ok(None) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = to.write_all(&masker.flush());
                let _ = to.flush();
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let pending = masker.flush();
                if !pending.is_empty() {
                    let _ = to.write_all(&pending);
                    let _ = to.flush();
                }
            }
        }
    }
}

/// 模板中的引用：`{{ keevo://… }}`。返回 (起点, 终点, 引用) 列表。
#[must_use]
pub(crate) fn template_refs(text: &str) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(open) = text.get(from..).and_then(|t| t.find("{{")) {
        let start = from.saturating_add(open);
        let inner_start = start.saturating_add(2);
        let Some(close) = text.get(inner_start..).and_then(|t| t.find("}}")) else {
            break;
        };
        let end = inner_start.saturating_add(close).saturating_add(2);
        let inner = text
            .get(inner_start..inner_start.saturating_add(close))
            .unwrap_or("")
            .trim();
        if inner.starts_with(SCHEME) && !inner.contains(char::is_whitespace) {
            out.push((start, end, inner.to_owned()));
            from = end;
        } else {
            from = inner_start;
        }
    }
    out
}

/// 渲染模板。
///
/// # Errors
/// 连接、解析失败。
pub(crate) fn render(client: &mut Client, text: &str) -> Result<Zeroizing<String>, CliError> {
    let found = template_refs(text);
    let refs: Vec<String> = found.iter().map(|(_, _, r)| r.clone()).collect();
    let resolved = if refs.is_empty() {
        BTreeMap::new()
    } else {
        resolve_all(client, &refs)?
    };
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    let mut last = 0usize;
    for (start, end, r) in &found {
        out.push_str(text.get(last..*start).unwrap_or(""));
        out.push_str(resolved.get(r).map_or("", |s| s.as_str()));
        last = *end;
    }
    out.push_str(text.get(last..).unwrap_or(""));
    Ok(out)
}

/// 以 0600 写入输出文件；已存在时需要 `force`。
///
/// # Errors
/// 文件已存在且没有 `force`，或写入失败。
pub(crate) fn write_private(path: &Path, content: &str, force: bool) -> Result<(), CliError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).mode(0o600);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    let mut f = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::Usage(format!("{} 已存在：加 --force 覆盖", path.display()))
        } else {
            CliError::Other(format!("无法写入 {}：{e}", path.display()))
        }
    })?;
    // 覆盖已有文件时也收紧权限
    let _ = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    f.write_all(content.as_bytes())
        .map_err(|e| CliError::Other(format!("无法写入 {}：{e}", path.display())))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn env_files() {
        let text = "# 注释\n\nexport A=1\nB = \"keevo://dev/x/y\"\nC='quoted value'\nD=keevo://dev/a%20b/c\n";
        let vars = parse_env_file(text, ".env.keevo").unwrap();
        assert_eq!(
            vars,
            vec![
                ("A".into(), EnvValue::Literal("1".into())),
                ("B".into(), EnvValue::Ref("keevo://dev/x/y".into())),
                ("C".into(), EnvValue::Literal("quoted value".into())),
                ("D".into(), EnvValue::Ref("keevo://dev/a%20b/c".into())),
            ]
        );
        assert!(
            matches!(parse_env_file("NOPE\n", "f"), Err(CliError::Usage(m)) if m.contains("第 1 行"))
        );
        assert!(parse_env_file("1A=x\n", "f").is_err());
        assert!(parse_env_arg("X=keevo://a/b/c").is_ok());
        assert!(parse_env_arg("X").is_err());
    }

    #[test]
    fn template_references() {
        let t = "url: {{ keevo://dev/db/connection_string }}\nkey: {{keevo://dev/api/Secret}}\nother: {{ not a ref }} {{";
        let found = template_refs(t);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].2, "keevo://dev/db/connection_string");
        assert_eq!(&t[found[1].0..found[1].1], "{{keevo://dev/api/Secret}}");
    }

    /// 伪终端（§7）：子进程的标准输出是终端，输出照常遮蔽；窗口大小取自 keevo 所在的终端。
    #[test]
    fn pseudo_terminal_keeps_the_terminal_and_masks_output() {
        // 用另一个伪终端充当"keevo 所在的终端"，设定一个特别的窗口大小
        let outer = Pty::open(std::io::stdin()).unwrap();
        let size = rustix::termios::Winsize {
            ws_row: 33,
            ws_col: 97,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        rustix::termios::tcsetwinsize(&outer.slave, size).unwrap();
        let pty = Pty::open(&outer.slave).unwrap();
        let mut cmd = Command::new("/bin/sh");
        cmd.args([
            "-c",
            "if [ -t 1 ]; then echo tty; fi; stty size <&1; printf 'token=s3cret-value\\n'",
        ]);
        let mut resize = Vec::new();
        let master = attach(&mut cmd, Some(pty), Stream::Out, &mut resize).unwrap();
        assert_eq!(resize.len(), 1);
        let mut child = cmd.spawn().unwrap();
        drop(cmd);
        let mut out = Vec::new();
        pump(master, &mut out, Masker::new(["s3cret-value"]));
        assert!(child.wait().unwrap().success());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "tty\r\n33 97\r\ntoken=<concealed by keevo>\r\n"
        );
    }

    #[test]
    fn private_files_are_not_overwritten_by_default() {
        let dir = std::env::temp_dir().join(format!("keevo-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("out");
        let _ = std::fs::remove_file(&p);
        write_private(&p, "a", false).unwrap();
        assert!(write_private(&p, "b", false).is_err());
        write_private(&p, "c", true).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "c");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
