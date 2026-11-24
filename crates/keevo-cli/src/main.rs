//! `keevo`：Keevo 的命令行工具（`spec/cli.md`）。
//!
//! 不持有任何密钥：每次取值都经 Unix socket 向 Keevo.app 请求，第一次在某个终端会话中使用时由 Keevo.app 确认。

mod client;
mod mask;
mod run;

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

use keevo_core::generator::{Recipe, generate};
use keevo_ipc::cli::{
    CreateResult, FieldArg, ItemResult, ItemsResult, Request, SetArg, StatusResult, TotpResult,
};

use crate::client::{CliError, Client};

/// 引用无法解析时附在报错后面的提示（不含"提示："标签，见 [`hint`]）。
const REF_HINT: &str = "在 Keevo 中把指针移到字段上，从右侧的下拉菜单（或右键菜单）选「复制…引用」可以得到准确的引用；keevo item get 保险库/条目 列出字段名。";

/// 一行提示："提示：…"。`color` 时"提示"二字用青色加粗，与报错区分开。
fn hint(text: &str, color: bool) -> String {
    if color {
        format!("\x1b[1;36m提示\x1b[0m：{text}")
    } else {
        format!("提示：{text}")
    }
}

/// 标准错误是终端、没有设置 `NO_COLOR`（https://no-color.org）、`TERM` 不是 `dumb` 时才用颜色。
fn stderr_color() -> bool {
    std::io::stderr().is_terminal()
        && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
        && std::env::var_os("TERM").is_none_or(|t| t != "dumb")
}

const USAGE: &str = "keevo — Keevo 的命令行工具

用法：
  keevo status [--format json]                 连接、锁定与本终端的授权状态
  keevo read <引用> [--reveal] [--newline]      读取一个值，如 keevo://个人/GitHub/密码
  keevo run [--env-file 文件]… [--env KEY=值或引用]… [--no-masking] -- <命令>…
                                                解析引用后注入环境变量并运行命令
  keevo inject [-i 模板] [-o 输出] [--force]    把模板中的 {{ keevo://… }} 替换为值
  keevo item list [--vault 保险库] [--query 搜索词] [--format json]
  keevo item get <保险库/条目 或 ID> [--reveal] [--format json]
  keevo item create --vault 保险库 --type 类型 --title 标题 [--field [分区/]名称=值]…
  keevo item edit <保险库/条目 或 ID> [--title 标题] [--set 名称=值]…
  keevo totp <保险库/条目 或 ID>                当前的一次性密码
  keevo generate [--length N] [--no-symbols] [--no-digits] [--avoid-ambiguous]
  keevo generate --words N [--separator -] [--capitalize] [--number]
  keevo generate --pin N
  keevo lock                                   立即锁定 Keevo
  keevo ssh config                             SSH 配置片段（IdentityAgent）
  keevo ssh-sign …                             经 Keevo 的 SSH Agent 执行 ssh-keygen
                                                （以 keevo-ssh-sign 的名字运行时相同，供 git 的 gpg.ssh.program 使用）

引用：keevo://保险库/条目/字段，或 keevo://保险库/条目/分区/字段；名称有重复时，那一段改用 ID。
  获取引用：在 Keevo 中把指针移到字段（或环境变量的一项）上，从右侧的下拉菜单（或右键菜单）选「复制…引用」。
  也可以用 keevo item get 保险库/条目 查看字段与分区的名称。

退出码：0 成功；1 其他错误；2 用法错误；3 无法连接 Keevo；4 已锁定；5 未授权；6 引用无法解析。
命令的退出码由 keevo run 原样返回。";

fn out(s: &str) {
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(s.as_bytes());
    let _ = o.flush();
}

fn eprint(s: &str) {
    let mut e = std::io::stderr().lock();
    let _ = e.write_all(s.as_bytes());
    let _ = e.write_all(b"\n");
}

/// 参数游标。
struct Args {
    rest: std::collections::VecDeque<String>,
}

impl Args {
    fn next(&mut self) -> Option<String> {
        self.rest.pop_front()
    }

    fn value(&mut self, flag: &str) -> Result<String, CliError> {
        self.next()
            .ok_or_else(|| CliError::Usage(format!("{flag} 需要一个值")))
    }

    fn number(&mut self, flag: &str) -> Result<u32, CliError> {
        self.value(flag)?
            .parse()
            .map_err(|_| CliError::Usage(format!("{flag} 需要一个数字")))
    }
}

fn unknown(arg: &str) -> CliError {
    CliError::Usage(format!("不认识的参数：{arg}（keevo help 查看用法）"))
}

fn json<T: serde::Serialize>(v: &T) -> Result<(), CliError> {
    let s = serde_json::to_string_pretty(v).map_err(|e| CliError::Other(e.to_string()))?;
    out(&s);
    out("\n");
    Ok(())
}

fn main() {
    let mut all = std::env::args();
    let program = all.next().unwrap_or_default();
    let mut rest: std::collections::VecDeque<String> = all.collect();
    // 以 keevo-ssh-sign 的名字运行（软链）：等同于 keevo ssh-sign，供 git 的 gpg.ssh.program 使用
    if std::path::Path::new(&program)
        .file_name()
        .is_some_and(|n| n == "keevo-ssh-sign")
    {
        rest.push_front("ssh-sign".into());
    }
    let code = match dispatch(Args { rest }) {
        Ok(code) => code,
        Err(e) => {
            eprint(&format!("keevo：{e}"));
            // 引用无法解析（退出码 6）：说明怎样得到准确的引用
            if matches!(e, CliError::Ref(_)) {
                eprint(&hint(REF_HINT, stderr_color()));
            }
            e.exit_code()
        }
    };
    std::process::exit(code);
}

fn dispatch(mut args: Args) -> Result<i32, CliError> {
    let Some(cmd) = args.next() else {
        out(USAGE);
        out("\n");
        return Ok(2);
    };
    match cmd.as_str() {
        "help" | "--help" | "-h" => {
            out(USAGE);
            out("\n");
            Ok(0)
        }
        "version" | "--version" | "-V" => {
            out(&format!("keevo {}\n", env!("CARGO_PKG_VERSION")));
            Ok(0)
        }
        "status" => status(args),
        "read" => read(args),
        "run" => run_cmd(args),
        "inject" => inject(args),
        "item" => item(args),
        "totp" => totp(args),
        "generate" => generate_cmd(args),
        "lock" => {
            no_more(&mut args)?;
            Client::connect()?.call::<()>(|id| Request::Lock { id })?;
            eprint("Keevo 已锁定");
            Ok(0)
        }
        "ssh" => ssh(args),
        "ssh-sign" => ssh_sign(args),
        other => Err(unknown(other)),
    }
}

fn no_more(args: &mut Args) -> Result<(), CliError> {
    match args.next() {
        Some(a) => Err(unknown(&a)),
        None => Ok(()),
    }
}

fn format_json(args: &mut Args) -> Result<bool, CliError> {
    match args.value("--format")?.as_str() {
        "json" => Ok(true),
        "human" | "text" => Ok(false),
        other => Err(CliError::Usage(format!("--format 只能是 json：{other}"))),
    }
}

fn status(mut args: Args) -> Result<i32, CliError> {
    let mut as_json = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--format" => as_json = format_json(&mut args)?,
            _ => return Err(unknown(&a)),
        }
    }
    let s: StatusResult = Client::connect()?.call(|id| Request::Status { id })?;
    if as_json {
        json(&s)?;
    } else {
        out(&format!(
            "Keevo：{}\n这个终端：{}\n",
            if s.locked { "已锁定" } else { "已解锁" },
            match s.expires_in {
                Some(secs) if s.authorized =>
                    format!("已授权（闲置 {} 分钟后失效）", secs.div_ceil(60)),
                _ => "未授权（第一次读取时会在 Keevo 中确认）".into(),
            }
        ));
    }
    Ok(0)
}

/// 标准输出是终端时，秘密只在 `--reveal` 时显示（§7）。
fn require_reveal(reveal: bool) -> Result<(), CliError> {
    if !reveal && std::io::stdout().is_terminal() {
        return Err(CliError::Usage(
            "不在终端上显示秘密：加 --reveal 显示，或输出到管道与文件".into(),
        ));
    }
    Ok(())
}

fn read(mut args: Args) -> Result<i32, CliError> {
    let mut reference = None;
    let mut reveal = false;
    let mut newline = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--reveal" => reveal = true,
            "--newline" | "-n" => newline = true,
            _ if reference.is_none() && !a.starts_with("--") => reference = Some(a),
            _ => return Err(unknown(&a)),
        }
    }
    let reference = reference
        .ok_or_else(|| CliError::Usage("缺少引用：keevo read keevo://保险库/条目/字段".into()))?;
    keevo_core::secret_ref::SecretRef::parse(&reference)
        .map_err(|e| CliError::Ref(e.to_string()))?;
    require_reveal(reveal)?;
    let mut client = Client::connect()?;
    let values = run::resolve_all(&mut client, std::slice::from_ref(&reference))?;
    if let Some(v) = values.get(&reference) {
        out(v);
        if newline || std::io::stdout().is_terminal() {
            out("\n");
        }
    }
    Ok(0)
}

fn run_cmd(mut args: Args) -> Result<i32, CliError> {
    let mut vars = Vec::new();
    let mut masking = true;
    let mut command = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--env-file" => {
                let path = args.value("--env-file")?;
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| CliError::Usage(format!("无法读取 {path}：{e}")))?;
                vars.extend(run::parse_env_file(&text, &path)?);
            }
            "--env" => vars.push(run::parse_env_arg(&args.value("--env")?)?),
            "--no-masking" => masking = false,
            "--" => {
                command.extend(args.rest.drain(..));
                break;
            }
            _ => return Err(unknown(&a)),
        }
    }
    if command.is_empty() {
        return Err(CliError::Usage(
            "缺少要运行的命令：keevo run [选项] -- <命令>".into(),
        ));
    }
    let mut client = Client::connect()?;
    run::run(&mut client, vars, &command, masking)
}

fn inject(mut args: Args) -> Result<i32, CliError> {
    let mut input = None;
    let mut output: Option<PathBuf> = None;
    let mut force = false;
    let mut reveal = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "-i" | "--in" => input = Some(args.value("-i")?),
            "-o" | "--out" => output = Some(PathBuf::from(args.value("-o")?)),
            "--force" | "-f" => force = true,
            "--reveal" => reveal = true,
            _ => return Err(unknown(&a)),
        }
    }
    let text = match &input {
        Some(p) => {
            std::fs::read_to_string(p).map_err(|e| CliError::Usage(format!("无法读取 {p}：{e}")))?
        }
        None => {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .map_err(|e| CliError::Other(e.to_string()))?;
            s
        }
    };
    if output.is_none() {
        require_reveal(reveal)?;
    }
    let mut client = Client::connect()?;
    let rendered = run::render(&mut client, &text)?;
    match output {
        Some(path) => run::write_private(&path, &rendered, force)?,
        None => out(&rendered),
    }
    Ok(0)
}

fn item(mut args: Args) -> Result<i32, CliError> {
    let sub = args
        .next()
        .ok_or_else(|| CliError::Usage("keevo item list|get|create|edit".into()))?;
    match sub.as_str() {
        "list" | "ls" => {
            let (mut vault, mut query, mut as_json) = (None, None, false);
            while let Some(a) = args.next() {
                match a.as_str() {
                    "--vault" => vault = Some(args.value("--vault")?),
                    "--query" | "-q" => query = Some(args.value("--query")?),
                    "--format" => as_json = format_json(&mut args)?,
                    _ => return Err(unknown(&a)),
                }
            }
            let r: ItemsResult =
                Client::connect()?.call(|id| Request::Items { id, vault, query })?;
            if as_json {
                json(&r)?;
            } else {
                for i in &r.items {
                    out(&format!(
                        "{}\t{}\t{}\t{}\n",
                        i.title, i.item_type, i.vault, i.id
                    ));
                }
            }
            Ok(0)
        }
        "get" => {
            let (mut target, mut reveal, mut as_json) = (None, false, false);
            while let Some(a) = args.next() {
                match a.as_str() {
                    "--reveal" => reveal = true,
                    "--format" => as_json = format_json(&mut args)?,
                    _ if target.is_none() && !a.starts_with("--") => target = Some(a),
                    _ => return Err(unknown(&a)),
                }
            }
            let item =
                target.ok_or_else(|| CliError::Usage("缺少条目：保险库/条目 或 ID".into()))?;
            let r: ItemResult = Client::connect()?.call(|id| Request::Item { id, item, reveal })?;
            if as_json {
                json(&r)?;
            } else {
                out(&format!("{}（{} · {}）\n", r.title, r.item_type, r.vault));
                let mut section: Option<&str> = None;
                for f in &r.fields {
                    if f.section.as_deref() != section {
                        section = f.section.as_deref();
                        if let Some(s) = section {
                            out(&format!("\n[{s}]\n"));
                        }
                    }
                    let value = match (&f.value, f.concealed) {
                        (Some(v), _) => v.replace('\n', "\n    "),
                        (None, true) => "••••••（加 --reveal 显示）".into(),
                        (None, false) => String::new(),
                    };
                    out(&format!("  {}：{}\n", f.label, value));
                }
                if !r.tags.is_empty() {
                    out(&format!("\n标签：{}\n", r.tags.join("、")));
                }
            }
            Ok(0)
        }
        "create" => {
            let (mut vault, mut item_type, mut title, mut fields) = (None, None, None, Vec::new());
            while let Some(a) = args.next() {
                match a.as_str() {
                    "--vault" => vault = Some(args.value("--vault")?),
                    "--type" => item_type = Some(args.value("--type")?),
                    "--title" => title = Some(args.value("--title")?),
                    "--field" => {
                        let spec = args.value("--field")?;
                        let (name, value) = spec.split_once('=').ok_or_else(|| {
                            CliError::Usage(format!("--field 应为 [分区/]名称=值：{spec}"))
                        })?;
                        let (section, label) = match name.split_once('/') {
                            Some((s, l)) => (Some(s.to_owned()), l.to_owned()),
                            None => (None, name.to_owned()),
                        };
                        fields.push(FieldArg {
                            section,
                            label,
                            value: value.to_owned(),
                        });
                    }
                    _ => return Err(unknown(&a)),
                }
            }
            let need = |v: Option<String>, flag: &str| {
                v.ok_or_else(|| CliError::Usage(format!("缺少 {flag}")))
            };
            let (vault, item_type, title) = (
                need(vault, "--vault")?,
                need(item_type, "--type")?,
                need(title, "--title")?,
            );
            let r: CreateResult = Client::connect()?.call(|id| Request::Create {
                id,
                vault,
                item_type,
                title,
                fields,
            })?;
            out(&format!("{}\n", r.id));
            Ok(0)
        }
        "edit" => {
            let (mut target, mut title, mut set) = (None, None, Vec::new());
            while let Some(a) = args.next() {
                match a.as_str() {
                    "--title" => title = Some(args.value("--title")?),
                    "--set" => {
                        let spec = args.value("--set")?;
                        let (field, value) = spec.split_once('=').ok_or_else(|| {
                            CliError::Usage(format!("--set 应为 名称=值：{spec}"))
                        })?;
                        set.push(SetArg {
                            field: field.to_owned(),
                            value: value.to_owned(),
                        });
                    }
                    _ if target.is_none() && !a.starts_with("--") => target = Some(a),
                    _ => return Err(unknown(&a)),
                }
            }
            let item =
                target.ok_or_else(|| CliError::Usage("缺少条目：保险库/条目 或 ID".into()))?;
            if title.is_none() && set.is_empty() {
                return Err(CliError::Usage("没有要修改的内容：--title 或 --set".into()));
            }
            Client::connect()?.call::<()>(|id| Request::Edit {
                id,
                item,
                title,
                set,
            })?;
            Ok(0)
        }
        other => Err(unknown(other)),
    }
}

fn totp(mut args: Args) -> Result<i32, CliError> {
    let (mut target, mut as_json) = (None, false);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--format" => as_json = format_json(&mut args)?,
            _ if target.is_none() && !a.starts_with("--") => target = Some(a),
            _ => return Err(unknown(&a)),
        }
    }
    let item = target.ok_or_else(|| CliError::Usage("缺少条目：保险库/条目 或 ID".into()))?;
    let r: TotpResult = Client::connect()?.call(|id| Request::Totp { id, item })?;
    if as_json {
        json(&r)?;
    } else {
        out(&format!("{}\n", r.code));
        if std::io::stderr().is_terminal() {
            eprint(&format!("（{} 秒后更新）", r.remaining));
        }
    }
    Ok(0)
}

fn generate_cmd(mut args: Args) -> Result<i32, CliError> {
    let mut recipe = Recipe::Password {
        length: 20,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: true,
        avoid_ambiguous: false,
    };
    while let Some(a) = args.next() {
        match (a.as_str(), &mut recipe) {
            ("--length", Recipe::Password { length, .. }) => *length = args.number("--length")?,
            ("--no-symbols", Recipe::Password { symbols, .. }) => *symbols = false,
            ("--no-digits", Recipe::Password { digits, .. }) => *digits = false,
            ("--no-uppercase", Recipe::Password { uppercase, .. }) => *uppercase = false,
            ("--no-lowercase", Recipe::Password { lowercase, .. }) => *lowercase = false,
            (
                "--avoid-ambiguous",
                Recipe::Password {
                    avoid_ambiguous, ..
                },
            ) => {
                *avoid_ambiguous = true;
            }
            ("--words", _) => {
                recipe = Recipe::Passphrase {
                    words: args.number("--words")?,
                    separator: "-".into(),
                    capitalize: false,
                    include_number: false,
                };
            }
            ("--separator", Recipe::Passphrase { separator, .. }) => {
                *separator = args.value("--separator")?;
            }
            ("--capitalize", Recipe::Passphrase { capitalize, .. }) => *capitalize = true,
            ("--number", Recipe::Passphrase { include_number, .. }) => *include_number = true,
            ("--pin", _) => {
                recipe = Recipe::Pin {
                    length: args.number("--pin")?,
                };
            }
            _ => return Err(unknown(&a)),
        }
    }
    let generated = generate(&recipe).map_err(|_| {
        CliError::Usage(
            "参数超出范围：密码 8–128 位、口令 3–20 个单词、PIN 4–12 位，且至少选一类字符".into(),
        )
    })?;
    out(&generated.value);
    out("\n");
    if std::io::stderr().is_terminal() {
        // 与 Keevo.app 的生成器同一划分；不显示熵的数值
        let level = match generated.entropy_bits {
            b if b < 40.0 => "弱",
            b if b < 60.0 => "一般",
            b if b < 80.0 => "强",
            _ => "很强",
        };
        eprint(&format!("强度：{level}"));
    }
    Ok(0)
}

fn ssh(mut args: Args) -> Result<i32, CliError> {
    match args.next().as_deref() {
        Some("config") => {
            no_more(&mut args)?;
            let link =
                keevo_ipc::paths::agent_link_path().map_err(|e| CliError::Other(e.to_string()))?;
            let home = std::env::var("HOME").unwrap_or_default();
            let shown = link
                .to_str()
                .and_then(|p| p.strip_prefix(&home))
                .map_or_else(|| link.display().to_string(), |p| format!("~{p}"));
            out(&format!(
                "# 加到 ~/.ssh/config 的开头：经 Keevo 的 SSH Agent 使用保险库中的密钥\nHost *\n  IdentityAgent \"{shown}\"\n"
            ));
            Ok(0)
        }
        Some(other) => Err(unknown(other)),
        None => Err(CliError::Usage("keevo ssh config".into())),
    }
}

/// Git 的 `gpg.ssh.program`：把 `SSH_AUTH_SOCK` 指向 Keevo 的 Agent，再执行系统的 ssh-keygen（§7）。
fn ssh_sign(args: Args) -> Result<i32, CliError> {
    use std::os::unix::process::CommandExt;
    let sock = keevo_ipc::paths::agent_socket_path().map_err(|e| CliError::Other(e.to_string()))?;
    let err = std::process::Command::new("/usr/bin/ssh-keygen")
        .args(args.rest)
        .env("SSH_AUTH_SOCK", sock)
        .exec();
    Err(CliError::Other(format!("无法运行 ssh-keygen：{err}")))
}

#[cfg(test)]
mod tests {
    use super::{REF_HINT, hint};

    #[test]
    fn hint_is_plain_without_color() {
        assert_eq!(hint("x", false), "提示：x");
        assert_eq!(hint("x", true), "\x1b[1;36m提示\x1b[0m：x");
        assert!(hint(REF_HINT, false).starts_with("提示：在 Keevo 中把指针移到字段上"));
    }
}
