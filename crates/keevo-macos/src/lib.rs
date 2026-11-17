//! macOS 平台集成：进程代码签名校验（`spec/ipc.md` §3）。
//!
//! - Vault Service 用 [`verify_socket_peer`] 校验 Unix socket 对端（native host、CLI）。
//! - native host 用 [`verify_pid`] 校验父进程是否为已知浏览器。
//!
//! 校验基于内核提供的 audit token 或 pid，再由 Security.framework 按代码签名要求
//! （Code Signing Requirement Language）判定。整个 workspace 只有本 crate 允许 `unsafe`，
//! 且仅限 [`peer_audit_token`] 中一次 `getsockopt` 调用。

#![cfg_attr(not(target_os = "macos"), allow(unused))]

use core::fmt;

/// 已知浏览器的代码签名要求（§3.2）。只收录在构建机上用 `codesign -dv` 核实过的 Team ID。
///
/// | 浏览器 | Bundle ID | Team ID | 核实日期 |
/// |---|---|---|---|
/// | Google Chrome | `com.google.Chrome` | `EQHXZ8M8AV` | 2026-11-17 |
pub const KNOWN_BROWSERS: &[(&str, &str)] = &[(
    "com.google.Chrome",
    r#"anchor apple generic and identifier "com.google.Chrome" and certificate leaf[subject.OU] = "EQHXZ8M8AV""#,
)];

/// 代码签名校验错误。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodeSignError {
    /// 签名要求的语法错误。
    BadRequirement,
    /// 无法取得对端进程的代码对象（进程已退出等）。
    NoSuchProcess,
    /// 系统调用失败。
    Io(String),
    /// 当前平台不支持。
    Unsupported,
}

impl fmt::Display for CodeSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequirement => f.write_str("bad code signing requirement"),
            Self::NoSuchProcess => f.write_str("process not found"),
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Unsupported => f.write_str("unsupported platform"),
        }
    }
}

impl std::error::Error for CodeSignError {}

#[cfg(target_os = "macos")]
mod imp {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::str::FromStr;

    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement,
    };

    use super::CodeSignError;

    /// 读取 Unix socket 对端的 audit token（`LOCAL_PEERTOKEN`）。
    ///
    /// audit token 由内核在连接建立时记录，不会因对端 pid 被复用而指向另一个进程。
    #[allow(unsafe_code)]
    pub(super) fn peer_audit_token(stream: &UnixStream) -> Result<[u8; 32], CodeSignError> {
        let mut token = [0u8; 32];
        let mut len =
            libc::socklen_t::try_from(token.len()).map_err(|_| CodeSignError::Io("len".into()))?;
        // SAFETY: `fd` 在 `stream` 存活期间有效；`token` 是 32 字节的可写缓冲区，`len` 如实给出其长度，
        // 内核最多写入 `len` 字节并回写实际长度。调用不保留任何指针。
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERTOKEN,
                token.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(CodeSignError::Io(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        if usize::try_from(len).ok() != Some(token.len()) {
            return Err(CodeSignError::Io("unexpected audit token length".into()));
        }
        Ok(token)
    }

    fn check(code: &SecCode, requirement: &str) -> Result<bool, CodeSignError> {
        let req =
            SecRequirement::from_str(requirement).map_err(|_| CodeSignError::BadRequirement)?;
        // 动态校验：检查正在运行的进程，而不只是磁盘上的文件
        Ok(code.check_validity(Flags::NONE, &req).is_ok())
    }

    pub(super) fn verify_audit_token(
        token: &[u8; 32],
        requirement: &str,
    ) -> Result<bool, CodeSignError> {
        let data = CFData::from_buffer(token);
        let mut attrs = GuestAttributes::new();
        attrs.set_audit_token(data.as_concrete_TypeRef());
        let code = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE)
            .map_err(|_| CodeSignError::NoSuchProcess)?;
        check(&code, requirement)
    }

    pub(super) fn verify_pid(pid: u32, requirement: &str) -> Result<bool, CodeSignError> {
        let pid = libc::pid_t::try_from(pid).map_err(|_| CodeSignError::NoSuchProcess)?;
        let mut attrs = GuestAttributes::new();
        attrs.set_pid(pid);
        let code = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE)
            .map_err(|_| CodeSignError::NoSuchProcess)?;
        check(&code, requirement)
    }

    pub(super) fn verify_self(requirement: &str) -> Result<bool, CodeSignError> {
        let code = SecCode::for_self(Flags::NONE).map_err(|_| CodeSignError::NoSuchProcess)?;
        check(&code, requirement)
    }
}

/// 校验 Unix socket 对端进程是否满足代码签名要求。
///
/// # Errors
/// 要求语法错误、对端已退出或系统调用失败时返回错误；调用方应一律视为校验失败。
pub fn verify_socket_peer(
    stream: &std::os::unix::net::UnixStream,
    requirement: &str,
) -> Result<bool, CodeSignError> {
    #[cfg(target_os = "macos")]
    {
        let token = imp::peer_audit_token(stream)?;
        imp::verify_audit_token(&token, requirement)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(CodeSignError::Unsupported)
    }
}

/// 校验指定 pid 的进程是否满足代码签名要求。用于 native host 校验父进程。
///
/// # Errors
/// 同 [`verify_socket_peer`]。
pub fn verify_pid(pid: u32, requirement: &str) -> Result<bool, CodeSignError> {
    #[cfg(target_os = "macos")]
    {
        imp::verify_pid(pid, requirement)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(CodeSignError::Unsupported)
    }
}

/// 当前进程的父进程是否为 [`KNOWN_BROWSERS`] 中的某个浏览器；是则返回其 Bundle ID。
///
/// # Errors
/// 同 [`verify_socket_peer`]。
pub fn parent_browser() -> Result<Option<&'static str>, CodeSignError> {
    let ppid = std::os::unix::process::parent_id();
    for (bundle_id, requirement) in KNOWN_BROWSERS {
        if verify_pid(ppid, requirement)? {
            return Ok(Some(bundle_id));
        }
    }
    Ok(None)
}

/// 当前进程是否满足代码签名要求（测试与自检用）。
///
/// # Errors
/// 同 [`verify_socket_peer`]。
pub fn verify_self(requirement: &str) -> Result<bool, CodeSignError> {
    #[cfg(target_os = "macos")]
    {
        imp::verify_self(requirement)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(CodeSignError::Unsupported)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn requirements_are_evaluated_against_the_running_process() {
        assert_eq!(verify_self("always"), Ok(true));
        assert_eq!(verify_self("never"), Ok(false));
        // 测试二进制只有链接器生成的临时签名，不可能满足 Apple 根证书的要求
        assert_eq!(verify_self("anchor apple generic"), Ok(false));
        assert_eq!(
            verify_self("this is not a requirement"),
            Err(CodeSignError::BadRequirement)
        );
    }

    #[test]
    fn socket_peer_is_identified_by_audit_token() {
        let (a, _b) = UnixStream::pair().unwrap();
        // 对端就是本进程
        assert_eq!(verify_socket_peer(&a, "always"), Ok(true));
        assert_eq!(verify_socket_peer(&a, "never"), Ok(false));
        assert_eq!(verify_socket_peer(&a, "anchor apple generic"), Ok(false));
    }

    #[test]
    fn system_processes_satisfy_apple_anchor_but_not_chrome() {
        // launchd（pid 1）由 Apple 签名
        assert_eq!(verify_pid(1, "anchor apple"), Ok(true));
        assert_eq!(verify_pid(1, KNOWN_BROWSERS[0].1), Ok(false));
        // 测试进程的父进程（cargo）不是浏览器
        assert_eq!(parent_browser(), Ok(None));
    }
}
