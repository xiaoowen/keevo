//! 进程表的只读查询（`spec/cli.md` §5、`spec/ssh-agent.md` §4.2）：父进程、控制终端、启动时间、
//! 可执行文件路径与命令行。用于识别 CLI 与 SSH 请求的来源，以及按终端会话划分授权。
//!
//! 这里的每个 unsafe 块都只是调用一个只读的系统接口，把结果写进本函数拥有的缓冲区，不保留任何指针。

/// 一个进程的基本信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// 进程 ID。
    pub pid: u32,
    /// 父进程 ID。
    pub ppid: u32,
    /// 启动时间（Unix 微秒）。与 pid 一起唯一标识一个进程实例（pid 会被复用）。
    pub start_us: u64,
    /// 控制终端的设备号；没有控制终端时为 `None`。
    pub tty: Option<u32>,
    /// 进程名（最多 32 字节，取自内核）。
    pub name: String,
    /// 可执行文件路径。
    pub path: Option<String>,
}

/// 由 Unix socket 对端的 audit token 得到 pid（`audit_token_to_pid`：`val[5]`）。
/// audit token 在连接建立时由内核记录。
///
/// # Errors
/// 系统调用失败时返回错误。
pub fn socket_peer_pid(
    stream: &std::os::unix::net::UnixStream,
) -> Result<u32, crate::CodeSignError> {
    #[cfg(target_os = "macos")]
    {
        let token = crate::imp::peer_audit_token(stream)?;
        let bytes: [u8; 4] = token
            .get(20..24)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| crate::CodeSignError::Io("audit token".into()))?;
        Ok(u32::from_ne_bytes(bytes))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = stream;
        Err(crate::CodeSignError::Unsupported)
    }
}

/// 读取进程信息。进程不存在或无权读取时返回 `None`。
#[must_use]
pub fn process_info(pid: u32) -> Option<ProcessInfo> {
    #[cfg(target_os = "macos")]
    {
        imp::info(pid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

/// 读取进程的命令行参数（`argv`）。进程不存在或无权读取时返回 `None`。
#[must_use]
pub fn process_args(pid: u32) -> Option<Vec<String>> {
    #[cfg(target_os = "macos")]
    {
        imp::args(pid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::ProcessInfo;

    /// 没有控制终端时 `e_tdev` 的值（`NODEV`）。
    const NODEV: u32 = u32::MAX;

    fn c_name(raw: &[libc::c_char]) -> String {
        let bytes: Vec<u8> = raw
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c.to_ne_bytes()[0])
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[allow(unsafe_code)]
    pub(super) fn info(pid: u32) -> Option<ProcessInfo> {
        let c_pid = libc::c_int::try_from(pid).ok()?;
        // SAFETY: `proc_bsdinfo` 只含整数与定长数组，全零是合法值。
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
        // SAFETY: `info` 是本函数拥有的、大小为 `size` 的可写缓冲区；内核最多写入 `size` 字节并返回实际写入的
        // 字节数。调用不保留任何指针。
        let n = unsafe {
            libc::proc_pidinfo(
                c_pid,
                libc::PROC_PIDTBSDINFO,
                0,
                std::ptr::from_mut(&mut info).cast(),
                size,
            )
        };
        if n != size {
            return None;
        }
        let mut path_buf = vec![0u8; usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE).ok()?];
        let cap = u32::try_from(path_buf.len()).ok()?;
        // SAFETY: `path_buf` 是本函数拥有的、长度为 `cap` 的可写缓冲区；内核写入以 NUL 结尾的路径并返回其长度。
        let len = unsafe { libc::proc_pidpath(c_pid, path_buf.as_mut_ptr().cast(), cap) };
        let path = usize::try_from(len).ok().filter(|&l| l > 0).map(|l| {
            path_buf.truncate(l);
            String::from_utf8_lossy(&path_buf).into_owned()
        });
        let name = {
            let long = c_name(&info.pbi_name);
            if long.is_empty() {
                c_name(&info.pbi_comm)
            } else {
                long
            }
        };
        Some(ProcessInfo {
            pid: info.pbi_pid,
            ppid: info.pbi_ppid,
            start_us: info
                .pbi_start_tvsec
                .saturating_mul(1_000_000)
                .saturating_add(info.pbi_start_tvusec),
            tty: (info.e_tdev != NODEV).then_some(info.e_tdev),
            name,
            path,
        })
    }

    #[allow(unsafe_code)]
    pub(super) fn args(pid: u32) -> Option<Vec<String>> {
        let c_pid = libc::c_int::try_from(pid).ok()?;
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, c_pid];
        // 命令行与环境变量合计的上限（ARG_MAX）；超出部分不需要
        let mut buf = vec![0u8; 256 * 1024];
        let mut len: libc::size_t = buf.len();
        // SAFETY: `mib` 是长度为 3 的有效 MIB；`buf` 是本函数拥有的、长度为 `len` 的可写缓冲区，内核最多写入 `len`
        // 字节并回写实际长度；不设置新值（`newp` 为空）。调用不保留任何指针。
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        buf.truncate(len);
        parse_procargs2(&buf)
    }

    /// `KERN_PROCARGS2` 的格式：`int argc`，可执行文件路径（NUL 结尾，之后可能还有若干 NUL 填充），
    /// 然后是 `argc` 个以 NUL 结尾的参数，之后是环境变量（不读取）。
    pub(super) fn parse_procargs2(buf: &[u8]) -> Option<Vec<String>> {
        let argc_bytes: [u8; 4] = buf.get(..4)?.try_into().ok()?;
        let argc = usize::try_from(i32::from_ne_bytes(argc_bytes)).ok()?;
        let rest = buf.get(4..)?;
        let exec_end = rest.iter().position(|&b| b == 0)?;
        let mut pos = exec_end;
        while rest.get(pos) == Some(&0) {
            pos = pos.checked_add(1)?;
        }
        let mut out = Vec::with_capacity(argc.min(256));
        for arg in rest.get(pos..)?.split(|&b| b == 0).take(argc) {
            out.push(String::from_utf8_lossy(arg).into_owned());
        }
        (out.len() == argc).then_some(out)
    }
}

#[cfg(all(test, target_os = "macos"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_current_process() {
        let me = process_info(std::process::id()).unwrap();
        assert_eq!(me.pid, std::process::id());
        assert_eq!(me.ppid, std::os::unix::process::parent_id());
        assert!(me.start_us > 1_600_000_000_000_000);
        assert!(me.path.is_some());
        let args = process_args(std::process::id()).unwrap();
        assert_eq!(args.len(), std::env::args().count());
        assert_eq!(args.last(), std::env::args().next_back().as_ref());
        // 启动时间稳定：同一进程两次读取相同
        assert_eq!(
            process_info(std::process::id()).unwrap().start_us,
            me.start_us
        );
        assert!(process_info(u32::MAX).is_none());
    }

    #[test]
    fn socket_peer_pid_is_this_process() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(socket_peer_pid(&a).unwrap(), std::process::id());
    }

    #[test]
    fn parses_procargs2() {
        let mut buf = 2i32.to_ne_bytes().to_vec();
        buf.extend_from_slice(b"/bin/ls\0\0\0ls\0-la\0HOME=/x\0");
        assert_eq!(
            imp::parse_procargs2(&buf).unwrap(),
            vec!["ls".to_owned(), "-la".to_owned()]
        );
        assert!(imp::parse_procargs2(&buf[..3]).is_none());
        let mut short = 3i32.to_ne_bytes().to_vec();
        short.extend_from_slice(b"/bin/ls\0ls\0");
        assert!(imp::parse_procargs2(&short).is_none());
    }
}
