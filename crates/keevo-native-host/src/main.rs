//! Keevo 的 Native Messaging 宿主（`spec/ipc.md` §2、§3.2、§5.1）。
//!
//! 由浏览器启动，命令行第一个参数是扩展来源（`chrome-extension://<id>/`）。流程：
//! 1. 校验父进程是已知浏览器（按代码签名）；
//! 2. 读取扩展的 `hello`，连接 Vault Service 的 socket，发送 `HostHello`；
//! 3. 之后双向逐帧转发。只检查帧大小与 JSON 结构，不解析、也无法解密 Noise 内容。
//!
//! 任何错误都直接退出：浏览器会收到断开事件，扩展负责提示用户。

use std::io::{self, BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::thread;

use keevo_ipc::frame::{
    read_native_frame, read_socket_frame, write_native_frame, write_socket_frame,
};
use keevo_ipc::message::{ControlFrame, ErrorCode, HostHello, version_supported};

/// 开发构建可用：跳过父进程校验（仅 debug 构建生效）。端到端测试用它模拟浏览器启动宿主。
const DEV_ALLOW_ANY_PARENT: &str = "KEEVO_DEV_ALLOW_ANY_PARENT";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            // 尽力告诉扩展原因；stdout 可能已经不可用
            if let Ok(frame) = (ControlFrame::Error { code }).to_json() {
                let _ = write_native_frame(&mut io::stdout().lock(), &frame);
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), ErrorCode> {
    let origin = std::env::args()
        .nth(1)
        .filter(|o| valid_origin(o))
        .ok_or(ErrorCode::BadRequest)?;
    let browser = parent_browser()?;

    let mut stdin = BufReader::new(io::stdin().lock());
    let first = read_native_frame(&mut stdin).map_err(|_| ErrorCode::BadRequest)?;
    // 扩展请求的协议版本原样转给 Vault Service，由它决定是否支持（spec/ipc.md §5.5）。
    // 版本写在 Noise prologue 中，host 改动版本只会让握手失败
    let version = match ControlFrame::from_json(&first) {
        Ok(ControlFrame::Hello { v }) if version_supported(v) => v,
        Ok(ControlFrame::Hello { .. }) => return Err(ErrorCode::UnsupportedVersion),
        _ => return Err(ErrorCode::BadRequest),
    };

    let path = keevo_ipc::paths::socket_path().map_err(|_| ErrorCode::ServiceUnavailable)?;
    let mut socket = UnixStream::connect(path).map_err(|_| ErrorCode::ServiceUnavailable)?;
    let hello = HostHello {
        v: version,
        client: "native-host".into(),
        extension_origin: origin,
        browser: browser.into(),
    };
    let hello = serde_json::to_vec(&hello).map_err(|_| ErrorCode::BadRequest)?;
    write_socket_frame(&mut socket, &hello).map_err(|_| ErrorCode::ServiceUnavailable)?;

    // Vault Service → 浏览器
    let mut from_service = socket
        .try_clone()
        .map_err(|_| ErrorCode::ServiceUnavailable)?;
    thread::spawn(move || {
        let mut stdout = BufWriter::new(io::stdout().lock());
        while let Ok(frame) = read_socket_frame(&mut from_service) {
            if ControlFrame::from_json(&frame).is_err()
                || write_native_frame(&mut stdout, &frame).is_err()
            {
                break;
            }
        }
        // 服务断开：结束整个进程，浏览器随之收到断开事件
        std::process::exit(0);
    });

    // 浏览器 → Vault Service
    while let Ok(frame) = read_native_frame(&mut stdin) {
        match ControlFrame::from_json(&frame) {
            Ok(ControlFrame::Hello { .. }) | Err(_) => return Err(ErrorCode::BadRequest),
            Ok(_) => write_socket_frame(&mut socket, &frame)
                .map_err(|_| ErrorCode::ServiceUnavailable)?,
        }
    }
    // 浏览器关闭了端口
    Ok(())
}

/// 扩展来源必须形如 `chrome-extension://<32 个 a–p 字母>/`（Chrome 扩展 ID 的字母表）。
fn valid_origin(origin: &str) -> bool {
    origin
        .strip_prefix("chrome-extension://")
        .and_then(|rest| rest.strip_suffix('/'))
        .is_some_and(|id| id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b)))
}

fn parent_browser() -> Result<&'static str, ErrorCode> {
    if cfg!(debug_assertions) && std::env::var_os(DEV_ALLOW_ANY_PARENT).is_some() {
        return Ok("dev");
    }
    match keevo_macos::parent_browser() {
        Ok(Some(bundle_id)) => Ok(bundle_id),
        _ => Err(ErrorCode::BadRequest),
    }
}

#[cfg(test)]
mod tests {
    use super::valid_origin;

    #[test]
    fn origin_format() {
        assert!(valid_origin(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
        ));
        assert!(!valid_origin(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
        ));
        assert!(!valid_origin(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnoz/"
        ));
        assert!(!valid_origin("https://abcdefghijklmnopabcdefghijklmnop/"));
        assert!(!valid_origin("chrome-extension://short/"));
    }
}
