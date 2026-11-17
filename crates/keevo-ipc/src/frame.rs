//! 分帧（`spec/ipc.md` §2）。

use std::io::{Read, Write};

use crate::error::IpcError;

/// 单帧上限：1 MiB。
pub const MAX_FRAME: usize = 1 << 20;

/// 写一个 socket 帧：4 字节大端序长度 + 内容。
///
/// # Errors
/// 内容为空或超过 [`MAX_FRAME`] 时返回 [`IpcError::BadFrameLength`]；I/O 错误返回 [`IpcError::Io`]。
pub fn write_socket_frame<W: Write>(w: &mut W, payload: &[u8]) -> Result<(), IpcError> {
    let len = checked_len(payload.len())?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// 读一个 socket 帧。
///
/// # Errors
/// 长度为 0 或超过上限时返回 [`IpcError::BadFrameLength`]，调用方必须断开连接。
pub fn read_socket_frame<R: Read>(r: &mut R) -> Result<Vec<u8>, IpcError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    read_body(r, u32::from_be_bytes(len))
}

/// 写一个 Native Messaging 帧：4 字节**本机字节序**长度 + UTF-8 JSON（由 Chrome 定义）。
///
/// # Errors
/// 同 [`write_socket_frame`]。
pub fn write_native_frame<W: Write>(w: &mut W, json: &[u8]) -> Result<(), IpcError> {
    let len = checked_len(json.len())?;
    w.write_all(&len.to_ne_bytes())?;
    w.write_all(json)?;
    w.flush()?;
    Ok(())
}

/// 读一个 Native Messaging 帧。
///
/// # Errors
/// 同 [`read_socket_frame`]。
pub fn read_native_frame<R: Read>(r: &mut R) -> Result<Vec<u8>, IpcError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    read_body(r, u32::from_ne_bytes(len))
}

fn checked_len(len: usize) -> Result<u32, IpcError> {
    if len == 0 || len > MAX_FRAME {
        return Err(IpcError::BadFrameLength(len));
    }
    u32::try_from(len).map_err(|_| IpcError::BadFrameLength(len))
}

fn read_body<R: Read>(r: &mut R, len: u32) -> Result<Vec<u8>, IpcError> {
    let len = usize::try_from(len).map_err(|_| IpcError::BadFrameLength(usize::MAX))?;
    checked_len(len)?;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_limits() {
        let mut buf = Vec::new();
        write_socket_frame(&mut buf, b"hello").unwrap();
        assert_eq!(&buf[..4], &5u32.to_be_bytes());
        assert_eq!(read_socket_frame(&mut buf.as_slice()).unwrap(), b"hello");

        let mut nm = Vec::new();
        write_native_frame(&mut nm, br#"{"t":"hello","v":1}"#).unwrap();
        assert_eq!(
            read_native_frame(&mut nm.as_slice()).unwrap(),
            br#"{"t":"hello","v":1}"#
        );

        assert_eq!(
            write_socket_frame(&mut Vec::new(), b""),
            Err(IpcError::BadFrameLength(0))
        );
        let oversized = (u32::try_from(MAX_FRAME).unwrap() + 1).to_be_bytes();
        assert_eq!(
            read_socket_frame(&mut oversized.as_slice()),
            Err(IpcError::BadFrameLength(MAX_FRAME + 1))
        );
        // 声明的长度大于实际数据：读到 EOF 报错，而不是返回半截内容
        let mut short = 10u32.to_be_bytes().to_vec();
        short.extend_from_slice(b"abc");
        assert!(matches!(
            read_socket_frame(&mut short.as_slice()),
            Err(IpcError::Io(_))
        ));
    }
}
