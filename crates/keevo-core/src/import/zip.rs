//! 读取 zip 中的一个文件（1Password 的 1PUX 是一个 zip）。只支持 1PUX 实际用到的部分：不加密、
//! 存储或 Deflate 压缩、非 ZIP64；校验 CRC-32 与解压后的大小，解压有上限。

use super::ImportError;

const EOCD_SIG: u32 = 0x0605_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const LOCAL_SIG: u32 = 0x0403_4b50;
const EOCD_LEN: usize = 22;
const CENTRAL_LEN: usize = 46;
const LOCAL_LEN: usize = 30;
const MAX_ENTRIES: usize = 200_000;

fn u16_at(d: &[u8], off: usize) -> Result<u16, ImportError> {
    let b: [u8; 2] = d
        .get(off..off.checked_add(2).ok_or(ImportError::Malformed)?)
        .and_then(|b| b.try_into().ok())
        .ok_or(ImportError::Malformed)?;
    Ok(u16::from_le_bytes(b))
}

fn u32_at(d: &[u8], off: usize) -> Result<u32, ImportError> {
    let b: [u8; 4] = d
        .get(off..off.checked_add(4).ok_or(ImportError::Malformed)?)
        .and_then(|b| b.try_into().ok())
        .ok_or(ImportError::Malformed)?;
    Ok(u32::from_le_bytes(b))
}

fn at(base: usize, add: usize) -> Result<usize, ImportError> {
    base.checked_add(add).ok_or(ImportError::Malformed)
}

/// 中央目录中的一项。
struct Entry {
    name: String,
    flags: u16,
    method: u16,
    crc: u32,
    compressed: usize,
    size: usize,
    local: usize,
}

fn entries(data: &[u8]) -> Result<Vec<Entry>, ImportError> {
    if data.len() < EOCD_LEN {
        return Err(ImportError::NotRecognized);
    }
    let last = data.len().saturating_sub(EOCD_LEN);
    let first = last.saturating_sub(0xFFFF);
    let eocd = (first..=last)
        .rev()
        .find(|&i| u32_at(data, i).is_ok_and(|s| s == EOCD_SIG))
        .ok_or(ImportError::NotRecognized)?;
    let count = usize::from(u16_at(data, at(eocd, 10)?)?);
    let cd_offset = u32_at(data, at(eocd, 16)?)?;
    if cd_offset == u32::MAX || count == usize::from(u16::MAX) {
        // ZIP64：1PUX 用不到
        return Err(ImportError::TooLarge);
    }
    let mut off = usize::try_from(cd_offset).map_err(|_| ImportError::Malformed)?;
    let mut out = Vec::with_capacity(count.min(MAX_ENTRIES));
    for _ in 0..count {
        if out.len() >= MAX_ENTRIES {
            return Err(ImportError::TooLarge);
        }
        if u32_at(data, off)? != CENTRAL_SIG {
            return Err(ImportError::Malformed);
        }
        let flags = u16_at(data, at(off, 8)?)?;
        let method = u16_at(data, at(off, 10)?)?;
        let crc = u32_at(data, at(off, 16)?)?;
        let compressed = u32_at(data, at(off, 20)?)?;
        let size = u32_at(data, at(off, 24)?)?;
        let name_len = usize::from(u16_at(data, at(off, 28)?)?);
        let extra_len = usize::from(u16_at(data, at(off, 30)?)?);
        let comment_len = usize::from(u16_at(data, at(off, 32)?)?);
        let local = u32_at(data, at(off, 42)?)?;
        let name_start = at(off, CENTRAL_LEN)?;
        let name = data
            .get(name_start..at(name_start, name_len)?)
            .ok_or(ImportError::Malformed)?;
        let to_usize = |v: u32| usize::try_from(v).map_err(|_| ImportError::TooLarge);
        out.push(Entry {
            name: String::from_utf8_lossy(name).into_owned(),
            flags,
            method,
            crc,
            compressed: to_usize(compressed)?,
            size: to_usize(size)?,
            local: to_usize(local)?,
        });
        off = at(at(at(name_start, name_len)?, extra_len)?, comment_len)?;
    }
    Ok(out)
}

/// 全部文件名。
#[cfg(test)]
pub(crate) fn names(data: &[u8]) -> Result<Vec<String>, ImportError> {
    Ok(entries(data)?.into_iter().map(|e| e.name).collect())
}

/// 读取名为 `wanted` 的文件。解压后超过 `limit` 字节时返回 [`ImportError::TooLarge`]。
pub(crate) fn read(
    data: &[u8],
    wanted: &str,
    limit: usize,
) -> Result<Option<Vec<u8>>, ImportError> {
    let Some(e) = entries(data)?.into_iter().find(|e| e.name == wanted) else {
        return Ok(None);
    };
    if e.flags & 1 != 0 {
        return Err(ImportError::Malformed);
    }
    if e.size > limit {
        return Err(ImportError::TooLarge);
    }
    if u32_at(data, e.local)? != LOCAL_SIG {
        return Err(ImportError::Malformed);
    }
    let name_len = usize::from(u16_at(data, at(e.local, 26)?)?);
    let extra_len = usize::from(u16_at(data, at(e.local, 28)?)?);
    let start = at(at(at(e.local, LOCAL_LEN)?, name_len)?, extra_len)?;
    let raw = data
        .get(start..at(start, e.compressed)?)
        .ok_or(ImportError::Malformed)?;
    let out = match e.method {
        0 => raw.to_vec(),
        8 => miniz_oxide::inflate::decompress_to_vec_with_limit(raw, limit).map_err(|err| {
            if err.status == miniz_oxide::inflate::TINFLStatus::HasMoreOutput {
                ImportError::TooLarge
            } else {
                ImportError::Malformed
            }
        })?,
        _ => return Err(ImportError::Malformed),
    };
    if out.len() != e.size || crc32(&out) != e.crc {
        return Err(ImportError::Malformed);
    }
    Ok(Some(out))
}

/// CRC-32（IEEE 802.3，zip 使用的那个）。
fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (n, slot) in (0u32..).zip(t.iter_mut()) {
            let mut c = n;
            for _ in 0..8 {
                c = if c & 1 == 1 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        t
    });
    !data.iter().fold(!0u32, |c, &b| {
        let i = usize::from(u8::try_from((c ^ u32::from(b)) & 0xFF).unwrap_or(0));
        table.get(i).copied().unwrap_or(0) ^ (c >> 8)
    })
}

/// 测试与样例数据用：把若干文件写成一个 zip（Deflate 压缩）。
#[cfg(any(test, feature = "test-util"))]
#[allow(
    clippy::unwrap_used,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "只用于测试"
)]
pub fn write_for_tests(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, content) in files {
        let packed = miniz_oxide::deflate::compress_to_vec(content, 6);
        let crc = crc32(content);
        let local = out.len() as u32;
        out.extend_from_slice(&LOCAL_SIG.to_le_bytes());
        out.extend_from_slice(&[20, 0, 0, 0, 8, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        out.extend_from_slice(&(content.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&packed);
        central.extend_from_slice(&CENTRAL_SIG.to_le_bytes());
        central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 8, 0, 0, 0, 0, 0]);
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        central.extend_from_slice(&(content.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0; 12]);
        central.extend_from_slice(&local.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    let cd_len = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn reads_what_it_wrote() {
        let big = vec![b'a'; 10_000];
        let zip = write_for_tests(&[("export.attributes", b"{}"), ("export.data", &big)]);
        assert_eq!(names(&zip).unwrap(), ["export.attributes", "export.data"]);
        assert_eq!(read(&zip, "export.data", 1 << 20).unwrap().unwrap(), big);
        assert_eq!(read(&zip, "missing", 1 << 20).unwrap(), None);
        assert_eq!(
            read(&zip, "export.data", 100).err(),
            Some(ImportError::TooLarge)
        );
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        // 改动压缩数据：CRC 或解压失败
        let mut bad = zip.clone();
        let pos = bad
            .windows(4)
            .rposition(|w| w == LOCAL_SIG.to_le_bytes())
            .unwrap()
            + LOCAL_LEN
            + "export.data".len()
            + 2;
        bad[pos] ^= 0x55;
        assert!(read(&bad, "export.data", 1 << 20).is_err());
        assert_eq!(
            names(b"not a zip at all, definitely not").err(),
            Some(ImportError::NotRecognized)
        );
    }
}
