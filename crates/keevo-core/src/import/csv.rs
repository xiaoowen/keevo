//! RFC 4180 CSV（浏览器与 LastPass 的导出文件）：逗号分隔，双引号括起的字段可以含逗号、换行与 `""`。
//! 接受 UTF-8 BOM、CRLF 与 LF，忽略空行。

use super::ImportError;

/// 行数上限。
const MAX_ROWS: usize = 100_000;
/// 一行的字段数上限。
const MAX_COLUMNS: usize = 256;

/// 解析为行。第一行通常是表头。
pub(crate) fn parse(text: &str) -> Result<Vec<Vec<String>>, ImportError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut chars = text.chars().peekable();
    let mut quoted = false;
    // 当前字段是否以引号开头（用于区分空字段与 ""）
    let mut started = false;
    loop {
        let c = chars.next();
        if quoted {
            match c {
                Some('"') if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                Some('"') => quoted = false,
                Some(c) => field.push(c),
                None => return Err(ImportError::Malformed),
            }
            continue;
        }
        match c {
            Some('"') if field.is_empty() && !started => {
                quoted = true;
                started = true;
            }
            Some(',') => {
                push_field(&mut row, &mut field)?;
                started = false;
            }
            Some('\r') if chars.peek() == Some(&'\n') => {}
            Some('\n' | '\r') | None => {
                if !(row.is_empty() && field.is_empty() && !started) {
                    push_field(&mut row, &mut field)?;
                    rows.push(core::mem::take(&mut row));
                    if rows.len() > MAX_ROWS {
                        return Err(ImportError::TooLarge);
                    }
                }
                started = false;
                if c.is_none() {
                    break;
                }
            }
            Some(c) => field.push(c),
        }
    }
    Ok(rows)
}

fn push_field(row: &mut Vec<String>, field: &mut String) -> Result<(), ImportError> {
    if row.len() >= MAX_COLUMNS {
        return Err(ImportError::Malformed);
    }
    row.push(core::mem::take(field));
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_quotes_newlines_and_bom() {
        let rows = parse("\u{feff}name,url,password\r\n\"a, b\",\"https://x\",\"say \"\"hi\"\"\nthere\"\r\n\r\nc,,\n").unwrap();
        assert_eq!(
            rows,
            [
                vec!["name", "url", "password"],
                vec!["a, b", "https://x", "say \"hi\"\nthere"],
                vec!["c", "", ""],
            ]
        );
        assert_eq!(parse("a,\"\"\n").unwrap(), [vec!["a", ""]]);
        assert_eq!(parse("only").unwrap(), [vec!["only"]]);
        assert_eq!(parse("").unwrap(), Vec::<Vec<String>>::new());
        assert_eq!(parse("\"open").err(), Some(ImportError::Malformed));
    }
}
