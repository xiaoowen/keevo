//! `Id128` 的十六进制编码（32 个小写字符）。

use keevo_crypto::Id128;
use serde::{Deserialize, Deserializer, Serializer};

pub(crate) fn parse(s: &str) -> Option<Id128> {
    let bytes = s.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let hi = nibble(*pair.first()?)?;
        let lo = nibble(*pair.get(1)?)?;
        *slot = (hi << 4) | lo;
    }
    Some(Id128::from_bytes(out))
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

pub(crate) fn serialize<S: Serializer>(id: &Id128, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&id.to_hex())
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Id128, D::Error> {
    let s = String::deserialize(d)?;
    parse(&s).ok_or_else(|| serde::de::Error::custom("invalid id"))
}

pub(crate) mod option {
    use super::{Deserialize, Deserializer, Id128, Serializer};

    pub(crate) fn serialize<S: Serializer>(id: &Option<Id128>, s: S) -> Result<S::Ok, S::Error> {
        match id {
            Some(id) => s.serialize_some(&id.to_hex()),
            None => s.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Id128>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| super::parse(&s).ok_or_else(|| serde::de::Error::custom("invalid id")))
            .transpose()
    }
}

/// 可选的 SHA-256 摘要（64 个小写十六进制字符），用于附件引用的 `sha256`（`spec/vault-format.md` §2.5）。
pub(crate) mod sha256_option {
    use super::{Deserialize, Deserializer, Serializer, nibble};
    use core::fmt::Write as _;

    pub(crate) fn serialize<S: Serializer>(d: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match d {
            Some(d) => {
                let mut hex = String::with_capacity(64);
                for b in d {
                    let _ = write!(hex, "{b:02x}");
                }
                s.serialize_some(&hex)
            }
            None => s.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| parse(&s).ok_or_else(|| serde::de::Error::custom("invalid sha256")))
            .transpose()
    }

    fn parse(s: &str) -> Option<[u8; 32]> {
        let bytes = s.as_bytes();
        if bytes.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
            *slot = (nibble(*pair.first()?)? << 4) | nibble(*pair.get(1)?)?;
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_rejects_bad_input() {
        let id = Id128::from_bytes([0xab; 16]);
        assert_eq!(parse(&id.to_hex()), Some(id));
        assert_eq!(parse("AB"), None);
        assert_eq!(parse(&"AB".repeat(16)), None, "只接受小写");
        assert_eq!(parse(&"zz".repeat(16)), None);
    }
}
