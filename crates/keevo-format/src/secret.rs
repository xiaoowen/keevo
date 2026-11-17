use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// 释放时清零的字符串，用于字段值等可能包含秘密的文本。
///
/// `Debug` 输出固定为 `SecretString(…)`，不会泄露内容。序列化与反序列化是尽力而为的：
/// serde_json 在处理转义字符时可能使用未清零的临时缓冲区。
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// 包装一个字符串。
    #[must_use]
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    /// 取出内容。调用方应尽快丢弃返回的引用。
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self::new(s.to_owned())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(…)")
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}
