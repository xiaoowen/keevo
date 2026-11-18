//! 混合逻辑时钟（`spec/revisions.md` §3）。

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// HLC 时间戳：高 48 位为 Unix 毫秒，低 16 位为逻辑计数器。按整数比较先后。
///
/// JSON 中编码为 16 个字符的小写十六进制字符串，避免 JavaScript 等环境丢失超过 2⁵³ 的精度。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hlc(pub u64);

impl Hlc {
    /// 物理时间部分（Unix 毫秒）。
    #[must_use]
    pub const fn millis(self) -> u64 {
        self.0 >> 16
    }

    fn from_millis(ms: u64) -> Self {
        Self(ms.saturating_mul(1 << 16))
    }
}

impl fmt::Debug for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hlc({}+{})", self.millis(), self.0 & 0xffff)
    }
}

impl Serialize for Hlc {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{:016x}", self.0))
    }
}

impl<'de> Deserialize<'de> for Hlc {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 16
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(serde::de::Error::custom("invalid hlc"));
        }
        u64::from_str_radix(&s, 16)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// 远端时间戳最多比本机时钟快多少，才会被本机时钟采纳。
pub const MAX_ADOPT_SKEW_MS: u64 = 24 * 60 * 60 * 1000;

/// 本地 HLC 时钟。`last` 必须由调用方持久化。
#[derive(Debug, Clone, Copy, Default)]
pub struct HlcClock {
    last: Hlc,
}

impl HlcClock {
    /// 从持久化的值恢复。调用方应传入 max(持久化的值, 本地修订中物理时间不超过本机时钟 + 24 小时的最大 hlc)
    /// （`spec/revisions.md` §3）：不得重新引入 [`HlcClock::observe`] 拒绝采纳的远端极值。
    #[must_use]
    pub const fn restore(last: Hlc) -> Self {
        Self { last }
    }

    /// 最近一次发出或观察到的时间戳。
    #[must_use]
    pub const fn last(&self) -> Hlc {
        self.last
    }

    /// 生成新的时间戳：max(now_ms << 16, last + 1)。
    ///
    /// # Errors
    /// `last` 已是最大值、无法再递增时返回 [`crate::FormatError::ClockExhausted`]，而不是重复发出同一个值。
    pub fn next(&mut self, now_ms: u64) -> crate::Result<Hlc> {
        let bumped = self
            .last
            .0
            .checked_add(1)
            .ok_or(crate::FormatError::ClockExhausted)?;
        let candidate = Hlc::from_millis(now_ms).max(Hlc(bumped));
        self.last = candidate;
        Ok(candidate)
    }

    /// 观察到其他设备的时间戳。返回远端是否比本机时钟快 5 分钟以上（应提示用户）。
    ///
    /// 只有物理时间不超过本机时钟 + 24 小时的远端时间戳才会推进本机时钟（`spec/revisions.md` §3）：
    /// 否则一个极端的远端值会让本机此后的时间戳全部饱和。远端值本身照常参与合并，不做截断。
    pub fn observe(&mut self, remote: Hlc, now_ms: u64) -> bool {
        if remote.millis() <= now_ms.saturating_add(MAX_ADOPT_SKEW_MS) {
            self.last = self.last.max(remote);
        }
        remote.millis() > now_ms.saturating_add(5 * 60 * 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_even_if_clock_goes_back() {
        let mut c = HlcClock::default();
        let a = c.next(1_000).unwrap();
        let b = c.next(1_000).unwrap();
        let d = c.next(500).unwrap();
        assert!(a < b && b < d);
        assert_eq!(d.millis(), 1_000);
        let e = c.next(2_000).unwrap();
        assert_eq!(e, Hlc(2_000 << 16));
    }

    #[test]
    fn observe_adopts_remote_and_flags_skew() {
        let mut c = HlcClock::default();
        c.next(1_000).unwrap();
        assert!(!c.observe(Hlc(2_000 << 16), 1_000));
        assert!(c.next(1_000).unwrap() > Hlc(2_000 << 16));
        assert!(c.observe(Hlc((1_000 + 6 * 60 * 1000) << 16), 1_000));
    }

    #[test]
    fn json_is_fixed_width_hex() {
        let s = serde_json::to_string(&Hlc(0x1234)).unwrap();
        assert_eq!(s, "\"0000000000001234\"");
        assert_eq!(serde_json::from_str::<Hlc>(&s).unwrap(), Hlc(0x1234));
        assert!(serde_json::from_str::<Hlc>("\"1234\"").is_err());
    }

    /// 第二轮评审：极端的远端值不推进本机时钟；本机时钟耗尽时报错而不是重复发出同一个值。
    #[test]
    fn extreme_remote_is_not_adopted_and_exhaustion_is_an_error() {
        let mut c = HlcClock::default();
        assert!(c.observe(Hlc(u64::MAX), 1_000));
        let a = c.next(1_000).unwrap();
        assert!(a < Hlc(u64::MAX) && c.next(1_000).unwrap() > a);
        let mut full = HlcClock::restore(Hlc(u64::MAX));
        assert_eq!(full.next(1_000), Err(crate::FormatError::ClockExhausted));
    }
}
