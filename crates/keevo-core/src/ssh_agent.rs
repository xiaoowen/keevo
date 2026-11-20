//! SSH Agent 的授权策略（`spec/ssh-agent.md` §4.1）。
//!
//! 策略是本机的授权，存在本机记录中（`spec/crypto.md` §8.8，种类 [`LOCAL_KIND`]，ID 为条目 ID），与浏览器配对、
//! 站点授权一样：不随备份回退，也不随同步传播。从备份恢复不会让授权在用户不知情时变宽，被永久删除后又随旧备份
//! 回来的密钥也不在 Agent 中提供（第五轮预审 K17）。
//!
//! M1.4 把策略写在条目属性 `ssh_agent` 中（`spec/vault-format.md` §2.1）。第一次解锁时迁移到本机记录，
//! 并从条目中删除这个属性；迁移之后条目属性一律忽略（[`crate::Vault`] 的迁移）。

use keevo_format::{ItemDoc, ItemType, RecordKey, RecordValue};

/// M1.4 的条目属性名（已弃用：只在迁移时读取）。
pub const ATTRIBUTE: &str = "ssh_agent";
/// 本机记录的种类。明文是 ASCII 文本：[`AgentPolicy::as_str`] 之一，或 [`OFF`]。
pub const LOCAL_KIND: &str = "ssh_agent";
/// 本机记录中"明确关闭"的值：用户选择不在 Agent 中提供。
pub const OFF: &str = "off";

/// 一把密钥在 Agent 中的授权策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentPolicy {
    /// 每次签名都确认。
    Ask,
    /// 同一来源会话确认一次。
    Session,
    /// 解锁期间自动签名。
    Unlocked,
}

impl AgentPolicy {
    /// 属性中的文本。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Session => "session",
            Self::Unlocked => "unlocked",
        }
    }

    /// 由属性文本解析；其他值返回 `None`（不在 Agent 中提供）。
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ask" => Some(Self::Ask),
            "session" => Some(Self::Session),
            "unlocked" => Some(Self::Unlocked),
            _ => None,
        }
    }
}

/// M1.4 写在条目属性中的策略（只在迁移时读取）。不是 `ssh_key` 条目、属性缺省或取值不认识时为 `None`。
#[must_use]
pub fn legacy_policy_of(doc: &ItemDoc) -> Option<AgentPolicy> {
    if doc.item_type != ItemType::SshKey {
        return None;
    }
    match doc.get(&RecordKey::attr(ATTRIBUTE)) {
        Some(RecordValue::Text(t)) => AgentPolicy::parse(t.expose()),
        _ => None,
    }
}
