//! SSH Agent 的授权策略（`spec/ssh-agent.md` §4.1，条目属性 `ssh_agent`，`spec/vault-format.md` §2.1）。

use keevo_format::{ItemDoc, ItemType, RecordKey, RecordValue};

/// 属性名。
pub const ATTRIBUTE: &str = "ssh_agent";

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

/// 条目在 Agent 中的策略。不是 `ssh_key` 条目、属性缺省或取值不认识时为 `None`。
#[must_use]
pub fn policy_of(doc: &ItemDoc) -> Option<AgentPolicy> {
    if doc.item_type != ItemType::SshKey {
        return None;
    }
    match doc.get(&RecordKey::attr(ATTRIBUTE)) {
        Some(RecordValue::Text(t)) => AgentPolicy::parse(t.expose()),
        _ => None,
    }
}
