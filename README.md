# Keevo

> 开源、本地优先、以安全为核心的个人数字保险库。

Keevo 保存你的密码、双因素验证、SSH 密钥、API 令牌、数据库凭证和环境变量。数据默认只在你的设备上；需要多设备时，通过你自己的 iCloud、云盘或 NAS 端到端加密同步。除了你，没有人能读取，包括我们。

> **状态：M0（基础建设）**。目前只有设计文档、规范和密码学核心，**还不能使用**，请勿用来存放真实数据。

## 核心理念

- **安全至上**：
  - 主密码与 128 位账户密钥共同派生密钥（2SKD）。
  - 元数据同样加密。
  - 规范先行，并接受外部审计。
- **隐私设计**：零遥测；同步文件中只有不透明的密文。
- **本地优先**：无需账户、无需网络即可完整使用。
- **自托管**：同步可以只走你自己的存储，不需要运行任何服务端。
- **卓越体验**：原生 macOS 应用与 Chrome 扩展，对标一流的密码管理器。

首发平台：macOS，Chrome 及 Chromium 系浏览器。

## 文档

| 内容 | 位置 |
|---|---|
| 产品与技术设计 | [docs/](docs/README.md) |
| 威胁模型与安全设计 | [docs/security.md](docs/security.md) |
| 加密规范 v0.1 | [spec/crypto.md](spec/crypto.md) |
| 修订模型规范 v0.1 | [spec/revisions.md](spec/revisions.md) |
| 路线图 | [docs/roadmap.md](docs/roadmap.md) |

## 仓库结构

```
crates/keevo-crypto/   密码学边界：2SKD、加密信封、密钥集（实现 spec/crypto.md）
crates/keevo-format/   数据模型：记录映射、修订图、HLC、因果合并（实现 spec/revisions.md）
crates/keevo-store/    本地 SQLite 存储，只存密文
crates/keevo-core/     账户、解锁状态机、保险库与条目操作
crates/keevo-ffi/      UniFFI 导出给 Swift
apps/macos/            macOS 应用（M0：SwiftUI 空壳 + 端到端冒烟测试）
spec/                  可审计的规范、独立参考实现与测试向量
fuzz/                  模糊测试目标（nightly + cargo-fuzz）
tools/                 构建工具
docs/                  设计文档与架构决策记录（ADR）
scripts/               CI 检查脚本
supply-chain/          cargo-vet 供应链审计记录
```

## 开发

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
scripts/build-macos.sh --smoke     # 构建 macOS 空壳应用并运行 Swift 端冒烟测试
```

完整流程与规则见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 安全

请按 [SECURITY.md](SECURITY.md) 私下报告漏洞，不要提交公开 issue。

## 许可证

Keevo 按目录采用不同的许可证：
- 核心库与规范：MIT OR Apache-2.0
- 客户端应用：GPL-3.0-or-later，附加 App Store 许可

详见 [LICENSE](LICENSE)。
