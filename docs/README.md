# Keevo 设计文档

> Keevo 是一个开源、本地优先的个人数字保险库，用来保存密码、2FA、SSH 密钥、API 令牌、数据库凭证和环境变量等敏感信息。无论数据同步到 iCloud、云盘还是你自己的 NAS，除了你，没有人能读取。

本目录是 Keevo 产品与技术设计的**唯一事实来源**：
- 设计变更走 PR。
- 重大决策写 ADR（`docs/adr/NNNN-标题.md`）。

## 文档索引

| 文档 | 内容 |
|---|---|
| [product.md](product.md) | 愿景、原则、目标用户、竞品定位、功能规格（条目类型、字段系统、2FA、开发者能力）、非功能需求 |
| [ux.md](ux.md) | 体验原则、信息架构、关键流程、浏览器扩展体验、安全交互规范、设计系统 |
| [architecture.md](architecture.md) | 系统架构、技术选型、模块划分、macOS 应用、Chrome 扩展、本地 IPC、CLI、SSH Agent、仓库结构、工程实践 |
| [security.md](security.md) | 安全目标、威胁模型、密钥体系、算法、加密格式、解锁、设备与轮换、完整性、扩展防护、恢复、后量子路线 |
| [sync.md](sync.md) | 本地存储模型、修订与合并、同步文件夹格式、iCloud 与云盘适配、新设备加入、局限 |
| [roadmap.md](roadmap.md) | 里程碑、MVP 范围与验收标准、风险、近期行动 |
| [governance.md](governance.md) | 许可证、透明度、漏洞处理、供应链安全、隐私承诺、社区 |
| [../spec/](../spec/README.md) | 可审计规范：加密格式、修订模型，以及独立参考实现与测试向量 |
| [adr/](adr/) | 架构决策记录 |
| [future/](future/) | 暂缓的设计：[自托管服务端](future/self-hosted-server.md) |
| [spikes/](spikes/) | 技术验证报告：[iCloud 云盘普通文件夹](spikes/2026-11-18-icloud-folder.md) |

## 一页纸摘要

**定位**：1Password 级别的精致体验，加上 Bitwarden 式的开放与透明，并且是对开发者最友好的保险库。

**首发平台**：macOS 原生应用，加上 Chrome 及 Chromium 系浏览器的扩展。

**架构**：
- 所有加密、数据模型、存储、同步和 SSH Agent 逻辑都在一个 **Rust 核心**里，各平台共用。
- macOS 应用用 **SwiftUI** 原生开发，通过 UniFFI 调用 Rust 核心。
- Chrome 扩展是桌面应用的**瘦客户端**：通过 Native Messaging 与桌面应用建立端到端加密会话，**密钥永远不离开桌面应用**。
- **同步无需服务器**：
  - 各设备把签名的加密日志写进 **iCloud** 或任意同步文件夹（Dropbox、OneDrive、坚果云、Syncthing、NAS 等）。
  - 合并在各设备本地完成。

**安全模型**：
- **主密码 + 128 位账户密钥（Secret Key）** 共同派生密钥（2SKD）。即使云盘中的数据全部泄露、主密码偏弱，离线暴力破解也不可行。
- 全量端到端加密，**元数据同样加密**：标题、网址、标签都看不到，同步文件甚至不暴露改了哪些条目。
- 存储提供方被视为不可信：
  - 每台设备的日志都是一条签名的哈希链，配合高水位线，能发现注入、篡改和回滚。
  - 设备密钥放在 Secure Enclave 中，无法导出。
- 本地用 Secure Enclave + Touch ID 解锁，内存中的秘密用后清零。

**里程碑**：
1. M0 基础（6–8 周）
2. M1 纯本地 MVP（4–5 个月）
3. M2 iCloud 与云盘同步，完成首次审计（3–4 个月）
4. M3 1.0（2–3 个月）
5. M4+：共享、更多浏览器与桌面平台

## 关键决策

| # | 决策 | 结论 | 状态 |
|---|---|---|---|
| D1 | 核心语言 | Rust 共享核心，各平台 UI 原生 | 已决定 |
| D2 | macOS UI 技术 | SwiftUI（必要处用 AppKit），不用 Electron | 已决定 |
| D3 | 扩展与桌面应用的关系 | 扩展作为瘦客户端，经 Native Messaging 连接桌面应用；独立模式（WASM）留到后续 | 已决定 |
| D4 | 账户密钥（Secret Key） | 强制启用 2SKD，配合应急包 | 已决定 |
| D5 | M1 是否包含同步 | 不包含。M1 纯本地，但数据格式从第一天起就为同步设计 | 已决定 |
| D6 | 许可证 | 核心库 MIT OR Apache-2.0；客户端 GPL-3.0 + App Store 附加许可；将来的服务端 AGPL-3.0 | 已落地（见根目录 `LICENSE`；App Store 附加许可待法律审阅） |
| D7 | 最低系统版本 | macOS 15+，按 macOS 26+ 的设计语言适配 | 已决定 |
| D8 | 分发方式 | 临时签名 + SHA-256 校验和 + Sigstore 签名 + 可复现构建，经 GitHub Releases 直接分发；不公证、不上 Mac App Store（[ADR-0003](adr/0003-no-apple-developer-team.md)） | 已决定 |
| D9 | 可持续模式 | 以捐赠为主；官方托管同步依赖服务端，随服务端一起再议 | 已决定 |
| D10 | 同步方案 | 基于不可变文件的加密日志；默认 iCloud，兼容任意同步文件夹；M2 交付（[ADR-0001](adr/0001-file-based-cloud-sync.md)） | 已决定 |
| D11 | 自托管服务端 | 暂缓、不排期；同步引擎通过 `SyncStore` 预留扩展点 | 已决定 |
| D12 | 开发者团队与 iCloud 位置 | 不绑定任何 Apple 开发者团队，也不为 Keevo 申请；iCloud 同步用 iCloud 云盘中的普通文件夹（[ADR-0002](adr/0002-icloud-drive-folder-without-team.md)、[ADR-0003](adr/0003-no-apple-developer-team.md)）。依赖团队的功能（公证、iOS、系统级自动填充、Safari、Mac App Store）移出路线图 | 已决定 |
