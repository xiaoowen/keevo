# ADR-0003：Keevo 不绑定任何 Apple 开发者团队

- **状态**：已采纳
- **日期**：2026-11-18
- **修订**：
  - [ADR-0002](0002-icloud-drive-folder-without-team.md) 中"发布前仍需要 Keevo 自己的开发者账号"一节，以及"专属容器降为将来的可选增强"一条；
  - [docs/README.md](../README.md) 的 D8（分发方式）与 D12（开发者团队）。

## 背景

ADR-0002 决定不使用任何现有团队，但仍计划在正式发布前（最迟 M3）为 Keevo 申请组织开发者账号，用来做公证、native host 的签名校验与 Touch ID。

现在的决定更进一步：**这个项目不绑定任何 Apple 开发者团队**，也不为 Keevo 申请。

## 决策

1. **签名**：所有 macOS 产物使用临时签名（`codesign -s -`），启用 Hardened Runtime。不申请、不使用任何团队的证书、描述文件或 entitlement。
2. **依赖团队的功能移出路线图**（见下文）。将来如果要做，必须先写一份新的 ADR 推翻本决定。
3. **本机密钥**改为"Secure Enclave 密钥包裹后存成普通文件"，不使用数据保护钥匙串（[技术验证](../spikes/2026-11-18-secure-enclave-without-team.md)）。
4. **IPC 对端校验**改为固定 cdhash：Vault Service 只接受 cdhash 与本应用包内 `keevo-native-host`、`keevo` CLI 一致的对端（`spec/ipc.md` §3.1）。
5. **数据位置**改为 `~/Library/Application Support/Keevo/`。App Group 容器需要 Team ID 前缀与 entitlement，不再使用。
6. **分发**：在 GitHub Releases 发布临时签名的构建，附 SHA-256 校验和、Sigstore 签名，并实现可复现构建；同时提供从源码构建的脚本。自动更新用 Sparkle 的 EdDSA 签名，不依赖 Apple。具体安装流程 M3 定稿。
7. **范围**：本决定只涉及 Apple 开发者团队。Chrome 网上应用店的发布账号不受影响。

## 影响

### 做不了的功能（移出路线图）

| 功能 | 原计划 | 原因 | 替代 |
|---|---|---|---|
| Apple 公证，Gatekeeper 直接放行 | M1 起 | 公证需要 Developer ID 证书 | 首次打开时，用户需在"系统设置 → 隐私与安全性"中选择"仍要打开"，或从源码构建 |
| 系统级自动填充与通行密钥提供方（Safari 与原生 App） | M2 | AutoFill 凭据提供扩展需要团队签发的 entitlement | 通行密钥只在 Chrome 扩展中支持 |
| Safari Web Extension | M4+ | Safari 只运行已签名应用中的扩展；未签名的扩展要求用户每次打开开发者设置 | 无 |
| iOS 应用 | M4+ 的首位 | 向普通用户分发 iOS 应用都需要团队签名 | 无 |
| Mac App Store | 后续评估 | 上架需要团队 | 无。GPL 的 App Store 附加许可草案暂无用途，是否撤回另行决定 |
| iCloud 专属容器；用 iCloud 钥匙串同步账户密钥 | ADR-0002 的将来增强；M2 可选功能 | 需要 iCloud 与钥匙串 entitlement | iCloud 云盘普通文件夹（ADR-0002）；账户密钥用局域网配对、扫码或应急包传递 |

### 改用替代方案

| 原方案 | 替代 | 安全影响 |
|---|---|---|
| Touch ID：Secure Enclave 包裹 AUK，存入数据保护钥匙串 | Secure Enclave 包裹 AUK（ECDH + HKDF-SHA256 + AES-256-GCM），blob 与密文存入数据目录下的文件（0600） | blob 只能由本机的 Secure Enclave 使用，复制到别处无用。但它**不绑定应用身份**：同用户进程拿到 blob 后，可以自己发起一次 Touch ID 请求，提示文字可以伪造。归入 A7 的残余风险 |
| 账户密钥：数据保护钥匙串，`ThisDeviceOnly` | 不需要用户在场的 Secure Enclave 密钥包裹后存成文件 | 不随备份迁移到其他 Mac（blob 在别处无法使用）。同用户进程可以解开它，与 A7 的假设一致：账户密钥单独泄露仍需主密码 |
| Vault Service 静态密钥、浏览器配对记录：钥匙串 | 同上 | 同上 |
| 设备 ID 的"仅限本机"标记（`spec/revisions.md` §8） | Secure Enclave 包裹的标记：在另一台 Mac 上解不开，即说明数据库被恢复到了新设备 | 比钥匙串标记更可靠 |
| IPC：对端必须由 Keevo 的 Team ID 签名 | 对端 cdhash 必须等于本应用包内 host 或 CLI 的 cdhash，运行时从自身应用包读取 | 同用户进程可以替换整个应用包，但那等于替换 Keevo 本身，属于非目标（注入或替换 Keevo 进程） |
| Library Validation（只加载同一团队签名的库） | 静态链接 Rust 核心，不加载第三方动态库；Hardened Runtime 照常启用，阻止 `DYLD_*` 注入 | 临时签名下 Library Validation 无法按团队放行，改以"不加载动态库"达到同样目的 |
| Developer ID 签名的发布 | 临时签名 + 校验和 + Sigstore + 可复现构建 | 用户不能靠 Gatekeeper 判断来源，需要核对校验和或签名。安装说明必须写清楚 |

### 用户体验

- 首次安装需要手动放行，这是最明显的代价。
- 每次更新后 cdhash 都会变化。Keevo 自己的密钥不放在登录钥匙串里，因此更新不会触发钥匙串授权提示。

### 仍需验证（M1.1）

- 登记指纹后，`biometryCurrentSet` 密钥的创建与使用。
- 临时签名 + Hardened Runtime 的应用能否正常运行，Rust 核心改为静态链接。
- 未公证应用下载后的首次打开流程（M3 写安装说明前）。

## 备选方案

| 方案 | 优点 | 缺点 | 结论 |
|---|---|---|---|
| **A. 不绑定任何团队（采纳）** | 不依赖任何组织主体与年费；项目完全独立 | 上表中的功能做不了；首次安装体验差 | 采纳 |
| B. 为 Keevo 申请组织开发者账号（原 ADR-0002 的计划） | 公证、iOS、系统级自动填充、Safari 都可行 | 需要组织主体与年费；项目与一个 Apple 账号绑定 | 不采纳 |
