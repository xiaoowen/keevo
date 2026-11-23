# ADR-0003：Keevo 不绑定任何 Apple 开发者团队

- **状态**：已采纳；同日按第二轮模型评审修订（[处理记录](../reviews/2026-11-18-model-review-round2-response.md)）
- **日期**：2026-11-18
- **修订**：
  - [ADR-0002](0002-icloud-drive-folder-without-team.md) 中"发布前仍需要 Keevo 自己的开发者账号"一节，以及"专属容器降为将来的可选增强"一条；
  - [docs/README.md](../README.md) 的 D8（分发方式）与 D12（开发者团队）。

## 背景

ADR-0002 决定不使用任何现有团队，但仍计划在正式发布前（最迟 M3）为 Keevo 申请组织开发者账号，用来做公证、native host 的签名校验与 Touch ID。

现在的决定更进一步：**这个项目不绑定任何 Apple 开发者团队**，也不为 Keevo 申请。

## 决策

1. **签名**：所有 macOS 产物使用临时签名（`codesign -s -`），启用 Hardened Runtime，并保留它默认启用的 Library Validation。不申请、不使用任何团队的证书与描述文件，也不使用需要团队授权的受管能力（managed capabilities）。可以在临时签名中声明的本地 entitlement 与运行时例外（例如禁用 Library Validation），项目同样一律不用。
2. **依赖团队的功能移出路线图**（见下文）。将来如果要做，必须先写一份新的 ADR 推翻本决定。
3. **本机密钥**改为"Secure Enclave 密钥包裹后存成普通文件"，格式见 `spec/crypto.md` §8.7，不使用数据保护钥匙串（[技术验证](../spikes/2026-11-18-secure-enclave-without-team.md)）。配对记录与站点授权不用这种文件，而是存入加密的保险库数据库（`spec/ipc.md` §4.2）。
4. **IPC 对端校验**改为固定 cdhash：构建时把 `keevo-native-host`、`keevo` CLI 的 cdhash 编译进主程序，Vault Service 只接受这些对端；运行时不从磁盘读取（`spec/ipc.md` §3.1）。
5. **数据位置**改为 `~/Library/Application Support/Keevo/`。App Group 容器需要 Team ID 前缀与 entitlement，不再使用。
6. **分发**：在 GitHub Releases 发布临时签名的构建，并实现可复现构建；同时提供从源码构建的脚本。
   - **来源与完整性靠 Sigstore**：验证时固定期望的签名身份（发布仓库的 `.github/workflows/release.yml`，仅限 `v*` 标签）与 OIDC issuer（`https://token.actions.githubusercontent.com`），并核验透明日志证明；不接受"任意有效的 Sigstore 签名"。
   - **SHA-256 校验和**只用来发现产物与一个已可信的摘要不一致。摘要本身要来自经 Sigstore 验证的发布清单，而不是与产物放在同一处、可被一起替换的文本。
   - **更新**：Sparkle 的 EdDSA 签名，公钥编译进应用。首次安装的信任来自对安装包的 Sigstore 验证。
   - 可复现构建用于核对源码与产物是否一致，不单独证明源码或构建者可信。
   - 不公证也就没有 Apple 的恶意软件检查，签名不能替代它。
   - 可执行的验证步骤（工具的取得方式、命令、版本与降级规则）M3 定稿。Alpha 起（2026-11-23）已按本条实施：`.github/workflows/release.yml` 在 `v*` 标签上构建并用 cosign 无密钥签名 `SHA256SUMS`，验证步骤见 [docs/alpha/install.md](../alpha/install.md)；可复现构建、SBOM 与 SLSA 来源证明尚未实现。
7. **范围**：本决定只涉及 Apple 开发者团队。Chrome 网上应用店的发布账号不受影响。

## 影响

### 做不了的功能（移出路线图）

| 功能 | 原计划 | 原因 | 替代 |
|---|---|---|---|
| Apple 公证，Gatekeeper 直接放行 | M1 起 | 公证需要 Developer ID 证书 | 首次打开时，用户在"系统设置 → 隐私与安全性"中选择"仍要打开"，或从源码构建。这一流程待验证；受管设备的策略可能不允许手动放行 |
| 系统级自动填充与通行密钥提供方（Safari 与原生 App） | M2 | AutoFill 凭据提供扩展需要团队签发的 entitlement | 通行密钥只在 Chrome 扩展中支持 |
| Safari Web Extension（正式支持） | M4+ | 正式分发需要 Developer ID 或 App Store；开发与测试时 Safari 可以运行未签名的扩展，但需要用户打开开发者设置 | 无 |
| iOS 应用 | M4+ 的首位 | 按本项目的分发方式（面向普通用户）需要团队签名；个人开发调试所用的 Personal Team 也是团队。这是当前的支持政策，未逐一核实所有地区与安装方式的例外 | 无 |
| Mac App Store | 后续评估 | 上架需要团队 | 无。GPL 的 App Store 附加许可草案暂无用途，是否撤回另行决定 |
| iCloud 专属容器；用 iCloud 钥匙串同步账户密钥 | ADR-0002 的将来增强；M2 可选功能 | 需要 iCloud 容器 entitlement；可同步的钥匙串项（`kSecAttrSynchronizable`）与数据保护钥匙串都需要访问组权限。传统登录钥匙串仍可用，但不同步 | iCloud 云盘普通文件夹（ADR-0002），它只替代数据的存储与传输；账户密钥用局域网配对、扫码或应急包传递 |

### 改用替代方案

| 原方案 | 替代 | 安全影响 |
|---|---|---|
| Touch ID：Secure Enclave 包裹 AUK，存入数据保护钥匙串 | 需要用户在场的 Secure Enclave 密钥包裹 AUK（`spec/crypto.md` §8.7），存入数据目录下的文件（0600） | blob 只能由本机的 Secure Enclave 使用，复制到别处无用。但它**不绑定应用身份**：同用户进程拿到 blob 后，可以自己发起一次 Touch ID 请求，提示文字可以伪造。归入 A7 的残余风险 |
| 账户密钥：数据保护钥匙串，`ThisDeviceOnly` | 不需要用户在场的 Secure Enclave 密钥包裹后存成文件 | 不随备份迁移到其他 Mac（blob 在别处无法使用）。**同用户进程可以在本机无提示地解开它**（第二轮评审已用另一个临时签名程序实测）。账户密钥泄露后，安全性退化为主密码与 KDF 的强度 |
| Vault Service 的 Noise 静态私钥：钥匙串 | 同上 | 同用户进程同样可以取出。与账户密钥不同，它没有"还需主密码"这第二层：取得它就能冒充 Vault Service 与扩展握手，看到扩展请求的网址，或向扩展返回伪造的填充数据。接受为 A7 的残余风险，因为每次浏览器重启都要求 Touch ID 的代价过高 |
| 浏览器配对记录、站点授权：钥匙串 | 加密的保险库数据库（`spec/ipc.md` §4.2） | 不需要用户在场的 Secure Enclave 包裹无法阻止同用户进程解开再重新包裹，提供不了授权记录的完整性，因此不用它 |
| 设备 ID 的"仅限本机"标记（`spec/revisions.md` §8） | Secure Enclave 包裹的标记 | 解不开说明数据库到了新硬件上，也可能是标记被删除或损坏，都按新设备处理。它不能发现同一台 Mac 上的数据库副本 |
| IPC：对端必须由 Keevo 的 Team ID 签名 | 对端 cdhash 必须等于构建时编译进主程序的 host 或 CLI 的 cdhash | 只替换辅助程序无效。同用户进程替换主程序等于替换 Keevo 本身，已写入非目标（`docs/security.md` §1） |
| Library Validation 放行同一团队签名的库 | 保留 Hardened Runtime 默认的 Library Validation；Rust 核心静态链接 | 临时签名没有 Team ID，Library Validation 只放行 Apple 签名的库，因此自家的动态库加载不了，改为静态链接。第二轮评审已实测：临时签名 + Hardened Runtime 的程序能加载 Apple 系统库，另一个临时签名的 dylib 被拒绝。Library Validation 仍对 `dlopen`、插件等生效 |
| Developer ID 签名的发布 | 临时签名 + Sigstore（固定身份与 issuer）+ 可复现构建 | 用户不能靠 Gatekeeper 判断来源，必须核对 Sigstore 签名；校验和只用来发现与可信摘要不一致（决策第 6 条）。安装说明必须写清楚 |

### 用户体验

- 首次安装需要手动放行，这是最明显的代价。
- 每次更新后 cdhash 都会变化。Keevo 自己的密钥不放在登录钥匙串里，因此更新不会触发钥匙串授权提示。

### 仍需验证（M1.1）

- ~~登记指纹后，`biometryCurrentSet` 密钥的创建与使用、取消、指纹不匹配~~：已实测（技术验证记录的补充）。锁屏与指纹变更后的失效与恢复仍待实测。
- ~~完整的 SwiftUI 应用在临时签名 + Hardened Runtime 下能否正常运行，Rust 核心改为静态链接~~：已实测。`scripts/package-macos.sh --verify` 组装并签名 `Keevo.app`，逐项检查：flags 为 adhoc + runtime、没有 Team ID 与 entitlement、只链接系统库；Hardened Runtime 下冒烟测试（含 Secure Enclave）通过；`DYLD_INSERT_LIBRARIES` 被忽略；Library Validation 拒绝临时签名的库（"mapping process and mapped file (non-platform) have different Team IDs"）、放行系统库；后两项都有不加 Hardened Runtime 的对照组，证明测试本身有效。`--launch` 确认应用能正常启动。CI 的 macOS 任务每次运行 `--verify`。
- 构建流程：先签名辅助程序，把 cdhash 编译进主程序，再签名主程序。
- macOS 的"App 管理"保护能否阻止其他应用修改拖拽安装的 Keevo.app。
- ~~未公证应用下载后的首次打开流程（M3 写安装说明前）~~：已实测（2026-11-23，macOS 27.0.1，人工检查 A1），步骤写入 [docs/alpha/install.md](../alpha/install.md)。

## 备选方案

| 方案 | 优点 | 缺点 | 结论 |
|---|---|---|---|
| **A. 不绑定任何团队（采纳）** | 不依赖任何组织主体与年费；项目完全独立 | 上表中的功能做不了；首次安装体验差 | 采纳 |
| B. 为 Keevo 申请组织开发者账号（原 ADR-0002 的计划） | 公证、iOS、系统级自动填充、Safari 都可行 | 需要组织主体与年费；项目与一个 Apple 账号绑定 | 不采纳 |
