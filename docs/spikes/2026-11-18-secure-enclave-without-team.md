# 技术验证：不绑定开发者团队时的 Secure Enclave 与钥匙串

- **日期**：2026-11-18
- **环境**：macOS 27.0.1（26A434），MacBook Pro（Mac14,9，Apple M2 Pro），有 Touch ID 硬件但**未登记指纹**
- **程序**：[`spikes/secure-enclave/main.swift`](../../spikes/secure-enclave/main.swift)，临时签名（`Signature=adhoc`、`TeamIdentifier=not set`），没有任何 entitlement
- **运行**：3 次，结果一致；不弹出任何认证提示，钥匙串测试项写入后立即删除
- **用途**：为 [ADR-0003](../adr/0003-no-apple-developer-team.md) 提供依据

## 结论

**结论一：不需要团队也能使用 Secure Enclave。** 通过 CryptoKit 创建的 Secure Enclave 密钥以加密 blob 的形式交给应用自己保存，不经过钥匙串，也就不需要钥匙串访问权限。Touch ID 解锁、设备签名密钥都可以照此实现。

**结论二：数据保护钥匙串不可用，传统的登录钥匙串可用。** 前者需要团队签发的 `keychain-access-groups` 权限。因此原设计中"存入数据保护钥匙串（`WhenUnlockedThisDeviceOnly`）"的几项都要改为"Secure Enclave 包裹后存成文件"。

## 测量结果

| # | 验证项 | 结果 | 对设计的影响 |
|---|---|---|---|
| 1 | 环境 | `SecureEnclave.isAvailable = true`；`biometryType = touchID`；未登记指纹 | — |
| 2 | SE 密钥协商 + HKDF + AES-GCM 包裹 32 字节的 AUK；只凭 blob 恢复 SE 密钥后解包 | **通过**，blob 284 字节 | Touch ID 解锁材料、账户密钥、服务静态密钥都可以这样存成文件 |
| 3 | SE 签名密钥签名并验证 | **通过** | M2 的设备签名密钥可行 |
| 4 | 带 `userPresence`（Touch ID 或登录密码）的 SE 密钥 | **创建成功**，blob 427 字节；未调用，因此未弹出认证 | 需要用户在场的解锁可行 |
| 5 | 带 `biometryCurrentSet`（仅 Touch ID，指纹变化即失效）的 SE 密钥 | **未能验证**：本机未登记指纹，系统拒绝创建（`-1000`）；这与团队无关 | M1.1 在登记了指纹的 Mac 上验证 |
| 6 | 数据保护钥匙串写入 | 失败，`-34018`（缺少 entitlement），符合预期 | 不再使用 |
| 7 | 登录钥匙串写入 | **通过** | 可用，但访问控制按代码签名；临时签名的 cdhash 每次更新都会变，系统会再次询问是否允许访问，因此不用它存 Keevo 自己的密钥 |

## 尚未验证

| 项目 | 原因 | 计划 |
|---|---|---|
| `biometryCurrentSet` 密钥的创建与使用（弹出 Touch ID） | 本机未登记指纹；使用时需要用户操作 | M1.1，在登记了指纹的 Mac 上与用户一起验证 |
| 把 blob 复制到另一台 Mac 后无法使用 | 只有一台 Mac | M1.1 或 M2；按 Apple 的设计，blob 由本机 Secure Enclave 的密钥加密 |
| 其他进程拿到 blob 后能否使用该 SE 密钥 | 本次未测 | **第二轮模型评审已实测：能**。另一个代码标识、cdhash 都不同的临时签名程序，只凭 blob 文件就无提示地解包。见 ADR-0003 与 `spec/crypto.md` §8.7 的保护范围 |
| 临时签名 + Hardened Runtime 的应用能否正常启动、加载静态链接的 Rust 核心 | 本次只测了命令行程序。第二轮评审实测：这种程序能加载 Apple 系统库，另一个临时签名的 dylib 被 Library Validation 拒绝 | **M1.1 已验证完整应用**：`scripts/package-macos.sh --launch`，见 ADR-0003"仍需验证" |
| 未公证的应用下载后首次打开的流程 | 需要从网络下载、带隔离属性的安装包 | M3 定稿安装说明前验证 |

## 补充：错误分类实测（M1.1，2026-11-18）

为本机密钥包裹（`spec/crypto.md` §8.7）区分"取消、暂时不可用、失效"三类错误，在同一台 Mac 上测量 CryptoKit 的实际报错。程序为临时编译的命令行工具，结论已用于 `apps/macos/Sources/KeevoKit/SecureEnclaveBridge.swift`。

| 情形 | 报错的位置 | 错误 | 分类 |
|---|---|---|---|
| blob 中间改动一个字节 | 恢复私钥时不报错；协商时报错 | CryptoTokenKit `-3`（`corruptedData`），"unable to compute shared secret"，附带 `AKSError` | 失效 |
| blob 被截断、随机字节 | 恢复私钥时 | CryptoTokenKit `-3`，"corrupted objectID detected" | 失效 |
| 临时公钥不在曲线上、或为压缩格式 | 解析公钥时 | `CryptoKitError.incorrectParameterSize` / `.invalidParameter` | 失效 |
| 需要用户在场的密钥，用禁止交互的认证上下文协商 | 协商时 | LocalAuthentication `-1004`（`notInteractive`） | 暂时不可用 |
| 未登记指纹时创建 `biometryCurrentSet` 密钥 | 创建时 | LocalAuthentication `-1000`；`canEvaluatePolicy` 报告 `-7`（`biometryNotEnrolled`） | 暂时不可用（创建失败不涉及已有材料） |

用真实的 Secure Enclave 跑冒烟测试（`scripts/build-macos.sh --smoke`）：账户密钥与设备标记的 blob 被改动后，Keevo 分别按"要求账户密钥"与"重新登记本机"处理，没有误判为暂时不可用。

**Touch ID 实测**（2026-11-18，同一台 Mac 登记指纹之后，用户在场，`keevo-smoke --touch-id`，8 项全部通过）：

| 步骤 | 原始错误 | Keevo 的处理 |
|---|---|---|
| 已登记的手指 | — | 解锁成功 |
| 点"取消" | LocalAuthentication `-2`（`userCancel`） | 取消：什么都不改变，Touch ID 仍可用 |
| 未登记的手指按到提示消失 | LocalAuthentication `-1`（`authenticationFailed`） | 未通过：计入连续失败次数，Touch ID 不失效 |
| 再用已登记的手指 | — | 解锁成功，失败次数清零 |

启用 Touch ID 时不弹出提示（新一代中的 AUK 包裹在首次使用时验证），与 §8.7 一致。

**仍需验证**：

| 项目 | 风险 | 当前处理 |
|---|---|---|
| 锁屏期间使用 `WhenUnlockedThisDeviceOnly` 的密钥报什么错 | 如果也是 CryptoTokenKit `-3`，锁屏时打开数据库会被误判为设备标记失效，进而换掉设备 ID（可用应急包恢复） | 打开数据库发生在登录之后、应用启动时，锁屏期间通常不会发生。验证后按实际错误码细分 |
| 指纹变化后使用 `biometryCurrentSet` 密钥报什么错 | 如果也报 `authenticationFailed`（`-1`），会被当作"未通过"：连续 3 次后要求主密码，但不会进入"失效后恢复"，主密码解锁后 Touch ID 仍然用不了 | 用途 0x01 中无法确定的错误按失效处理。用 `keevo-smoke --touch-id-change` 验证 |
| Touch ID 提示中的原因文字 | — | 已确认：`LAContext.localizedReason` 显示在系统提示中（实测的每一步说明都由它显示） |

