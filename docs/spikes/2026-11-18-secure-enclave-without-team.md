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
| 其他进程拿到 blob 后能否使用该 SE 密钥 | 本次未测 | M1.1。设计上假设**能**：blob 不绑定应用身份，见 ADR-0003 的残余风险 |
| 临时签名 + Hardened Runtime 的应用能否正常启动、加载静态链接的 Rust 核心 | 本次只测了命令行程序 | M1.1 |
| 未公证的应用下载后首次打开的流程 | 需要从网络下载、带隔离属性的安装包 | M3 定稿安装说明前验证 |
