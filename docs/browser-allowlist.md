# 浏览器白名单的维护流程

native host 启动时检查父进程的代码签名，只接受白名单中的浏览器（`spec/ipc.md` §3.2）。白名单在 `crates/keevo-macos/src/lib.rs` 的 `KNOWN_BROWSERS` 中，每一项是一条代码签名要求：

```
anchor apple generic and identifier "<签名标识>" and certificate leaf[subject.OU] = "<Team ID>"
```

这一检查只是**纵深防御**，不是身份证明：同用户的进程可以用 fork→exec 绕过（§3.2）。白名单的作用是挡住"任意程序直接启动 host"这类低成本的尝试，因此宁缺毋滥：只收录在构建机上核实过的正式版浏览器。

## 当前白名单

| 浏览器 | 签名标识 | Team ID | 核实日期 | 核实方式 |
|---|---|---|---|---|
| Google Chrome | `com.google.Chrome` | `EQHXZ8M8AV` | 2026-11-17；2026-11-19 复核（版本 157.0.8103.79） | `scripts/verify-browser.sh`；真实浏览器测试中 Chrome 启动的 host 通过父进程校验 |

Chrome 的 Beta、Dev、Canary 版签名标识不同（`com.google.Chrome.beta` 等），不在白名单中，host 会拒绝。有需要时按下面的流程单独收录。

## 收录一个浏览器

1. **取得安装包**：从浏览器官网下载正式版，安装到 `/Applications`。不使用第三方镜像。
2. **运行核实脚本**：`scripts/verify-browser.sh "/Applications/<浏览器>.app"`。脚本只读，检查：
   - 有 Team ID（不是临时签名，也不是 Apple 平台二进制）；
   - 代码与资源完整（`codesign --verify --deep`）；严格模式只因附加属性失败时给出提示；
   - 满足与 `KNOWN_BROWSERS` 相同形式的签名要求；
   - Gatekeeper 评估通过（已公证）。
3. **独立核对 Team ID**：与至少一个独立来源比对，例如浏览器开发者的公开说明，或另一台机器上从官网安装的同一浏览器。不能只凭一台机器的输出。
4. **修改代码**：
   - 在 `KNOWN_BROWSERS` 中加入脚本给出的条目，在其上方的表格中写明核实日期；
   - 在本文档的"当前白名单"中加一行；
   - 如果要在"设置 → 浏览器"中一键安装 host 清单，在 `apps/macos/Sources/KeevoUI/BrowserSupport.swift` 中加入该浏览器的 `NativeMessagingHosts` 目录（例如 Microsoft Edge 为 `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts`，Brave 为 `~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts`），并在 `browserName` 中加上显示名。
5. **验证**：在该浏览器中加载扩展，完成一次配对与填充，确认 host 通过父进程校验；把核实脚本的输出贴在合并请求中。
6. **评审**：至少一名评审者在自己的机器上重新运行第 2、3 步，结果一致才能合并。

## 每次发布前

- 对白名单中的每个浏览器运行 `scripts/verify-browser.sh`，确认签名标识与 Team ID 没有变化，并更新"当前白名单"中的复核日期。
- 浏览器更换了签名团队（罕见）：按"收录"流程重新核实，确认来源可信后再更新，并在发布说明中写明。在此之前，新版本浏览器会被 host 拒绝，扩展提示连接失败。

## 移除

浏览器停止维护、签名出现异常（例如证书被吊销），或无法再核实时，从白名单中移除，并在发布说明中写明受影响的浏览器。
