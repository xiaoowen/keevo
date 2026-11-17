# Keevo 本地通信协议（IPC）

- **版本**：0.1（草案）
- **状态**：待评审
- **参考实现**：
  - `crates/keevo-crypto` 的 `noise` 模块（Noise 握手与传输加密）
  - `crates/keevo-ipc`（分帧、消息、配对与会话）
- **背景**：[docs/architecture.md §6](../docs/architecture.md#6-本地-ipc-与信任链)

## 1. 范围与拓扑

```
Chrome 扩展 ──Native Messaging(stdio)──▶ keevo-native-host ──Unix socket──▶ Vault Service（Keevo.app）
                                                                        ▲
keevo CLI ─────────────────────────────────Unix socket──────────────────┘
```

本规范定义：

1. 两段链路的分帧格式；
2. 操作系统层的对端身份校验；
3. 扩展与 Vault Service 之间的端到端加密：配对与会话；
4. 会话内的请求与响应。

CLI 的会话授权（按终端会话划分）在 v0.2 定义。

## 2. 分帧

| 链路 | 帧格式 | 上限 |
|---|---|---|
| 浏览器 ↔ native host | 由 Chrome 定义：4 字节**本机字节序**长度 + UTF-8 JSON | 发往浏览器 1 MiB；来自浏览器 64 MiB，但本协议把单帧限制为 1 MiB |
| native host ↔ Vault Service | 4 字节**大端序**长度 + 内容 | 1 MiB |

- 长度为 0 或超过上限时，接收方必须立即断开连接，不能尝试恢复。
- Vault Service 的 socket 位于 App Group 容器内的 `ipc/` 目录，目录权限 0700。

## 3. 对端身份校验（操作系统层）

### 3.1 Vault Service 校验 socket 对端

1. 通过 `LOCAL_PEERTOKEN` 取得对端的 audit token，再用 `SecCodeCreateWithAuditToken` 得到对端代码对象。
2. 用代码签名要求校验：

```
anchor apple generic
and certificate leaf[subject.OU] = "<Keevo Team ID>"
and (identifier "app.keevo.native-host" or identifier "app.keevo.cli")
```

3. 校验失败时立即断开，并记入本地安全日志。
4. 从源码自行构建的 CLI 不满足上述要求：用户在 App 中显式信任后，固定其 cdhash（v0.2）。

### 3.2 native host 校验父进程

- **浏览器侧限制**：host 清单中的 `allowed_origins` 只包含 Keevo 扩展 ID，由浏览器负责执行。
- **父进程校验**：host 启动时检查父进程的代码签名，Team ID 必须在白名单中（Google Chrome、Microsoft Edge、Brave 等，具体值在实现中维护，并在每个版本发布前核实）。不在白名单中时，host 立即退出。
- **来源参数**：Chrome 以扩展来源（`chrome-extension://<id>/`）作为第一个参数启动 host。host 把它原样转发给 Vault Service，作为配对记录的一部分。

> **M0 原型的实现状态**：
> - §3.2 父进程校验：已实现，按代码签名（`crates/keevo-macos`）。白名单目前只有已在构建机上核实的 Google Chrome（Team ID `EQHXZ8M8AV`）。
> - §3.1 socket 对端校验：机制已实现（基于 `LOCAL_PEERTOKEN` 取得的 audit token），但 Keevo 尚无 Team ID 与签名证书，开发服务只依赖 socket 目录的 0700 权限。release 构建拒绝这种模式。
> - 仅 debug 构建可用 `KEEVO_DEV_ALLOW_ANY_PARENT` 跳过父进程校验、用 `KEEVO_DEV_SOCKET` 指定 socket 路径，供端到端测试使用。
>
> 取得签名证书并启用 §3.1 的代码签名要求之前，不得处理真实数据。

## 4. 端到端加密

**native host 只转发密文**，不参与加密，也看不到任何内容。

### 4.1 Noise 参数

| 用途 | 握手模式 | 套件 |
|---|---|---|
| 首次配对 | `XX` | `Noise_XX_25519_ChaChaPoly_SHA256` |
| 已配对后的会话 | `IK` | `Noise_IK_25519_ChaChaPoly_SHA256` |

- **角色**：扩展是发起方（initiator），Vault Service 是响应方（responder）。
- **prologue** 为 `"keevo/v1/ipc" ‖ 0x00 ‖ 握手用途 ‖ 0x00 ‖ 扩展来源`：
  - 握手用途为 `"pair"` 或 `"session"`；
  - 扩展来源即 native host 收到的参数，例如 `chrome-extension://abc…/`。

  任何一方看到的扩展来源不一致，握手都会失败，因此一个扩展的配对无法被挪给另一个扩展使用。
- **双方的静态密钥**：
  - 扩展的静态密钥在首次配对时生成，存于 `chrome.storage.local`。
  - Vault Service 的静态密钥在首次启动时生成，存于钥匙串（`ThisDeviceOnly`）。

### 4.2 配对（XX）

1. 扩展发起 XX 握手，共 3 条消息：
   - 第 1 条：扩展 → Vault Service，负载为空。
   - 第 2 条：Vault Service → 扩展，负载为空。
   - 第 3 条：扩展 → Vault Service，负载为 `{"name": "<浏览器与配置文件的显示名>"}`。
2. 握手完成后，双方计算短认证串：

   ```
   SAS = HKDF-SHA-256(IKM = handshake_hash, salt = "", info = "keevo/v1/ipc-sas", L = 6)
   ```

   6 个字节映射为 6 个单词，词表 v1 中英文各 256 个，词表单独发布。M0 原型暂以 6 组两位十六进制显示。
3. 两端同时显示 SAS，用户在 Keevo.app 中确认两边一致。
4. 用户确认后，Vault Service 保存配对记录：
   - 扩展的静态公钥；
   - 扩展来源；
   - 浏览器信息；
   - 显示名；
   - 配对时间。

   扩展保存 Vault Service 的静态公钥。
5. 用户拒绝或 60 秒内未确认：丢弃握手结果，双方都不保存任何东西。

### 4.3 会话（IK）

1. 扩展用已保存的 Vault Service 公钥发起 IK 握手，共 2 条消息，负载均为空。
2. Vault Service 读完第 1 条消息后得到扩展的静态公钥：
   - 不在配对记录中，或来源与记录不符：发送错误帧（§5.3）并断开。
3. 握手完成后进入传输模式。每个方向的 nonce 都严格递增，任何重放或乱序都会导致解密失败并断开。
4. **会话生命周期**：
   - 会话不跨越 Vault Service 的锁定：锁定时，Vault Service 推送 `locked` 事件（§5.2），但不断开会话。
   - 会话最长存活 24 小时，之后必须重新握手。
   - native host 进程退出时，会话随之结束。

### 4.4 撤销

用户在"设置 → 浏览器"中解除配对后：
- Vault Service 删除配对记录，并立即断开该扩展的所有会话；
- 此后该扩展的 IK 握手都会失败，扩展提示重新配对。

## 5. 消息

### 5.1 扩展 ↔ native host（明文控制层）

```json
{ "t": "hello", "v": 1 }                         // 扩展 → host：协议版本
{ "t": "pair", "d": "<base64url，无填充>" }        // 扩展 → 服务：XX 配对的第一条握手消息
{ "t": "session", "d": "<base64url，无填充>" }     // 扩展 → 服务：IK 会话的第一条握手消息
{ "t": "noise", "d": "<base64url，无填充>" }       // 双向：其余握手消息与传输消息
{ "t": "error", "code": "<错误码>" }              // 服务或 host → 扩展，随后断开
```

- **host 的职责**：
  - 收到 `hello` 后连接 Vault Service，先发送 `HostHello`（§5.4）。
  - 之后把扩展的每一帧原样放进 socket 帧转发，并把服务的回帧原样转回。
  - host 只检查帧大小与 JSON 结构，不解析 `d` 的内容。协议逻辑全部集中在 Vault Service，这样经过签名的 host 二进制攻击面最小。
- **握手用途由第一条消息的帧类型决定**：
  - `pair` 用于配对（XX），`session` 用于会话（IK）。
  - 同一连接中只能出现一次，出现在其他位置一律视为 `bad_request`。
- **配对确认**：XX 握手完成后，Vault Service 等待用户确认 SAS（§4.2）。
  - 确认后，发送加密的 `{"event": "paired"}`，此后才接受请求。
  - 拒绝或超时后，发送 `{"t": "error", "code": "pairing_rejected"}` 并断开。

### 5.2 会话内（Noise 传输层加密）

**请求**：

```json
{ "id": 1, "method": "status" }
{ "id": 2, "method": "candidates", "params": { "url": "https://github.com/login" } }
{ "id": 3, "method": "fill", "params": { "item_id": "<id>", "url": "https://github.com/login" } }
```

**响应与推送**：

```json
{ "id": 1, "result": { "locked": false } }
{ "id": 2, "result": { "items": [{ "item_id": "<id>", "title": "GitHub", "subtitle": "octocat" }] } }
{ "id": 3, "result": { "username": "octocat", "password": "…", "totp": "123456" } }
{ "id": 3, "error": { "code": "locked" } }
{ "event": "locked" }
{ "event": "paired" }
```

**最小披露原则（Vault Service 强制执行）**：

| 规则 | 说明 |
|---|---|
| 候选只返回概要 | `candidates` 只返回与 `url` 匹配的条目（匹配规则见 architecture.md §5.3），且只含标题与副标题 |
| `fill` 再次校验 | 再次检查 `item_id` 与 `url` 是否匹配，不匹配时返回 `url_mismatch`，绝不返回秘密 |
| `fill` 可要求用户在场 | 按用户设置要求 Touch ID |
| 锁定时只回状态 | 锁定状态下，除 `status` 外的所有请求都返回 `locked` |

### 5.3 错误码

| 错误码 | 含义 |
|---|---|
| `unsupported_version` | 协议版本不支持 |
| `not_paired` | IK 握手时，扩展的静态公钥不在配对记录中 |
| `pairing_rejected` | 用户拒绝或超时 |
| `locked` | Vault Service 已锁定 |
| `url_mismatch` | 条目与网址不匹配 |
| `not_found` | 条目不存在 |
| `bad_request` | 消息格式错误 |
| `service_unavailable` | host 无法连接 Vault Service（应用未运行） |

### 5.4 native host → Vault Service 的首帧（明文）

```json
{ "v": 1, "client": "native-host", "extension_origin": "chrome-extension://…/", "browser": "com.google.Chrome" }
```

- **为什么能信任**：这一帧来自已通过 §3.1 代码签名校验的 host。
- **用途**：其中的扩展来源同时用作 Noise prologue 的一部分，以及与配对记录的比对。

## 6. 安全性质与残余风险

| 威胁 | 防护 |
|---|---|
| 其他扩展冒充 Keevo 扩展 | 浏览器的 `allowed_origins` 限制；扩展来源写入 prologue 与配对记录 |
| 本机恶意进程直连 socket | §3.1 代码签名校验；即便连上，没有已配对的静态私钥也无法完成 IK 握手 |
| 恶意进程启动 native host | §3.2 父进程校验 |
| 中间人篡改或重放 | Noise 认证加密；nonce 严格递增 |
| 首次配对被中间人截获 | SAS 由用户确认 |
| 扩展的静态私钥被窃取（例如从浏览器配置目录读出） | 攻击者还必须同时通过 §3.1 与 §3.2；敏感操作可要求 Touch ID；用户可随时撤销配对 |

## 7. 未决事项

| 事项 | 计划 |
|---|---|
| SAS 词表 v1（中文 / 英文） | M1.3 |
| CLI 会话授权（TTY + 父 shell）与 cdhash 信任 | v0.2，M1.4 |
| 浏览器 Team ID 白名单的维护流程 | M1.3 |
| 推送事件的完整列表（`locked`、`unlocked`、`items_changed`） | M1.3 |

## 8. 变更记录

| 版本 | 日期 | 说明 |
|---|---|---|
| 0.1 | 2026-11-17 | 首个草案 |
