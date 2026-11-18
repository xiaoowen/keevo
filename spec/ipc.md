# Keevo 本地通信协议（IPC）

- **版本**：0.2（草案）
- **状态**：已按 2026-11-18 模型评审修订（[处理记录](../docs/reviews/2026-11-18-model-review-response.md)），待外部人工评审
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

1. 通过 `LOCAL_PEERTOKEN` 取得对端的 audit token，再以 `kSecGuestAttributeAudit` 属性调用 `SecCodeCopyGuestWithAttributes` 得到对端代码对象。不得只凭 PID 标识对端（PID 可被复用）。
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
- **父进程校验只是纵深防御，不是身份证明**（评审 2026-11-18 F2）：它检查的是查询时该 PID **当前**运行的代码，而不是创建 host 的进程。同用户的恶意进程可以先建立管道、派生出稍后执行 host 的子进程，再把自己 `exec` 成签名浏览器（PID 不变），host 看到的父进程就是浏览器，而管道与来源参数都由攻击者选择。该机制已用 Apple 签名的 `/bin/sleep` 复现；尚未在真实 Chrome 与正式签名的 host 上验证完整攻击链。
  - 因此，本协议**假设**落盘的扩展静态私钥可能被同用户进程读取并用于冒充已配对的扩展，由 §5.2 的按站点授权兜底。
  - 能把创建者身份、进程实例与通信端点绑定在一起的 OS 机制仍在调研（§7）；找到之前不得把本节写成安全保证。

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

1. 扩展生成 32 字节随机数 `nonce`，计算**配对承诺**：

   ```
   commitment = SHA-256("keevo/v1/ipc-pair-commit" ‖ 扩展静态公钥 (32) ‖ nonce (32) ‖ 显示名的 UTF-8 字节)
   ```

2. 扩展发起 XX 握手，共 3 条消息：
   - 第 1 条：扩展 → Vault Service，负载**恰好**是 32 字节的 `commitment`，否则 Vault Service 返回 `bad_request` 并断开。
   - 第 2 条：Vault Service → 扩展，负载为空；非空时扩展断开。
   - 第 3 条：扩展 → Vault Service，负载为 `{"name": "<显示名>", "nonce": "<base64(nonce)>"}`。
3. Vault Service 读完第 3 条消息后，用握手得到的扩展静态公钥、收到的显示名与 `nonce` 重新计算承诺；与第 1 条消息不一致时返回 `bad_request` 并断开。
4. 握手完成后，双方计算短认证串：

   ```
   SAS = HKDF-SHA-256(IKM = handshake_hash, salt = "", info = "keevo/v1/ipc-sas", L = 6)
   ```

   6 个字节映射为 6 个单词，词表 v1 中英文各 256 个，词表单独发布。M0 原型暂以 6 组两位十六进制显示。
5. 两端同时显示 SAS，用户在 Keevo.app 中确认两边一致。
6. 用户确认后，Vault Service 保存配对记录：
   - 扩展的静态公钥；
   - 扩展来源；
   - 浏览器信息；
   - 显示名：去除控制字符后取前 64 个字符（承诺按处理前的原始字符串计算）；
   - 配对时间（Unix 毫秒）。

   扩展保存 Vault Service 的静态公钥。配对记录与保险库同等保护，存入加密数据库；开发服务使用的未认证 JSON 文件不得用于正式版本。
7. **时限**：从 Vault Service 收到第 1 条消息起算 60 秒，覆盖握手与用户确认。超时后到达的第 3 条消息、超时后的确认都视为拒绝：返回 `pairing_rejected`，双方都不保存任何东西。用户拒绝时同样处理。

**为什么需要承诺**（评审 2026-11-18 I1）：没有承诺时，最后发言的一方可以在看到对方的贡献之后反复调整自己的消息，离线搜索使两段中间人握手 SAS 相同的取值，48 位的 SAS 不再是"一次机会"。有了承诺：
- 攻击者冒充 Vault Service 与扩展握手时，必须在第 2 条消息中定下自己的全部贡献，而扩展一侧的握手结果还取决于第 3 条消息才公开的 `nonce`；
- 攻击者冒充扩展与 Vault Service 握手时，第 1 条消息已承诺第 3 条消息的全部内容，而 Vault Service 的临时密钥在承诺之后才发送。

无论攻击者先完成哪一段，另一段的 SAS 对它都是均匀随机的。每次尝试只有 2⁻⁴⁸ 的成功概率，且会在 Keevo.app 中产生一次用户可见的配对请求。

### 4.3 会话（IK）

1. 扩展用已保存的 Vault Service 公钥发起 IK 握手，共 2 条消息，负载均为空；接收方必须检查，非空即断开。
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
- 会话层在处理**每个**请求前都重新核对配对记录（公钥存在、来源一致），因此即使断开与请求之间存在竞态，撤销后的请求也一律返回 `not_paired` 并断开；
- 此后该扩展的 IK 握手都会失败，扩展提示重新配对；
- 撤销与锁定无关：重新解锁保险库不会恢复被撤销的配对；
- 配对记录写盘失败时，内存中的撤销仍立即生效，但必须提示用户"撤销可能在重启后失效"。

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
| `fill` 按站点授权 | 见下文。网址匹配只能防钓鱼，不能防冒充的扩展：后者可以为每个条目提供与之匹配的网址 |
| `fill` 可要求用户在场 | 按用户设置要求 Touch ID |
| 锁定时只回状态 | 锁定状态下，除 `status` 外的所有请求都返回 `locked` |

**`fill` 的按站点授权**（评审 2026-11-18 F2、I3；M1.3 实现，M0 原型尚未实现）：

1. **首次确认**：某个配对**第一次**为某个条目在某个站点取用凭据时，Vault Service 在 Keevo.app 的原生界面请用户确认，显示：
   - 站点（规范化后的 `scheme://host[:port]`）；
   - 条目标题与用户名；
   - 发起请求的配对（显示名、浏览器）。

   用户确认后记住 `(配对, 条目, 站点)`；拒绝或 60 秒内未确认时返回 `not_authorized`，不返回任何秘密。
2. **授权的存储与失效**：授权与配对记录存在一起，撤销配对时一并删除；用户可在"设置 → 浏览器"中逐项撤销。
3. **频率限制**：同一配对 10 分钟内为 5 个以上不同条目取用凭据时（包括已授权的），暂停该配对的 `fill` 并在 Keevo.app 中提示；用户确认后恢复。阈值为初始值，M1 实测后调整。
4. **原生界面不可被扩展伪造**：确认只出现在 Keevo.app 中，不出现在扩展或网页里。

### 5.3 错误码

| 错误码 | 含义 |
|---|---|
| `unsupported_version` | 协议版本不支持 |
| `not_paired` | IK 握手时，扩展的静态公钥不在配对记录中 |
| `pairing_rejected` | 用户拒绝或超时 |
| `locked` | Vault Service 已锁定 |
| `url_mismatch` | 条目与网址不匹配 |
| `not_found` | 条目不存在 |
| `bad_request` | 消息格式错误，包括配对承诺不符、握手负载不合规定 |
| `not_authorized` | 用户拒绝本次 `fill` 的站点授权、授权超时，或该配对因频率限制被暂停（§5.2） |
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
| 恶意进程启动 native host | §3.2 父进程校验，**仅为纵深防御**：可被 fork→exec 绕过 |
| 中间人篡改或重放 | Noise 认证加密；nonce 严格递增 |
| 首次配对被中间人截获 | SAS 由用户确认；配对承诺（§4.2）使每次尝试只有 2⁻⁴⁸ 的机会，且每次尝试都会产生用户可见的配对请求 |
| 扩展的静态私钥被窃取（例如同用户进程从浏览器配置目录读出），再绕过 §3.2 冒充扩展 | **按站点授权**（§5.2）：未授权的站点需要用户在原生界面确认；频率限制；敏感操作可要求 Touch ID；用户可随时撤销配对 |

**残余风险**：
- 冒充成功的攻击者可以取得用户**已授权**的站点的凭据，速度受频率限制约束。
- `candidates` 不需要授权，冒充者可以逐个猜测网址，得知用户在哪些站点有账户以及对应的用户名。M1.3 会评估是否对 `candidates` 也做频率限制。
- Noise 依赖（snow 0.10）内部的 DH 私钥与 ChaCha 密钥副本没有清零（见 `docs/security.md` §9）。

## 7. 未决事项

| 事项 | 计划 |
|---|---|
| SAS 词表 v1（中文 / 英文） | M1.3 |
| CLI 会话授权（TTY + 父 shell）与 cdhash 信任 | v0.2，M1.4 |
| 浏览器 Team ID 白名单的维护流程 | M1.3 |
| 推送事件的完整列表（`locked`、`unlocked`、`items_changed`） | M1.3 |
| `fill` 按站点授权与频率限制的实现（§5.2） | M1.3 |
| 能绑定创建者身份、进程实例与通信端点的 OS 机制；在真实 Chrome 与正式签名的 host 上验证 F2 的完整攻击链 | M1.3 |
| `candidates` 的频率限制 | M1.3 评估 |

## 8. 变更记录

| 版本 | 日期 | 说明 |
|---|---|---|
| 0.1 | 2026-11-17 | 首个草案 |
| 0.2 | 2026-11-18 | 按模型评审修订：配对承诺与从第 1 条消息起算的时限（I1）；握手负载必须检查；撤销时每个请求都重新核对配对记录并主动断开（F1）；父进程校验降为纵深防御（F2）；`fill` 按站点授权与频率限制（F2、I3），新增 `not_authorized`；更正 §3.1 的 API 名称；补充显示名处理规则 |
