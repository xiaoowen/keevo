# SSH Agent

- **版本**：0.3（草案，M1.5）
- **协议**：SSH agent 协议（draft-miller-ssh-agent，即 OpenSSH `PROTOCOL.agent`），以及 OpenSSH 的 `session-bind@openssh.com` 扩展。
- **原则**：私钥永远不离开 Keevo（`docs/product.md` §5.5）。Agent 只代为签名，不导出私钥，不接受外部密钥。

## 1. socket

- **路径**：release `~/Library/Application Support/Keevo/ssh/agent.sock`；debug `~/Library/Application Support/Keevo-Dev/ssh/agent.sock`，可用 `KEEVO_DEV_AGENT_SOCKET` 覆盖（release 忽略）。所在目录权限 0700。
- **便捷软链**：`~/.keevo/agent.sock` 指向上面的路径，便于写进 `~/.ssh/config`（路径中没有空格）。软链已存在且指向别处、或者是普通文件时不改动，界面提示原因。
- **对端**：ssh 客户端没有可以固定的签名，同用户的任何进程都可以连接。因此**每个签名请求**都识别来源进程（§4），由策略决定是否需要确认。
- 开关在"设置 → 开发者 → SSH Agent"中，默认关闭。关闭时不监听 socket。

## 2. 消息

消息格式：`uint32 长度` + `byte 类型` + 内容；字符串为 `uint32 长度` + 字节（RFC 4251 §5）。单条消息最长 256 KiB，超过即断开连接。

| 请求 | 处理 |
|---|---|
| `SSH_AGENTC_REQUEST_IDENTITIES`（11） | `SSH_AGENT_IDENTITIES_ANSWER`（12）：可用的公钥（§3），注释为条目标题 |
| `SSH_AGENTC_SIGN_REQUEST`（13） | 按策略授权后签名，`SSH_AGENT_SIGN_RESPONSE`（14）；拒绝、超时、密钥不可用时 `SSH_AGENT_FAILURE`（5） |
| `SSH_AGENTC_EXTENSION`（27）`session-bind@openssh.com` | 记录绑定（§5），`SSH_AGENT_SUCCESS`（6）；解析失败 `SSH_AGENT_FAILURE` |
| 其他扩展 | `SSH_AGENT_EXTENSION_FAILURE`（28） |
| 添加、删除密钥，锁定与解锁 agent（17、18、19、22、23、25、26）等其他请求 | `SSH_AGENT_FAILURE`。Keevo 只提供保险库中的密钥 |

- 消息内容在规定字段之后还有多余字节、字符串长度越界：`SSH_AGENT_FAILURE`。
- 签名请求的 `flags`：Ed25519 签名忽略。

## 3. 密钥

Agent 提供的密钥同时满足：

1. 条目类型为 `ssh_key`，不在回收站；
2. 本机的策略（§4.1）为 `ask`、`session` 或 `unlocked`；
3. 条目中恰好有一个 `ssh_private_key` 字段，内容是未加密的 OpenSSH 私钥（`openssh-key-v1`，即 `ssh-keygen` 的默认格式），且算法受支持。

- **算法**：M1.4 支持 Ed25519。ECDSA P-256 与 RSA（`rsa-sha2-256`/`rsa-sha2-512`）所需的密码学库（RustCrypto 的 `p256`、`rsa` 0.10 等 34 个 crate）通过供应链审计后加入；包含这些算法私钥的条目不出现在列表中，界面说明原因。
- 公钥与指纹由私钥计算，不信任条目中"公钥""指纹"字段的文本。
- 列表按条目标题排序。私钥只在签名时解码，用后清零。

**导入**（Keevo.app 中"导入私钥…"）：

| 输入 | 处理 |
|---|---|
| 未加密的 OpenSSH 私钥 | 导入 |
| 有口令保护的 OpenSSH 私钥：`bcrypt` + `aes128-ctr`、`aes192-ctr` 或 `aes256-ctr`（`ssh-keygen` 的默认） | 在 Keevo.app 中输入口令后解密导入。口令只用于这一次解密，不保存；bcrypt 轮数上限 1024。私钥段开头的两个校验数不一致即"口令不对"（与 OpenSSH 相同） |
| 未加密的 PKCS#8 PEM（`BEGIN PRIVATE KEY`，RFC 8410 的 Ed25519，v1 或带公钥的 v2） | 导入；没有注释，用条目标题；v2 的公钥必须与私钥一致 |
| `aes256-gcm@openssh.com` 等带认证的加密方式 | 说明转换方法：`ssh-keygen -p -Z aes256-ctr -f <文件>` |
| 加密的 PEM（旧式 `Proc-Type: 4,ENCRYPTED`，或 `BEGIN ENCRYPTED PRIVATE KEY`） | 说明转换方法：`ssh-keygen -p -f <文件>`（转换为 OpenSSH 格式，可以保留口令） |
| RSA、ECDSA、DSA 私钥（OpenSSH 或 PEM） | 说明暂不支持；算法取自公钥，不需要先输入口令 |

- 不论原来是什么格式，导入后都以**未加密的 OpenSSH 格式**写入条目的 `ssh_private_key` 字段，由保险库加密保存（不保存原文件的口令保护）。
- 测试数据：`crates/keevo-ssh/src/testdata/`（由 `ssh-keygen` 与 `openssl` 生成，命令见其中的 README）。

## 4. 授权

### 4.1 策略

| 值 | 含义 |
|---|---|
| `ask` | 每次签名都在 Keevo.app 中确认 |
| `session` | 同一来源会话确认一次，闲置 10 分钟或锁定后失效 |
| `unlocked` | 解锁期间自动签名，不确认（每次签名仍记录在"最近使用"中） |

缺省或其他值：不在 Agent 中提供。界面中新生成或导入的密钥默认为 `ask`。

**存放位置：本机记录**（`crypto.md` §8.8，种类 `ssh_agent`，ID 为条目 ID 的 16 字节，明文为上表中的值）。策略是这台设备上的授权，与浏览器配对、站点授权一样（第五轮预审 K17）：
- **不随备份回退**：从备份恢复时本机记录保持恢复前的内容（`docs/sync.md` §2），恢复一份旧备份不会让授权变宽；
- **随永久删除一起删除**：被永久删除、又随旧备份回来的密钥没有策略，不在 Agent 中提供；
- **不随同步传播**（M2）：每台设备各自决定哪些密钥可以由 Agent 使用。

**从条目属性迁移**：M1.4 把策略写在条目属性 `ssh_agent` 中（`vault-format.md` §2.1）。第一次解锁时，Keevo 把每把密钥的属性值写入本机记录（已有本机记录的保留本机记录），从条目中删除这个属性，并在本机元数据中记下"已迁移"。此后条目属性一律忽略：恢复一份迁移之前的备份，条目中又出现这个属性，也不会生效。迁移失败时下次解锁再试；迁移完成之前，旧属性中的策略不生效。

### 4.2 来源

由 socket 对端的 pid 读取进程表（不采信对端自述）：

- **命令**：对端进程的命令行（如 `ssh -T git@github.com`）；它的父进程不是 shell 时一并显示（如"由 `git push` 启动"）。
- **应用**：祖先中最近的一个应用包（如 iTerm2、终端、Visual Studio Code）。
- **来源会话**：与 CLI 相同（`spec/cli.md` §5 第 1 条）：(终端设备, 最早一个使用同一终端的祖先)，没有终端时 (最近的应用祖先)。

### 4.3 确认

- 在 Keevo.app 的原生界面显示：来源应用、命令、密钥（条目标题与指纹）、目标主机（§5，有绑定时）。需要 Touch ID；没有启用 Touch ID 时输入主密码。
- 60 秒未确认或用户拒绝：`SSH_AGENT_FAILURE`。同一时间只显示一个确认界面，其他请求排队。
- **转发**：一个连接上收到 `is_forwarding` 为真的绑定之后，这个连接上的签名请求一律逐次确认（不论策略），并在界面中警告：远程主机正在使用你的密钥。

## 5. `session-bind@openssh.com`

```
string  "session-bind@openssh.com"
string  hostkey
string  session identifier
string  signature
bool    is_forwarding
```

- 解析每个字段；之后还有多余字节时失败。
- Ed25519 主机密钥：用它验证对 session identifier 的签名；验证失败时回 `SSH_AGENT_FAILURE`，并且不记录这次绑定。
- 其他算法的主机密钥：记录为"未验证"，只用于显示主机密钥指纹，不作为授权依据。
- 每个连接最多记录 16 次绑定，超过即断开。显示时用最近一次绑定的主机密钥指纹。

## 6. 锁定

- **请求公钥**：锁定时请 Keevo.app 显示解锁界面（"SSH 正在等待解锁"，只在程序坞提示，不抢占焦点；30 秒内最多提示一次，避免后台程序反复打扰），最多等待 30 秒。解锁则正常回答；超时回空列表。
- **签名**：同样等待解锁后再按策略授权；超时 `SSH_AGENT_FAILURE`。
- 锁定时清除全部 `session` 授权。

## 7. Git 提交签名

- `git config gpg.format ssh`，`user.signingkey` 为 `key::<公钥行>`，`gpg.ssh.program` 为 `keevo-ssh-sign`（指向 `keevo` 的软链，`spec/cli.md` §7）：它把 `SSH_AUTH_SOCK` 设为 Keevo 的 Agent，再执行 `/usr/bin/ssh-keygen`，签名经 Agent 完成。
- 界面在执行前显示将运行的命令。

## 8. 未决事项

| 事项 | 计划 |
|---|---|
| ECDSA P-256、RSA（`rsa-sha2-256/512`） | 所需的 34 个 crate 通过供应链审计之后；只做 SHA-2 签名，RSA 至少 2048 位 |
| 导入加密的 OpenSSH 私钥与 PEM 格式 | ✅ 0.2（§3"导入"）。`aes256-gcm@openssh.com` 与加密的 PEM 说明转换方法 |
| 按主机生成 `IdentityFile` + `IdentitiesOnly` 配置（避免"Too many authentication failures"） | 与配置助手一起 |

## 9. 变更记录

| 版本 | 日期 | 说明 |
|---|---|---|
| 0.1 | 2026-11-19 | 首个草案（M1.4） |
| 0.2 | 2026-11-19 | §3 新增"导入"：有口令保护的 OpenSSH 私钥（bcrypt + AES-CTR）与 Ed25519 的 PKCS#8 PEM；不支持的加密方式与格式给出转换方法 |
| 0.3 | 2026-11-20 | §4.1 策略改存本机记录，不再写在条目属性中：恢复备份不回退、永久删除时一起删除、不随同步传播；第一次解锁时迁移 M1.4 的条目属性（第五轮预审 K17） |
