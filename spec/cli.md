# 命令行工具 `keevo` 与 Vault Service 的协议

- **版本**：0.3（草案，M1.4）
- **相关**：`spec/ipc.md`（浏览器扩展的协议，分帧与对端校验的机制相同）、`spec/secret-refs.md`（`keevo://` 引用）、`docs/architecture.md` §6–§7。

## 1. 范围与拓扑

```
keevo（CLI）──Unix socket（cli.sock）──► Keevo.app 中的 Vault Service ──► 保险库
                                              │
                                              └─ 原生确认界面（会话授权）
```

- CLI 不持有任何密钥，也不打开数据库；每次取值都向 Keevo.app 请求。Keevo.app 没有运行时，CLI 报"无法连接"。
- 与浏览器扩展使用**不同的 socket**：两者的对端身份、消息集合与授权方式都不同，分开后互不影响。
- 不加 Noise 端到端加密：CLI 本身就是被校验的端点（§2），Unix socket 的数据只经过内核。浏览器协议需要 Noise，是因为 native host 只是中继，真正的端点在浏览器里。

## 2. socket 与对端身份

- **路径**：
  - release：`~/Library/Application Support/Keevo/ipc/cli.sock`；
  - debug：`~/Library/Application Support/Keevo-Dev/ipc/cli.sock`，可用环境变量 `KEEVO_DEV_CLI_SOCKET` 覆盖（release 忽略）。
  - 所在目录权限 0700。
- **服务校验 CLI**：与 native host 相同（`spec/ipc.md` §3.1）。构建时先签名 `keevo`，取得它的 cdhash，编译进主程序；服务通过 socket 对端的 audit token 取得代码签名，要求 cdhash 等于编译进来的值之一。
  - 从源码单独编译、没有连同 Keevo.app 一起构建的 CLI 不被接受。要使用自己编译的 CLI，请用 `scripts/package-macos.sh` 构建整个应用，它会固定这次构建的 CLI。
  - 开发构建（debug）没有编译进 cdhash 时只依赖目录权限，release 构建拒绝这种配置。
- **CLI 不校验服务**：Keevo 不绑定开发者团队（ADR-0003），没有可以固定的服务签名。同用户进程可以替换 socket，冒充服务返回伪造的值。CLI 除了创建、修改条目时用户提供的值之外，不向服务发送任何秘密。这属于 `docs/security.md` A7（同用户恶意软件）的残余风险。

## 3. 分帧与消息

- **帧**：与 `spec/ipc.md` §2 的 socket 帧相同：4 字节大端长度 + 内容，长度 1 字节到 1 MiB。内容是 UTF-8 JSON 对象。
- **握手**：连接后 CLI 先发 `{"v": 1, "client": "keevo-cli", "version": "<CLI 版本>"}`。服务回 `{"v": 1, "ok": true, "version": "<Keevo 版本>"}`；版本不支持时回 `{"v": 1, "ok": false, "error": "unsupported_version"}` 并断开。
- **请求与响应**：之后一问一答，CLI 不得在收到响应之前发送下一个请求。
  - 请求：`{"id": <u32>, "op": "<操作>", …参数}`；
  - 成功：`{"id": <同一个 id>, "ok": true, "result": <结果>}`；没有结果的操作（如 `lock`）`result` 为 `null`；
  - 失败：`{"id": <同一个 id>, "ok": false, "error": "<错误码>", "message": "<给人看的说明>"}`。
  - 未知字段一律拒绝（`bad_request`）。服务在任何错误之后都可以断开连接。

## 4. 操作

| `op` | 会话授权 | 参数 | 结果 |
|---|---|---|---|
| `status` | 否 | — | `locked`（布尔）、`authorized`（这个终端会话是否已授权）、`expires_in`（秒，未授权时省略） |
| `lock` | 否 | — | — |
| `resolve` | 是 | `refs`：字符串数组，1–256 个 | `values`：与 `refs` 一一对应，每项是 `{"value": "…"}` 或 `{"error": "<错误码>", "message": "…"}` |
| `items` | 是 | `vault`（可选，名称或 ID）、`query`（可选，搜索语法同应用） | `items`：`[{"id", "vault", "title", "type", "subtitle", "tags", "favorite"}]`，不含回收站 |
| `item` | 是 | `item`：`<保险库>/<条目>` 或条目 ID；`reveal`：布尔 | `{"id", "vault", "title", "type", "tags", "fields": [{"id", "section", "label", "kind", "concealed", "value"?}]}`。`reveal` 为假时隐藏字段不含 `value` |
| `totp` | 是 | `item`：同上 | `{"code", "remaining"}`；条目没有或有多个一次性密码字段时 `not_found` / `ambiguous` |
| `create` | 是 | `vault`、`type`、`title`、`fields`：`[{"section"?, "label", "value"}]` | `{"id"}`。从类型模板开始，`fields` 按名称填入模板字段；没有同名字段时新增文本字段 |
| `edit` | 是 | `item`：同上；`title`（可选）；`set`：`[{"field", "value"}]` | — |

- `resolve` 中每个引用独立解析（`spec/secret-refs.md`），一个失败不影响其他。
- 秘密只出现在 `resolve`、`item`（`reveal` 为真）、`totp` 的响应中。
- `create`、`edit` 只修改文本类字段；键值对、恢复码与附件需要在 Keevo.app 中编辑。

### 4.1 锁定时

需要保险库的请求在锁定时：服务请 Keevo.app 显示解锁界面（带上"命令行工具正在等待解锁"），最多等待 60 秒。期间解锁则继续处理；超时返回 `locked`。

## 5. 会话授权

终端里的 CLI 按**终端会话**授权，而不是按次：

1. **会话键**由服务从内核读取，不采信 CLI 的自述：
   - 由 socket 对端的 audit token 得到 CLI 进程；
   - 有控制终端时：会话键 = (终端设备, 最早一个使用同一终端的祖先进程的 pid 与启动时间)。这个祖先通常是终端标签页中的登录 shell；
   - 没有控制终端时（例如编辑器的任务）：会话键 = (无终端, 父进程的 pid 与启动时间)。
   - 启动时间参与比较，pid 被复用后不会继承授权。
2. **第一次请求**时在 Keevo.app 的原生界面确认，显示：
   - 终端应用（祖先中最近的一个应用包，如 iTerm2、终端、Visual Studio Code）；
   - 父进程（如 `zsh`）；
   - CLI 的命令行（如 `keevo run --env-file .env.keevo -- npm run dev`，最多 200 个字符）。
   - 确认需要 Touch ID；没有启用 Touch ID 时输入主密码（与"重新验证"相同，`docs/ux.md` §5）。
   - 60 秒未确认或用户拒绝：返回 `denied`。同一会话在被拒绝后 10 秒内的请求直接返回 `denied`，避免脚本循环弹窗。
3. **有效期**：闲置 10 分钟失效，从授权起最长 12 小时。锁定、Keevo 退出时全部失效。
4. 已授权的会话在"设置 → 开发者"中列出，可以逐个撤销。

同一时间只显示一个确认界面；其他会话的请求排队，排到时已超过 60 秒的按拒绝处理。

## 6. 错误码

| 错误 | 含义 |
|---|---|
| `bad_request` | 消息格式错误、缺少或多出参数 |
| `unsupported_version` | 协议版本不支持 |
| `locked` | 已锁定，等待解锁超时 |
| `denied` | 用户拒绝或未在 60 秒内确认会话授权 |
| `not_found`、`ambiguous`、`bad_ref`、`unsupported_field`、`invalid_otp` | 见 `spec/secret-refs.md` §6 |
| `invalid` | `create`、`edit` 的参数不合法（类型不存在、字段不是文本类等） |
| `failed` | 其他内部错误 |

## 7. CLI 的行为约定

- **输出**：默认给人看，`--format json` 供脚本使用。除非显式指定 `--reveal`，否则不在终端上显示秘密：
  - `keevo read` 的标准输出是终端时要求 `--reveal`（显示时末尾加换行）；输出到管道或文件（如 `$(keevo read …)`）时直接输出值，末尾不加换行，需要时加 `--newline`。
  - `keevo item get` 只在 `--reveal` 时显示隐藏字段的值。
- **退出码**（稳定，写入文档）：

| 退出码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 其他错误 |
| 2 | 用法错误 |
| 3 | 无法连接 Keevo（没有运行，或不是这个 Keevo 的 CLI） |
| 4 | 已锁定 |
| 5 | 未授权（拒绝或超时） |
| 6 | 引用无法解析（`not_found`、`ambiguous`、`bad_ref`、`unsupported_field`、`invalid_otp`） |

- **获取引用**：用户通常不知道引用的确切写法。`keevo --help` 写明引用的格式与获取方法（在 Keevo 中右键点字段，选"复制 `keevo://` 引用"，生成规则见 `spec/secret-refs.md` §5；或用 `keevo item get` 查看字段与分区的名称）；退出码为 6 时，标准错误在报错之后附一行同样的提示。

- **`keevo run`**：
  - 环境变量来自 `--env-file`（可多次）与 `--env KEY=<值或引用>`（可多次），后者覆盖前者；也会解析当前环境中值为 `keevo://…` 的变量。
  - `--env-file` 的格式：每行 `KEY=VALUE`，忽略空行与 `#` 开头的行，允许行首 `export `；`VALUE` 两端成对的单引号或双引号会去掉。`VALUE` 整体是 `keevo://` 引用时解析，否则原样使用。
  - 所有引用在启动子进程之前一次解析（一个 `resolve` 请求）；任何一个失败都不启动子进程。
  - **遮蔽**：默认把子进程标准输出与标准错误中出现的已解析值（长度至少 4 个字符）替换为 `<concealed by keevo>`。跨两次写入的值在 100 毫秒内会被拼接后遮蔽，间隔更长时可能漏遮，因此遮蔽只是防止意外露出，不是安全边界。`--no-masking` 让子进程直接继承终端。
  - **伪终端**：遮蔽时，`keevo` 的标准输出（或标准错误）是终端的那一路，子进程连到一个新的伪终端，`keevo` 从主端读取、遮蔽后写出，因此子进程看到的仍是终端，保留颜色、进度条与行缓冲；伪终端的窗口大小与 `keevo` 所在的终端一致，子进程运行期间每 200 毫秒同步一次。输出被重定向到文件或管道的那一路仍用管道。标准输入不经过 `keevo`，子进程直接从原来的终端读取。伪终端不是子进程的控制终端（不调用 `setsid`），作业控制与 Ctrl-C 照常作用于原来的终端。打不开伪终端时退回管道。
  - 子进程的退出码原样作为 `keevo run` 的退出码；被信号终止时为 128 + 信号编号。
- **`keevo inject -i <模板> -o <输出>`**：把模板中的 `{{ keevo://… }}`（花括号内两侧空白可选）替换为解析后的值；输出文件权限 0600，已存在时需要 `--force`；不给 `-o` 时写到标准输出（标准输出是终端时同样要求 `--reveal`）。
- **`keevo ssh-sign`**：把参数原样交给 `/usr/bin/ssh-keygen`，并把 `SSH_AUTH_SOCK` 设为 Keevo 的 SSH Agent（`spec/ssh-agent.md`），让 `ssh-keygen -Y sign` 经 Agent 签名，私钥不离开 Keevo。Git 的 `gpg.ssh.program` 只能是一个可执行文件，因此 CLI 以 `keevo-ssh-sign` 的名字运行（软链）时等同于 `keevo ssh-sign`。

## 8. 未决事项

| 事项 | 计划 |
|---|---|
| 子进程使用伪终端，在保留颜色的同时遮蔽输出 | ✅ 0.2（§7） |
| 信任单独编译的 CLI（固定其 cdhash，需要读取对端的签名信息） | 有需求时 |
| 外部评审，冻结 1.0 | M1.4 之后 |

## 9. 变更记录

| 版本 | 日期 | 说明 |
|---|---|---|
| 0.1 | 2026-11-19 | 首个草案（M1.4） |
| 0.2 | 2026-11-19 | §7：遮蔽时输出到终端的那一路改用伪终端 |
| 0.3 | 2026-11-23 | 退出码之后写明怎样获取引用：`keevo --help` 中的说明，退出码 6 时标准错误附一行提示。协议不变 |
