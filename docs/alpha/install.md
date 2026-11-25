# 安装 Keevo（Alpha）

Keevo 不使用 Apple 开发者团队（[ADR-0003](../adr/0003-no-apple-developer-team.md)），应用只有临时签名、没有经过 Apple 公证。macOS 因此无法替你确认来源，**下载后请先按第 2 步核对文件**，再打开。

需要：macOS 15 或更新版本，Google Chrome。

## 1. 下载

在 [Releases](https://github.com/xiaoowen/keevo/releases) 中找到要安装的版本，下载全部 4 个文件到同一个文件夹：

| 文件 | 内容 |
|---|---|
| `Keevo-<版本>-macos.zip` | Keevo.app（含浏览器扩展用的 native host 与 `keevo` 命令行工具） |
| `Keevo-<版本>-chrome-extension.zip` | Chrome 扩展 |
| `SHA256SUMS` | 两个 zip 的 SHA-256 |
| `SHA256SUMS.sigstore.json` | `SHA256SUMS` 的 Sigstore 签名 |

## 2. 核对来源与完整性

发布包由本仓库的 GitHub Actions 工作流 `release.yml` 在 `v*` 标签上构建，并用 Sigstore 签名 `SHA256SUMS`。核对分两步：先确认 `SHA256SUMS` 确实来自这个工作流，再用它核对两个 zip。**只核对校验和不够**：校验和与安装包放在同一处，可以被一起替换。

安装 [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)（3.0 或更新版本，发布时用 3.1.4 签名并验证），例如 `brew install cosign`。在下载文件夹中运行（把 `v0.1.0-alpha.1` 换成你下载的版本）：

```sh
TAG=v0.1.0-alpha.1
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/xiaoowen/keevo/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
shasum -a 256 -c SHA256SUMS
```

两条命令分别输出 `Verified OK` 与每个 zip 的 `OK` 才继续。签名身份与 issuer 必须与上面完全相同；不要接受"任意有效的 Sigstore 签名"。任何一步失败，都不要安装，请按 [SECURITY.md](../../SECURITY.md) 报告。

签名只证明安装包由这个仓库的发布工作流构建，不能替代 Apple 的恶意软件检查。

## 3. 安装应用

1. 解压 `Keevo-<版本>-macos.zip`，把 `Keevo.app` 拖进"应用程序"文件夹。
2. 打开 Keevo。macOS 会提示无法验证开发者，选"完成"（不要选"移到废纸篓"）。
3. 打开"系统设置 → 隐私与安全性"，滚动到"安全性"，在关于 Keevo 的提示旁点"仍要打开"，用密码或 Touch ID 确认，再在弹出的对话框中点"打开"。各版本 macOS 的文字可能略有不同，以你看到的界面为准。
4. 之后正常打开即可，不会再提示。

第一次打开时按引导设置主密码，并**保存或打印应急包**：忘记主密码、或者换一台 Mac 时，需要应急包中的账户密钥。Keevo 无法替你找回。

## 4. 连接 Chrome

1. 把 `Keevo-<版本>-chrome-extension.zip` 解压到一个**长期保留**的位置（例如 `~/Applications/keevo-chrome-extension`）。Chrome 从这个文件夹加载扩展，删除或移动它，扩展就会失效。
2. 在 Chrome 中打开 `chrome://extensions`，打开右上角的"开发者模式"，点"加载已解压的扩展程序"，选择上面的文件夹。
3. 在 Keevo 中打开"设置 → 浏览器"，确认"允许扩展连接 Keevo"已打开（首次使用时在引导中点过"安装扩展"的，这一项已经打开）。这一页在还没有配对时也列出了上面两步。
4. 点 Chrome 工具栏中的 Keevo 图标，选"与 Keevo 配对"。Keevo 中会弹出确认窗口：**核对两边显示的 6 个词完全一致**，再确认配对。
5. 想在输入框旁显示 Keevo 图标，在扩展弹窗中打开"在输入框旁显示 Keevo 图标"，按提示允许读取和更改网站数据。不开启时，用扩展弹窗或快捷键 `⌘⇧L` 填充。

## 5. 命令行工具与 SSH（可选）

- **命令行工具**：Keevo 的"设置 → 开发者 → 命令行工具"中点"安装到 ~/.local/bin"。终端找不到 `keevo` 时，把 `export PATH="$HOME/.local/bin:$PATH"` 加到 `~/.zshrc`。运行 `keevo --help` 查看用法。
- **SSH Agent 与 Git 签名**：同一页中的 SSH 与 Git 设置，按提示写入 `~/.ssh/config` 与 Git 配置。

## 6. 更新

有新版本时，Keevo 会在"设置 → 通用"与侧边栏底部提示（默认每天检查一次，可以关闭），但不会自动下载或安装。更新步骤：

1. 按第 1、2 步下载并核对。
2. 退出 Keevo（`⌥⌘Q`，或菜单栏图标中的"退出 Keevo"；`⌘Q` 只是退到后台），用新的 `Keevo.app` 替换旧的。第一次打开新版本时，可能需要再按第 3 步放行一次。
3. 用新的扩展文件夹替换旧的（保持同一位置），在 `chrome://extensions` 中点 Keevo 的刷新按钮。
4. 在"设置 → 浏览器"中再点一次"安装"（应用更新后 native host 的路径不变时显示"已安装"，可以跳过）。

数据保存在 `~/Library/Application Support/Keevo/`，替换应用不会影响数据，浏览器的配对也会保留。

## 7. 卸载

1. 在 Chrome 中移除 Keevo 扩展。
2. 退出 Keevo（`⌥⌘Q`），删除 `Keevo.app`。
3. 删除 `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/io.github.xiaoowen.keevo.json`，以及 `~/.local/bin` 中的 `keevo` 与 `keevo-ssh-sign`（如果安装过）。
4. 要连同数据一起删除，再删除 `~/Library/Application Support/Keevo/`。**删除前确认已经导出或不再需要其中的数据**，删除后无法恢复。

## 遇到问题

- 一般问题与建议：在 GitHub 上提 issue，写明 Keevo 的版本（"关于 Keevo"中的版本与构建号）、macOS 与 Chrome 的版本。
- 安全问题：不要公开提 issue，按 [SECURITY.md](../../SECURITY.md) 私下报告。
