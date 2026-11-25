Keevo 0.1.0-alpha.2：修复 0.1.0-alpha.1 安装后发现的问题。功能与已知限制与上一版相同，见 [0.1.0-alpha.1 的发布说明](https://github.com/xiaoowen/keevo/releases/tag/v0.1.0-alpha.1)。

**安装或更新之前请先阅读[安装说明](https://github.com/xiaoowen/keevo/blob/v0.1.0-alpha.2/docs/alpha/install.md)**：应用没有经过 Apple 公证，安装前要用 Sigstore 核对下载的文件，第一次打开需要在系统设置中放行。

**从 0.1.0-alpha.1 更新**：按安装说明的"更新"一节，替换 `Keevo.app` 与扩展文件夹（这一版的扩展也有改动），再在 `chrome://extensions` 中点 Keevo 的刷新按钮。数据与浏览器的配对都会保留。

## 修复

- **Touch ID**：在锁屏上主动点 Touch ID 解锁后，进入主界面时会再弹出一次 Touch ID。
- **首次使用 · 用 Touch ID 解锁**：中途锁定或退出后重开，"开启 Touch ID"一直不能点。现在会就地请你再输入一次主密码。
- **首次使用 · 连接浏览器**："安装扩展"打开的是 Chrome 应用商店，显示"此商品无法购买或下载"（扩展还没有上架）。现在就地给出三步：从发布页下载、在 `chrome://extensions` 中加载已解压的扩展、在扩展中配对。
- **设置 → 浏览器**：原来的"已安装"只表示 Keevo 这一侧登记了本机通道，并不代表 Chrome 装了扩展。现在改为开关"允许扩展连接 Keevo"；"Keevo 扩展"一行按是否配对显示；还没有配对时列出同样的三步。
- **Chrome 扩展**：输入框旁的菜单在 Keevo 锁定时打开，解锁后仍停在"已锁定"，要关掉再点一次图标。现在解锁后菜单自动显示条目。

## 反馈

- 问题与建议：在 GitHub 上提 issue。
- **安全问题请不要公开提 issue**，使用仓库的 Security → Report a vulnerability（见 [SECURITY.md](https://github.com/xiaoowen/keevo/blob/v0.1.0-alpha.2/SECURITY.md)）。
