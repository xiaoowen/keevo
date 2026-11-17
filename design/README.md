# Keevo 设计系统 v0

体验原则见 [docs/ux.md](../docs/ux.md)。本目录是视觉层的**唯一来源**：令牌改在这里，两端产物由脚本生成，不手改。

## 结构

```
design/
├── tokens/
│   ├── base.json            原始色板、网站图标色、间距、圆角、字体、动效（主题无关）
│   ├── theme.light.json     浅色主题的语义颜色
│   ├── theme.dark.json      深色主题
│   ├── theme.light-hc.json  浅色 + 增强对比度（只写差异）
│   └── theme.dark-hc.json   深色 + 增强对比度（只写差异）
├── build_tokens.py          校验对比度，生成下列产物
└── contrast.md              对比度报告（生成）
```

| 产物 | 使用方 |
|---|---|
| `apps/browser-extension/static/tokens.css` | 浏览器扩展：CSS 自定义属性 `--kv-*`，按 `prefers-color-scheme`、`prefers-contrast`、`prefers-reduced-motion` 切换 |
| `apps/macos/Sources/Keevo/DesignTokens.swift` | macOS 应用：`KV.Colors.*` 等，随系统外观（含「增强对比度」）自动切换 |

格式遵循 W3C 设计令牌社区组（DTCG）的 `$type` / `$value` 约定，值可以用 `{color.teal.600}` 引用原始色板。

```bash
python3 design/build_tokens.py          # 修改令牌后重新生成
python3 design/build_tokens.py --check  # CI：对比度达标且产物已更新
```

## 颜色

**一个品牌色，其余皆中性。** Keevo 青（teal）传达"安静的安全感"，并与常见密码管理器的蓝色区分开。状态色只在需要时出现。

### 关键取舍

这些决定都来自对比度计算，不靠目测：

| 决定 | 原因 |
|---|---|
| 品牌色分成 `accent.fill`（`teal.600`）与 `accent.fg`（浅色主题用 `teal.700`） | `teal.600` 作为文字放在侧边栏底色上只有 4.49:1，差一点不到 AA；作为按钮底色配白字是 4.88:1 |
| 浅色次要文字用 `neutral.600`（`#636366`），不用常见的 `#6E6E73` | 后者在侧边栏底色上只有 4.66:1，余量太小 |
| 两种主题的按钮都是 `teal.600` 配白字 | `teal.500` 配白字只有 3.40:1；深色主题提高的是品牌色文字的亮度，而不是按钮底色 |
| 区分装饰性分隔线 `border.subtle` 与控件边界 `border.control` | 分隔线不要求对比度；输入框等控件边界按 WCAG 1.4.11 需要 ≥ 3:1 |

### 对比度规则

由 `build_tokens.py` 强制执行，不达标时生成失败：

| 用途 | 普通主题 | 高对比主题 |
|---|---|---|
| 主要文字 | ≥ 7:1 | ≥ 7:1 |
| 次要文字、品牌色文字、状态色文字、秘密字符分色 | ≥ 4.5:1 | ≥ 7:1 |
| 占位文字 | ≥ 3:1 | ≥ 4.5:1 |
| 控件边界、焦点环 | ≥ 3:1 | ≥ 4.5:1 |
| 网站图标上的白字 | ≥ 4.5:1 | ≥ 4.5:1 |

当前全部 160 组检查都已达标，详见 [contrast.md](contrast.md)。

### macOS 上的用法

- **品牌与状态**：品牌色、状态色、秘密显示、网站图标一律用 `KV.Colors`。
- **系统控件**：侧边栏、工具栏、列表选中态等保留系统材质与行为（Liquid Glass、选中高亮），以保证原生感，并跟随用户的系统设置。
- **全局强调色**：设为 `KV.Colors.accentFill`。

## 字体

| 令牌 | 规格 | 用途 |
|---|---|---|
| `large-title` | 26 / 32，Bold | 首次使用、锁屏标题 |
| `title` | 20 / 26，Semibold | 条目详情标题 |
| `headline` | 15 / 20，Semibold | 分组标题、扩展弹窗标题 |
| `body` / `body-strong` | 13 / 18 | 正文（与 macOS 系统一致） |
| `footnote` | 12 / 16 | 副标题、说明 |
| `caption` | 11 / 14 | 角标、序号 |
| `mono` | 13 / 18，Medium，等宽 | 秘密值、密钥、命令 |
| `mono-large` | 18 / 24，Medium，等宽 | 账户密钥、配对码 |
| `large-type` | 28 / 36，Medium，等宽 | 大字显示 |

中文字体回退到苹方（PingFang SC）。

## 间距、圆角与动效

- **间距**：4pt 网格（`space.1` = 4），另有 2 / 6 两个微调值。
- **圆角**：`xs` 3、`sm` 5、`md` 8、`lg` 12、`xl` 16。网站图标用尺寸的 28%（连续曲率）。
- **动效**：`fast` 120ms、`base` 200ms、`slow` 320ms，缓动 `cubic-bezier(0.2, 0, 0, 1)`。只用于状态变化（锁定与解锁、复制成功、验证码刷新）。"减弱动态效果"开启时，CSS 端时长变为 0，Swift 端由调用方改用瞬时变化。

## 核心组件

| 组件 | macOS（`Components.swift`） | 扩展 | 规则 |
|---|---|---|---|
| 网站图标 | `SiteIcon` | `.site-icon` | 见下文算法 |
| 秘密值 | `SecretText` | — | 默认圆点；显示需用户主动操作 |
| 字符分色 | `classifiedText`、`CharClass` | — | 字母：`fg.primary`；数字：`secret.digit`；符号：`secret.symbol` |
| 大字显示 | `LargeTypeView` | — | 每字符一格，带序号与图例 |
| 提示横幅 | `Banner` | `.banner` | 信息 / 成功 / 注意 / 危险，每级图标不同，不只靠颜色区分 |
| 配对码 | `PairingCode` | `.sas` | 6 组两位，两端排版一致 |

待做：字段行、TOTP 倒计时环（M1.2）、密码强度条、空状态、授权弹窗。

### 网站图标

本地生成，不向任何第三方请求 favicon，因为那样会暴露你在哪些网站有账户。两端必须使用同一算法：

```
key     = 网址主机名转小写并去掉开头的 "www."；没有网址时用标题
index   = FNV-1a-32(UTF-8(key)) mod 8          // 取 site-1 … site-8，即 index + 1
initial = 标题的第一个字形（拉丁字母转大写）；标题为空时用 key 的第一个字形
```

**对照样例**：

| key | FNV-1a-32 | 颜色 |
|---|---|---|
| `github.com` | `0x49361819` | `site-2` |
| `example.com` | `0x431ceb26` | `site-7` |
| `localhost` | `0x0150773a` | `site-3` |
| `mail.qq.com` | `0x6b4401d5` | `site-6` |
| `个人笔记` | `0x5371398e` | `site-7` |

## 设计稿

高保真设计稿（锁屏、主窗口、条目详情、扩展弹窗、内联菜单）链接见 [docs/ux.md §7](../docs/ux.md#7-设计系统)。设计稿使用的颜色与本目录的令牌一致。
