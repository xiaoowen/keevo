# 自动填充回归语料

每个页面是一个独立的 HTML 文件，预期结果写在页面中的 `<script type="application/json" id="keevo-expect">` 里：

```json
{
  "title": "基本登录表单",
  "pattern": "这个页面代表的模式",
  "icons": { "#user": "login", "#search": null },
  "fills": [
    { "anchor": "#user", "expect": { "#user": "$U", "#pass": "$P" } },
    { "anchor": null, "outcome": "no_password_field", "expect": { "#user": "" } }
  ]
}
```

- `icons`：聚焦各字段后应出现的 Keevo 图标类别：`login`、`otp`，`null` 表示不出现。
- `fills`：从某个字段的菜单（`anchor`）或从弹窗（`anchor` 为 `null`）填充后，各字段应有的值。`kind` 默认 `login`，验证码框为 `otp`；`outcome` 默认 `filled`。
- `$U`、`$P`、`$T` 为测试用的用户名、密码与一次性密码。
- 选择器中的 ` >>> ` 表示进入开放的 shadow root；`#id[attr]` 表示读取属性而不是值。

运行：`node apps/browser-extension/test/corpus.mjs`（需要先构建扩展；`scripts/build-extension.sh --test` 会一并运行）。

## 现状与计划

- 目前是 30 个**合成页面**，各自代表一种常见模式或已知的陷阱（蜜罐字段、透明的陷阱密码框、分步登录、注册与修改密码、验证码、网页组件、受控输入框、模态对话框等）。
- 验收标准（`docs/roadmap.md` §3.6）要求"前 100 个登录页的识别率 ≥ 95%"，需要真实网站登录页的快照。收集时：
  - 只保存登录表单所需的 HTML 与内联样式，去掉脚本、追踪代码与任何个人信息；
  - 确认网站条款允许保存页面结构用于测试；
  - 每个快照同样写明预期，文件名以 `site-` 开头。
