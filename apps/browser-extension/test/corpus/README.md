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

## 合成页面

37 个合成页面，各自代表一种常见模式或已知的陷阱：蜜罐字段、透明的陷阱密码框、分步登录、注册与修改密码、验证码、网页组件、受控输入框、模态对话框等。31–37 是从真实网站快照中归纳出的模式与对应的反例：分步登录第一步中单独的邮箱或账号框（以及不应显示图标的订阅表单、忘记密码），登录页误标为 `new-password` 的密码框（以及只有一个新密码框的注册表单），用户名与密码分别在两个网页组件中。必须全部通过。

## 真实网站的登录页快照

验收标准（`docs/roadmap.md` §8）要求"前 100 个网站的登录页识别率 ≥ 95%"。

- **清单与预期**：[`../sites/sites.json`](../sites/sites.json)。约 50 个全球主流网站、25 个开发者服务、25 个国内网站，另有几个候补。
- **快照只保存在本机**（`test/sites/snapshots/`，git 忽略），不提交：页面内容属于各网站。仓库只提交清单、采集脚本、预期与结果（[`../sites/results.md`](../sites/results.md)）。
- **采集**：`node apps/browser-extension/test/capture-sites.mjs [--headful] [网站 id …]`
  - 用真实 Chrome 打开登录页，每个网站一个全新的浏览器上下文：没有 cookie，不登录，不输入，不提交。
  - `steps` 只做点击，例如切换到"密码登录"的选项卡。登录表单在 iframe 中时，`frame` 指定采集该 iframe 的页面。
  - 保存渲染后的完整 DOM：去掉脚本、事件处理属性与隐藏字段的值，内联样式表，开放的 shadow root 序列化为声明式 shadow DOM。同时保存截图与输入框摘要（`site-<id>.fields.json`），用来写预期。
- **预期**：按截图与输入框摘要判断哪个是用户名框、密码框、验证码框，不参考扩展的识别结果。格式同合成页面，写在清单的 `expect` 中。
- **不计入**：只看能否采集到登录表单，与识别结果无关。例如只有扫码登录、被人机验证拦下、没有密码登录。原因写在 `excluded` 中。
- **运行**：`node apps/browser-extension/test/corpus.mjs` 有快照时一并检查；`--record` 把结果写入 `results.md`。
  - 测试用的 Chrome 解析不了 localhost 以外的域名，快照不会访问真实网站。
  - 网站会改版，重新采集后预期可能需要更新。
