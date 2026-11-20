# Keevo 第五轮第五次确认评审

> **第五轮的第五次确认评审**，由外部模型完成（与正式评审相同）。归档时只把本机路径换成了说明、去掉了指向本机日志的链接，正文未改。处理记录：[2026-11-20-model-review-round5-confirmation5-response.md](2026-11-20-model-review-round5-confirmation5-response.md)。

评审提交：`2b78cd7b74066f57e270caee24d4e164adc78e54`。已在独立临时 clone 中切换并用 `git rev-parse HEAD` 确认；已读第四次确认报告、处理记录及 `git diff 865b652..2b78cd7`。仅复核 Q1–Q3 及相关回归，其余沿用上轮结论。原仓库未修改，未请求真实网络服务，报告未发布。

**1. 冻结结论**

**M1.5 全部草案仍不能一起冻结：导出尚有一项冻结阻塞 R1。**

| spec/REVIEW.md §0 草案 | 能否冻结 | 剩余事项 |
|---|---|---|
| 附件 | 可以 | 沿用上轮结论 |
| 条目详情 v2 | 可以 | 沿用上轮结论；格式向量通过 |
| 导出文件 | **整体不能；加密封装仍可以** | **冻结阻塞 R1**：两份均受损时，低成本的常见口令解释仍会遗漏 |
| 备份与恢复 | 可以 | 沿用上轮结论 |
| 导入 | 可以 | 沿用上轮结论 |
| 泄露检查 | 可以冻结本轮契约 | 沿用上轮结论 |
| SSH Agent 策略的存放 | 可以 | 沿用上轮结论 |

性能及没有满足本轮阻塞标准的其他启发式局限，继续归为**冻结后改进**。其他已接受的延期项维持原决定。

**2. 逐项确认**

- **Q1：部分到位。** `strength.rs:174–240` 确实增加了少量副本的位置候选（±3、基础片段≤64），并将周期上限改为 `(n+3)/2`；后者能覆盖最多删除三字符导致不足两整份的长度。原 Q1 两例现均估计为 **2,491,280、2 分、拒绝导出**。但所有候选仍取自原文连续片段，未恢复被不同副本上的改动破坏的常见基础口令，见 R1。
- **Q2：到位（原反例及下限跳过正确性）。** `strength.rs:242–271` 去重后取前 16 个匹配，以 `base_estimate` 计算总代价并取最小；该函数不再递归调用近似周期估计。原 Q2 现为 **184,110,000、3 分、拒绝导出**。
  
  下限跳过本身**不会让低于门槛的解释漏网**：令 `F=ceil(n/p)×(95n)^e`，基础估计 `g≥1`，所以 `gF≥F`。若 `F≥10¹⁰`，此解释不属于低成本阻塞范围；若下限已达到其他路线或已找到的更低估计，该更低估计仍会保留。前 16 个的截断仍是启发式边界，本轮未发现由此产生的冻结阻塞；新增完好副本对照共 **2,336 组**，debug/release 均通过。R1 在候选生成阶段就缺少正确基础片段，与该跳过无关。
- **Q3：到位。** `strength.rs:282–306` 在同哈希桶内比较真实字符，再分别计数，保留等频取最早的规则。原碰撞测试在两种构建下均返回 `Some((0,1))`。
- **测试口径：正确，覆盖仍有限。** `handles_unicode_and_long_input` 对标注编辑次数的单口令变体，按 `g×ceil(len/p)×(95len)^e<10¹⁰` 才强制断言分数≤3，符合约定；低于门槛样本数量也有非空检查。双口令交替的 `None→0` 是额外检查，不能充当单口令模型证据。现有变体没有覆盖 R1 的“每份各受损一次”。该测试在工作区 debug 和单独 release 运行均通过，不能据此推断整个变体集合都已覆盖。

**3. 新发现**

**R1：两份各替换一个字符，正确的常见基础口令不在候选中**

- **位置**：`crates/keevo-core/src/strength.rs:174–192,227–240`；`spec/export.md` §3（131–138 行）。
- **问题**：第二种候选扩大了原文切片的位置，却仍要求可从原文截取完整基础片段。两份分别受损时，原基础片段及其旋转可能都不存在于任何同长度窗口中。
- **前提**：用户以该类口令保护导出，攻击者取得导出文件；不需要在线服务或账户密钥。
- **影响**：符合约定范围、模型成本低于 10¹⁰ 的口令获准导出，允许选择弱于约定门槛的导出保护；不涉及 KDF 或 AEAD 被突破。
- **严重程度**：**中**。
- **建议**：增加能从受损副本恢复常见基础口令的有界候选，例如用常见口令字典候选校验重复后的编辑距离；不能以原文中存在完好的基础片段为必要条件。
- **证据**：`review5g_r1_damaged_copies_below_model_threshold_are_rejected` 在 debug/release 均失败。输入从 `password123 × 2` 在零起算位置 2、11 分别替换为 `!`、`#` 得到；对正确基础片段的编辑距离为 2，每个 11 字符窗口都含改动。基础估计为 596。

| 输入 | 规范模型成本 | 实际估计 | 导出 |
|---|---:|---:|---|
| `pa!sword123#assword123` | **5,206,775,200** | **156,406,000,000（4 分）** | **允许** |

模型成本为 `596 × 2 × (22 × 95)² = 5,206,775,200 < 10¹⁰`。ASCII 输入不受 NFKD 改写，长度满足导出要求；测试直接断言 `!export_password_ok(...)`，失败。

**是否阻塞冻结：是。** 单个常见口令、两次重复、两处替换，完全落在本轮约定标准内。

**4. 验证记录**

工作目录：仓库的一份临时 clone（本机路径略）。Rust/Cargo 1.97.1；格式向量使用 Python 3.14.7；密码学向量复用已有 Python 3.12.4 venv。依赖版本与 requirements.txt 一致：argon2-cffi 25.1.0、argon2-cffi-bindings 26.2.0、cffi 2.1.1、pycparser 3.12、PyNaCl 1.6.2；未下载依赖。

| 命令 | 结果 |
|---|---|
| `git clone --no-hardlinks <原仓库> <临时副本>`；`git checkout --detach 2b78cd7b74066f57e270caee24d4e164adc78e54`；`git rev-parse HEAD` | 成功，哈希一致 |
| `CARGO_NET_OFFLINE=true cargo test --workspace`（新增测试前） | 沙箱内两个 CLI 测试创建本机 Unix socket 被拒绝，退出 101；获准沙箱外重跑后 **374 passed、0 failed、4 ignored，退出 0** |
| `python3 spec/reference/format_vectors.py --check` | 通过，退出 0 |
| `<venv>/bin/python -I spec/reference/generate_vectors.py --check` | 通过，退出 0 |
| `CARGO_NET_OFFLINE=true cargo test -p keevo-core --lib review5f_ -- --nocapture --test-threads=1` | **5 passed，退出 0** |
| `CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=target/review-release cargo test -p keevo-core --release --lib review5f_ -- --nocapture --test-threads=1` | **5 passed，退出 0** |
| `CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=target/review-release cargo test -p keevo-core --release --lib handles_unicode_and_long_input -- --nocapture --test-threads=1` | **1 passed，退出 0**；debug 已在工作区测试通过 |
| `CARGO_NET_OFFLINE=true cargo test -p keevo-core --lib review5g_ -- --nocapture --test-threads=1` | **1 passed、1 failed，退出 101**：C1 的 2,336 组通过；R1 失败 |
| `CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=target/review-release cargo test -p keevo-core --release --lib review5g_ -- --nocapture --test-threads=1` | **1 passed、1 failed，退出 101**：同 debug |
| `cargo fmt --all`；`git diff --check`；`git apply --reverse --check ../review5g-tests.patch` | 通过 |
| 原仓库 `git rev-parse HEAD`；`git status --porcelain=v1` | 仍为指定提交，工作区干净 |

新增测试完整代码：review5g-tests.patch（已并入仓库，名称以 `review5g_` 开头），仅向 `strength.rs` 测试模块增加两个测试、81 行，未修改产品逻辑。R1 断言修复后应成立的拒绝行为；C1 是通过的对照测试，并非第二项发现。

日志：工作区沙箱首跑、工作区通过、格式向量、密码学向量、旧测试 debug 与 release、变体族 release、新测试 debug 与 release（均未收录）。

`<venv>` 为本机已有的 Python 虚拟环境（路径略）。

