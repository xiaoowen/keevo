# Keevo 第五轮第三次确认评审

> **第五轮的第三次确认评审**，由外部模型完成（与正式评审相同）。归档时只把本机路径换成了说明、去掉了指向本机日志的链接，正文未改。处理记录：[2026-11-20-model-review-round5-confirmation3-response.md](2026-11-20-model-review-round5-confirmation3-response.md)。

评审提交：`28074f083d3c1de1f8bf41953ef1b3be60b5e69c`。仅核对 N1、N2，范围为 `git diff 455d633..28074f0`，先读了上次确认报告及处理记录。在独立临时 clone 中切换提交，`git rev-parse HEAD` 完全相符。原仓库未修改；没有请求真实网络服务，也没有发布报告。

**1. 冻结结论**

**仍不建议把 M1.5 全部草案一起冻结。唯一冻结阻塞为 P1，即 N1 尚未覆盖的首段插入变体。**

| 草案 | 结论 | 剩余事项 |
|---|---|---|
| 附件 | 可以冻结 | 沿用上轮结论及边界 |
| 条目详情 v2 | 可以冻结 | 沿用上轮结论；格式向量通过 |
| 导出文件 | **整体暂缓；加密封装仍可冻结** | 修复 P1，并使 §3 的效果描述与模型边界一致 |
| 备份与恢复 | 可以冻结 | 沿用上轮结论及边界 |
| 导入 | **可以冻结** | N2 已解决 |
| 泄露检查 | 可以冻结本轮契约 | 沿用上轮结论；未请求真实服务 |
| SSH Agent 策略的存放 | 可以冻结 | 沿用上轮结论 |

P2 为**冻结后可以继续改进**的性能建议，不是冻结阻塞。其他已接受的延期项维持原决定；本轮没有重新审计已确认模块。

**2. 逐项确认**

- **N1：部分到位。** 三路取最小已实现，上轮 `review5d_n1_` 及新增家族回归通过，但还存在模型内明显廉价的 4 分变体，见 P1。
  - **模型判断**：复制按“重复次数 × 来源选择数”、改动按“位置数 × 95”计费，作为常见弱口令筛选的启发式是合理的。它近似枚举构造选择，不是精确候选空间或熵下界：LZ 的 token 数并不枚举全部来源偏移和长度，多处改动的乘方也会重复计数。基础片段已有一定成本、叠加改动后达到 4 分，本身不构成缺陷。§3 第 133–134 行笼统的“达不到很强”应改成有条件表述，与处理记录中的解释保持一致。
  - **随机长口令**：debug、release 各检验 24 个 CSPRNG 样本，覆盖 65、96、256、1024 字符及均匀数字/可打印 ASCII，全部为 4 分；既有长口令句回归也通过。未发现系统性误判，但抽样不是全输入证明。
  - **耗时**：入口最多取 1024 个 Unicode 标量，近似周期递归的片段长度至少减半；未发现无界增长路径。密集 l33t 输入仍有明显长尾，见 P2；单一 5000 字符重复样本不能代表最坏情况。
- **N2：到位。** `import/keevo.rs:122、140` 均改为保留 `f.purpose`；`Builder::push → import_items → template_doc → add_field` 没有再次清空用途。原 `review5d_n2_own_export_preserves_structured_field_purpose` 通过，覆盖两个结构化字段携带 `notes` 的正常导出、解析往返。

**3. 新发现**

**P1：首段插入一个字符，廉价重复仍被接受为“很强”**

- **位置**：`crates/keevo-core/src/strength.rs:150、195、203`；`spec/export.md` §3。
- **问题**：近似周期按同余位置比较，只处理替换型差异；插入造成错位。LZ 从受损首段开始贪心分解，把其部分内容当成高成本新内容，后续识别出复制也无法消除这笔高估。
- **前提**：用户选择该类口令保护导出文件，并依赖 4 分门槛；攻击者取得文件。
- **影响**：明确廉价的常见口令变体获准保护全部导出内容；不涉及 Argon2id 或 AEAD 被突破。
- **严重程度**：**中，冻结阻塞**。
- **建议**：覆盖首个基础片段内部的插入/删除对齐，或采用能恢复完整重复片段的其他有界候选分析；保留各位置的家族回归，不只特判下列字符串。目标是降低该家族的明显高估，无须证明所有弱口令都被拒绝。
- **证据**：`review5e_p1_single_insertion_in_repeated_common_password_is_cheap` 在 debug/release 均失败，且确认 `export_password_ok=true`：

| 构造（下标从 0 起） | 字符数 | 按模型枚举代价 | 实际估计 / 得分 |
|---|---:|---:|---:|
| `"password".repeat(10)`，在下标 2 插入 `!` | 81 | ≤230,850 | 124,830,000,000 / 4 |
| 同上，在下标 3 插入 `!` | 81 | ≤230,850 | 1,240,200,000,000 / 4 |
| `"password123".repeat(10)`，在下标 4 插入 `!` | 111 | ≤62,848,200 | 34,740,000,000 / 4 |

第一例的枚举预算为 **3 × 10 × 81 × 95 = 230,850**：基础候选、重复次数、插入位置、插入字符。即使再计入少量操作类型选择，也远低于 10¹⁰；这是候选枚举分析，不是实测破解时间。因此 P1 不是“模型本身已经算到 10¹⁰，仍要求拒绝”的变体。

**P2：密集 l33t 输入存在性能长尾**

- **位置**：`strength.rs:201–204、521、527–532`，即逐段分析和 l33t 字典匹配路径。
- **问题/前提**：1024 字符由多种 l33t 符号组成、缺少长重复时，多个窗口反复执行大量替换映射和字典扫描。
- **影响**：本机单次估计明显变慢，批量处理可能累积延迟；未证明生产环境拒绝服务，也不判定为本提交引入的回归。
- **严重程度**：**建议，非冻结阻塞**。
- **建议**：为此类输入补 release 性能预算，优化或限制总匹配工作量；不能仅凭字符数上限或易压缩样本断言所有输入都很快。
- **证据**：`review5e_p2_adversarial_inputs_finish_within_five_seconds` 使用确定性构造。最终 debug 运行约 **13.69 秒**，5 秒断言失败；release 约 **0.68 秒**，通过。5 秒沿用既有长输入测试的宽松检查尺度，**不是规范要求或生产 DoS 阈值**。其他构造包括互异 Unicode、近似周期、四处分隔的长重复，release 均小于 14 ms。

**4. 验证记录**

环境：Rust/Cargo 1.97.1；格式向量使用 Python 3.14.7；密码学向量复用本机已有 venv 的 Python 3.12.4。依赖与 `spec/reference/requirements.txt` 一致：argon2-cffi 25.1.0、argon2-cffi-bindings 26.2.0、cffi 2.1.1、pycparser 3.12、PyNaCl 1.6.2；没有下载依赖。

| 命令 | 结果 |
|---|---|
| `git clone --no-hardlinks <原仓库> repo`；`git checkout --detach 28074f083d3c1de1f8bf41953ef1b3be60b5e69c`；`git rev-parse HEAD` | 成功，哈希完全一致 |
| `CARGO_NET_OFFLINE=true cargo test --workspace`（未加新测试的基线） | 沙箱首次运行因两个 CLI 测试创建本机 Unix socket 被拒绝，退出 101；获准沙箱外重跑后 **366 passed、0 failed、4 ignored，退出 0** |
| `python3 spec/reference/format_vectors.py --check` | 通过，退出 0 |
| `<venv>/bin/python -I spec/reference/generate_vectors.py --check` | 通过，退出 0 |
| `CARGO_NET_OFFLINE=true cargo test -p keevo-core --lib review5e_ -- --nocapture --test-threads=1` | **1 passed、2 failed，退出 101**：随机对照通过，P1、P2 失败 |
| `CARGO_NET_OFFLINE=true cargo test -p keevo-core --release --lib review5e_ -- --nocapture --test-threads=1` | **2 passed、1 failed，退出 101**：随机对照、P2 通过，P1 失败 |
| `cargo fmt --all`；`git diff --check`；`git apply --reverse --check ../review5e-tests.patch` | 通过 |
| 原仓库 `git rev-parse HEAD`；`git status --porcelain=v1` | 仍为指定提交，工作区干净 |

4 个忽略项仍为两个性能测试和两个 kill-nine 相关测试。临时副本仅在 `review5_tests.rs` 新增 3 个测试、109 行；产品代码未改。

完整测试代码：review5e-tests.patch（已并入仓库，名称以 `review5e_` 开头）。补丁适用于评审提交；P1 断言低于模型门槛的插入变体应被拒绝，P2 断言构造输入应在 5 秒内完成；另有随机长口令对照 `review5e_c1_random_long_passwords_remain_strong`。

日志：工作区基线、沙箱首跑、格式向量、密码学向量、新增测试 debug、新增测试 release（均未收录）。

使用的已有解释器：本机已有的 Python 虚拟环境（路径略）。

