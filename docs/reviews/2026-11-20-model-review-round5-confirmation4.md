# Keevo 第五轮第四次确认评审

> **第五轮的第四次确认评审**，由外部模型完成（与正式评审相同）。归档时只把本机路径换成了说明、去掉了指向本机日志的链接，正文未改。处理记录：[2026-11-20-model-review-round5-confirmation4-response.md](2026-11-20-model-review-round5-confirmation4-response.md)。

评审提交：`865b652a61818306619b35f13a50032dfb2c4c8f`。在独立临时 clone 中切换并用 `git rev-parse HEAD` 确认；已读上次报告、处理记录及 `git diff 28074f0..865b652`。仅复核 P1、P2 和 export §3，其余模块沿用上轮结论。原仓库未修改，未访问真实网络服务，报告未发布。

**1. 冻结结论**

**M1.5 全部草案目前仍不能一起冻结：导出还有 Q1、Q2 两项冻结阻塞。** 同意本轮提出的划分：启发式不必证明熵下界，但单个常见口令重复、最多 3 处编辑，按规范模型低于 10¹⁰ 的变体，仍应被导出门槛拦截。下面两例均在这个范围内。

| spec/REVIEW.md §0 草案 | 能否冻结 | 剩余事项 |
|---|---|---|
| 附件 | 可以 | 沿用上轮结论及边界 |
| 条目详情 v2 | 可以 | 沿用上轮结论；格式向量通过 |
| 导出文件 | **整体不能；加密封装仍可以** | **冻结阻塞：Q1、Q2**，需补齐廉价近似重复的候选及成本选择；Q3 为冻结后改进 |
| 备份与恢复 | 可以 | 沿用上轮结论及边界 |
| 导入 | 可以 | 沿用上轮结论 |
| 泄露检查 | 可以冻结本轮契约 | 沿用上轮结论；未请求真实服务 |
| SSH Agent 策略的存放 | 可以 | 沿用上轮结论 |

其他已接受的延期项维持原决定。

**2. 逐项确认**

- **P1：部分到位。** 上次的 `review5e_` 三个测试在 debug、release 均通过，包括首份各位置插入的家族回归和 24 个随机长口令对照。但候选预筛仍漏掉只重复两次的替换变体（Q1）；按最少编辑选择相位，也可能舍弃更低枚举成本的解释（Q2）。
  相位的 `anchor ± 3` 对净插入/删除偏移合理；周期升序遍历、只在编辑数严格下降时更新，实现了“已检查候选中编辑最少、同数周期最短”。它不是全部可能基础片段的搜索：每个长度只取一个最高频片段，且最多检查 32 个候选。带状 DP 的初始化、三种转移、提前退出及末行取最小，与允许不完整末份的语义相符；用独立全矩阵 DP 对照 **24,990 组**二元字符输入/周期/相位，全部通过。`most_frequent` 另有哈希碰撞计数问题（Q3）。
- **P2：到位，仍有可优化的延迟。** 每次 LZ 估计累计只分析 128 个新字符，后续不再乘入新内容成本，属于合理的保守截断；足以保留本轮随机长口令的 4 分判断。预算不是整个调用树的硬耗时上限，递归和短输入整段分析仍会产生额外工作。旧密集 l33t 样本约 **1.96 s / 0.10 s**（debug / release）；新增六类样本中最慢的是“64 字符 l33t 片段重复并插入三字符”，约 **2.90 s / 0.143 s**。数字、交错复制等样本也通过 5 秒检查。没有发现新的超预算样本；这些测量不是最坏情况证明，百毫秒级 release 延迟仍可在冻结后优化。
- **export §3：有条件的效果表述到位，整体实现符合性仍部分到位。** 公式、128 字符上限以及“筛选而非熵下界”的限定与实现方向一致。但 §3 第 131–132 行描述的近似重复不能据此视为已完整覆盖；Q1、Q2 的模型成本确实低于门槛，不能用“通常”或基础片段已有中等强度解释。修复应落在实现上。

**3. 新发现**

**Q1：候选要求两份完全相同片段，漏掉“两次重复、一处替换”**

- **位置**：`crates/keevo-core/src/strength.rs:160–174`，`near_period_estimate` 的候选筛选；`spec/export.md` §3。
- **问题**：`count < 2` 可证明更长的完全相同子串不重复，却不能证明不存在近似重复。只有两份、其中一份被修改时，完整基础片段可能只出现一次，正确周期在 DP 之前即被排除。
- **前提**：用户用该类常见口令变体保护导出，攻击者取得文件。
- **影响**：明确低成本的口令通过强度门槛；不涉及 KDF 或 AEAD 被突破。
- **严重程度**：**中；冻结阻塞**。
- **建议**：为少量重复且副本受损的情形保留有界恢复候选，不把“两份未改动的相同子串”作为近似周期的必要条件。
- **证据**：`review5f_q1_two_copies_with_one_substitution_are_rejected` 在 debug/release 均失败。两例都是 `password123 × 2`，在第一份下标 2 或 5 替换为 `!`；直接对正确基础片段求编辑距离均为 1，但 `near_period_estimate=None`。

| 输入 | 规范模型成本 | 实际估计 | 导出 |
|---|---:|---:|---|
| `pa!sword123password123` | 2,491,280 | 93,102,070,000 | 允许，4 分 |
| `passw!rd123password123` | 2,491,280 | 10,188,000,000 | 允许，4 分 |

模型成本为 `596 × 2 × 22 × 95`，596 是当前实现对基础口令的估计。

**Q2：按最少编辑选相位，丢弃更便宜的常见口令解释**

- **位置**：`crates/keevo-core/src/strength.rs:179–205`，相位选择、基础片段旋转及递归估计。
- **问题**：编辑次数最少不等于总枚举成本最小。`letmein × 3` 删除开头 `l`，再把第一份中的 `e` 替换为 `!`，得到 `etm!inletmeinletmein`。从 `letmein` 的相位 0 看是两处编辑；从相位 1 看只需一处，但旋转后的基础片段 `etmeinl` 贵得多。实现仅保留后者。
- **前提**：同 Q1；输入只有一个常见基础口令、两处改动。
- **影响**：丢掉模型内低于门槛的解释，最终获准导出。
- **严重程度**：**中；冻结阻塞**。
- **建议**：在有界候选/相位中按总枚举成本比较，或保留常见基础片段的低成本解释；单靠最少编辑不能保证这轮约定的筛选效果。
- **证据**：`review5f_q2_cheaper_common_password_phase_must_not_be_discarded` 在 debug/release 均失败。两种相位的 DP 结果分别为 2、1；`estimate("letmein")=17`，模型成本为 **`17 × 3 × (20 × 95)² = 184,110,000`**。旋转基础片段估计为 10,000,001，近似周期路线得到 57,000,005,700；三路取最小后仍是 **15,100,000,000、4 分、允许导出**。

**Q3：滚动哈希碰撞被当作相同片段**

- **位置**：`crates/keevo-core/src/strength.rs:217–227`，`most_frequent`。
- **问题**：以哈希直接合并计数，没有比较实际字符片段。令 `B=1,000,003`，`[0,B]` 与 `[1,0]` 的二字符哈希相同，但内容不同。
- **前提**：输入包含相应 Unicode 标量；不需要触发整数溢出。
- **影响**：最高频候选和覆盖计数可能失真。该测试只证明辅助函数错误，未证明满足本轮阻塞标准的口令获准导出。
- **严重程度**：**低；冻结后改进，不阻塞冻结**。
- **建议**：同哈希桶内核对真实片段，再计数与选代表。
- **证据**：`review5f_q3_hash_collision_is_not_a_repeated_substring` 对 `['\0', '\u{f4243}', '\u{1}', '\0']`、周期 2，断言应返回 `Some((0,1))`，debug/release 实际均为 `Some((0,2))`，测试失败。

**4. 验证记录**

环境：Rust/Cargo 1.97.1；格式向量 Python 3.14.7；密码学向量复用现有 venv 的 Python 3.12.4。依赖版本与 `spec/reference/requirements.txt` 一致：argon2-cffi 25.1.0、argon2-cffi-bindings 26.2.0、cffi 2.1.1、pycparser 3.12、PyNaCl 1.6.2；没有下载依赖。

| 命令 | 结果 |
|---|---|
| `git clone --no-hardlinks <原仓库> <临时副本>`；`git checkout --detach 865b652a61818306619b35f13a50032dfb2c4c8f`；`git rev-parse HEAD` | 成功，哈希一致 |
| `CARGO_NET_OFFLINE=true cargo test --workspace`（基线） | 沙箱内两个 CLI 测试创建本机 Unix socket 被拒绝，退出 101；获准沙箱外重跑后 **369 passed、0 failed、4 ignored，退出 0** |
| `python3 spec/reference/format_vectors.py --check` | 通过，退出 0 |
| `<venv>/bin/python -I spec/reference/generate_vectors.py --check` | 通过，退出 0 |
| `CARGO_NET_OFFLINE=true cargo test -p keevo-core --lib review5e_ -- --nocapture --test-threads=1` | **3 passed，退出 0** |
| `CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=target/review-release cargo test -p keevo-core --release --lib review5e_ -- --nocapture --test-threads=1` | **3 passed，退出 0** |
| `CARGO_NET_OFFLINE=true cargo test -p keevo-core --lib review5f_ -- --nocapture --test-threads=1` | **2 passed、3 failed，退出 101**：C1/C2 通过；Q1/Q2/Q3 失败 |
| `CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=target/review-release cargo test -p keevo-core --release --lib review5f_ -- --nocapture --test-threads=1` | **2 passed、3 failed，退出 101**：结果同 debug |
| `cargo fmt --all`；`git diff --check`；`git apply --reverse --check ../review5f-tests.patch` | 通过 |
| 原仓库 `git rev-parse HEAD`；`git status --porcelain=v1` | 仍为指定提交，工作区干净 |

4 个忽略项仍是两个性能测试和两个 kill-nine 相关测试。工作区基线运行的是新增测试前的版本；最终补丁只在 `strength.rs` 的测试模块增加 5 个单元测试、142 行，没有修改产品逻辑。

完整测试代码：review5f-tests.patch，可应用于本次评审提交（已并入仓库，名称以 `review5f_` 开头）。所有新发现测试都断言修复后应成立的行为。

日志：工作区基线、沙箱首跑、密码学向量、旧测试 debug、旧测试 release、新测试 debug、新测试 release（均未收录）。格式向量的终端输出为“格式与合并测试向量与参考实现一致。”

上述 `<venv>` 为本机已有的 Python 虚拟环境（路径略）。
