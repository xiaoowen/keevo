# Keevo 第五轮再次确认评审

> **第五轮的第二次确认评审**，由外部模型完成（与正式评审相同）。归档时只把本机路径换成了说明、去掉了指向本机日志的链接，正文未改。处理记录：[2026-11-20-model-review-round5-confirmation2-response.md](2026-11-20-model-review-round5-confirmation2-response.md)。

评审提交：`455d633e3f9304a83e0ee506084f4982066987da`。范围：`git diff d7ef907..455d633`，以及这些修复涉及的调用路径；先读了上轮确认报告与处理记录。开始时在独立临时 clone 中执行 `git checkout --detach 455d633e3f9304a83e0ee506084f4982066987da`，`git rev-parse HEAD` 完全相符。原仓库未修改，结束时仍为该提交、工作区干净。没有请求真实网络服务；报告与测试仅保存在本机，未发布。

**结论：仍不建议将全部草案一起冻结。** M1 部分到位，原 M2–M6 已到位；确认两个剩余问题：N1（中）、N2（低）。N2 是核对原样导入时新发现的既有遗漏，其所在文件本轮未修改，不是本次提交引入的回归。

## 1. 冻结结论

| `spec/REVIEW.md` §0 草案 | 判断 | 冻结前还差什么 |
|---|---|---|
| 附件 | **可以冻结** | M6 已解决健康条目被损坏历史阻断的问题；保留现有 M1 单设备及 M2 因果稳定边界。 |
| 条目详情 v2 | **可以冻结** | 维持上轮结论，向量检查通过。 |
| 导出文件 | **封装可以；整体暂不冻结** | 修复弱口令筛选 N1，以及自有 JSON 读取的保真遗漏 N2。 |
| 备份与恢复 | **可以冻结** | M3、M5 已解决；沿用已明确的不认证备份内容的边界。 |
| 导入 | **暂不冻结** | 保留结构化字段的 `purpose`，N2。 |
| 泄露检查 | **可以冻结本轮契约** | 维持上轮结论；没有发起真实 HIBP 请求。 |
| SSH Agent 策略的存放 | **可以冻结** | 包括本机记录及此次补全的删除、重建生命周期。 |

上轮已接受的延期项维持原决定。N1 不要求修改加密封装，N2 不要求修改线上版本或增加字段。

## 2. 逐项确认

| 项目 | 判断 | 依据 |
|---|---|---|
| M1 | **部分到位** | KMP 最短周期及不完整末次重复的处理正确；原反例通过，重复窗口不再逐段 ×2。但非周期输入仍逐窗相乘，周期基础片段超过 64 字符时也回到同一路径，简单变体仍达 4 分，见 N1。 |
| M2 | **到位（原问题）** | `Builder::finish` 仅规整模式补标题；§2 已分开自有格式、全局资源上限、第三方规整，原有 trim/数量上限冲突消除，空标题回归通过。完整原样契约另有 N2。 |
| M3 | **到位** | `ssh_agent_revocation` 在迁移未完成时写 `off`，完成后删除记录；永久删除与重建都使用它。撤销、重建的新记录与墓碑经 `insert_revisions_with` 同事务提交；恢复保留本机记录及迁移标记，与 §4.1 一致。原失败迁移→删除→恢复反例通过。 |
| M4 | **到位** | 先一次性取走标记并释放标记锁，再持有同一保险库锁核对时限、代次及执行导出取数。新解锁不能插入核对与取数之间；锁外写文件使用已经取出的结果。两把锁不嵌套，原并发测试通过。 |
| M5 | **到位** | 调整可接受：恢复时沿用可信保存时间或赋恢复前有效时间，并限制不超过该时点；重建的时钟起点因此不会前跳，恢复旧备份允许回退。随后仍正常按单调时间推进。测试改验回退符合条文和上轮建议，不是削弱“不得提前清理”的要求。 |
| M6 | **到位** | 全库扫描逐条目捕获失败并继续。单条目先完整读取留存历史、建立引用集合，再删除无引用附件，读历史失败时保留该条目的附件。原损坏条目阻断健康条目的反例通过。 |

**新增导出向量到位。** `other_kdf_params` 使用合法的 `m=65536 KiB、t=4、p=2`；`kdf_t_changed_within_range` 只将原文件的合法 `t=3` 改成 `4`，预期认证失败；`kdf_unknown_algorithm` 改为 `alg=0x02`，预期参数拒绝。Python 独立生成检查及 Rust `vectors::export_files` 均通过；Rust 逐字节比较封装、核对 62 字节 AAD、打开正例并拒绝反例。现共 4 个正例、11 个反例。默认 256 MiB 参数向量仍可维持上轮的非阻塞决定。

## 3. 新发现

### N1：近似重复和长基础片段仍被评为“很强”

- **位置**：`crates/keevo-core/src/strength.rs:127`、`:157`；`spec/export.md` §3。
- **问题**：末尾加一个符号或内部改一个字符即可破坏全串周期；剩余路径将 64 字符窗口的估计相乘，重复关系和跨窗口截断没有被整体处理。即使 KMP 命中，基础片段超过 64 字符时也有同样问题。
- **前提**：用户用此类弱口令保护导出文件并依赖 4 分门槛；攻击者获得该文件。
- **影响**：只需枚举常见基础词、重复次数及少量改动的口令被接受保护全部导出内容。没有证明 Argon2id/AEAD 被突破，也不把估计数当作实测破解成本。
- **严重程度**：**中**。
- **建议**：不要把固定窗口视作独立猜测成本；跨窗口识别重复片段及简单变体，或对无法可靠分析的长输入保守降档。将下列家族加入回归，不只特判这几个字符串。
- **证据**：`review5d_n1_near_repetition_does_not_reach_export_threshold` 失败，以下三例均为 **4 分、`export_password_ok=true`**：

| 构造（Rust 表达方式） | 字符数 | 估计猜测次数 |
|---|---:|---:|
| `format!("{}!", "password123".repeat(10))` | 111 | 262,756,292,400,000 |
| `"password123".repeat(20)`，将零起点位置 110 的 `p` 换成 `!` | 220 | 约 7.292×10²⁴ |
| `format!("{}{}", "password123".repeat(3), "qwerty123456".repeat(3)).repeat(3)` | 207 | 92,580,069,696 |

第三例的最短基础片段为 69 字符。对照：`"password123qwerty123456".repeat(10)` 得 2 分；两个 `"password123".repeat(5)` 中间插入 `!` 得 3 分，均正确拒绝。因此这里报告的是明确反例，并非声称所有交替或插入都绕过。

### N2：原样导入静默清空结构化字段的用途

- **位置**：`crates/keevo-core/src/import/keevo.rs:122`、`:140`；`spec/export.md` §2；`spec/vault-format.md` §2 的字段及用途定义。
- **问题**：读取 `kv_list` / `recovery_codes` 时硬编码 `purpose: None`，丢掉文件中合法的 `purpose`。规范允许字段带用途，未将此行为列为原样导入例外。
- **前提**：正常 API 创建带 `purpose=notes` 的上述字段，然后正常 JSON 导出、按 Keevo 来源导入；不需要恶意文件。
- **影响**：字段用途元数据静默丢失，违反自有格式往返保真承诺；本测试不涉及秘密值丢失或泄露。
- **严重程度**：**低**。
- **建议**：两个结构化分支均保留 `f.purpose`，并覆盖往返测试。
- **证据**：`review5d_n2_own_export_preserves_structured_field_purpose` 失败。创建和导出成功，测试先确认两个导出字段都是 `purpose="notes"`，解析后却得到 `[None, None]`，应为 `[Some(Notes), Some(Notes)]`。该代码在 `d7ef907..455d633` 中无变化，是新发现的剩余问题。

## 4. 验证记录与附件

环境：Rust/Cargo 1.97.1；格式向量用系统 Python 3.14.7；密码学向量用已有 venv 的 Python 3.12.4。该环境的 argon2-cffi 25.1.0、argon2-cffi-bindings 26.2.0、cffi 2.1.1、pycparser 3.12、PyNaCl 1.6.2 与 `requirements.txt` 一致；没有下载依赖。

| 命令 | 结果 |
|---|---|
| `git clone --no-hardlinks <原仓库> repo`；`git checkout --detach 455d633e3f9304a83e0ee506084f4982066987da`；`git rev-parse HEAD` | 成功，哈希完全一致。 |
| `CARGO_NET_OFFLINE=true cargo test --workspace`，原提交构建 | 沙箱首跑两个 CLI 测试因创建本机 Unix socket 的 `Operation not permitted` 失败，退出 101。获准沙箱外重跑后 **364 passed、0 failed、4 ignored，退出 0**；包含全部六项 `review5c_` 和 `vectors::export_files`。 |
| `python3 spec/reference/format_vectors.py --check` | **通过**。 |
| `python3 spec/reference/generate_vectors.py --check` | 系统解释器缺少 `argon2`，退出 1；改用下行已有环境。 |
| `<venv>/bin/python -I spec/reference/generate_vectors.py --check` | **通过，退出 0**。 |
| `CARGO_NET_OFFLINE=true cargo test -p keevo-core --lib review5d_ -- --nocapture` | **0 passed、2 failed，退出 101**；分别失败于 N1、N2 的“应当成立”断言，编译与夹具均成功。 |
| `cargo fmt --all`；`git diff --check`；`git apply --reverse --check ../review5d-tests.patch` | 通过。临时副本只增加两个测试，共 84 行，产品代码未改。 |
| 原仓库 `git rev-parse HEAD`；`git status --porcelain=v1` | 仍为指定提交，工作区干净。 |

4 个忽略项仍为已有的两个性能测试和两个 kill-nine 相关测试，不代表已完成断电验收。工作区基线运行使用加入新测试前已完成的构建；新增失败测试单独运行。

完整测试补丁：review5d-tests.patch，适用于评审提交（已并入仓库，名称以 `review5d_` 开头）。新测试均位于 `crates/keevo-core/src/review5_tests.rs`。

日志：工作区完整验证、沙箱首次验证、新失败测试、格式向量、密码学向量（均未收录）。

使用的已有解释器：本机已有的 Python 虚拟环境（路径略）；仅复用了其解释器与依赖。
