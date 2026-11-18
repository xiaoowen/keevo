# Keevo 规范第三轮评审：复核第二轮修复

## 1. 评审版本与总体结论

**评审提交：6f498292468f198007844d0361f19ba021df2713。** 评审开始及写报告前运行 git rev-parse HEAD，结果均为该提交；开始时工作区干净。本轮只检查 d3d2faf..6f49829 的改动及其直接交互，源码行号均指 6f49829；新增评审测试只存在于临时副本，以下用测试名引用，不把临时文件行号当作提交中的行号。

**结论：可以继续以 v0.3 开展 M1 开发，但现在不能把这四份文档整体标为已完成审查、冻结的格式。** 二进制配对承诺、删除状态进入候选集合、KDF 串行化、迁移时保守赋龄和 cdhash 信任锚的修改都有实质效果；移植后的 26 个第二轮测试全部通过。不过，新的大小策略存在合法而无法精简保存的状态，有效时间仍会让新历史提前过期，读取限长与会话登记也还有边界缺口。本轮没有确认无凭据解密、来源绑定绕过或高／严重级别的新问题；主要问题是数据可恢复性、状态表示及实现与承诺不一致。

### 冻结格式前必须解决

1. **确定大小策略的闭合性（H2）**：无限制的头集合、最多 256 个父修订、不可移除的记录墓碑、单信封 16 MiB，目前不能同时保证“精简后可保存”。需要明确可实现的合并／压缩／拆分或其他恢复表示，并验证最坏合法状态；仅增加一个精简按钮不够。
2. **明确删除状态的合法表示和纯合并的适用域（H4）**：拒绝非法的 attr:purged 文档，禁止普通编辑接口写入保留键；将“已删除视图不写回”的限制纳入 §5.3 的性质声明。若要允许任意中间结果写回，则必须为已删除结果保留完整合并状态。
3. **补齐规范编码与解析边界（H7）**：明确墓碑参与比较时的编码、null／缺省处理及规范编码的适用对象；统一概要与详情的整数范围。否则另一语言按文字实现，不一定得到相同的接受集合和冲突决胜结果。
4. **区分共享格式冻结与本机包裹格式定稿**：crypto §8.6 已独立声明本机版本和迁移责任，可以单独保持草案；若也要冻结它，必须先补每个 purpose 的明文布局与长度、ECDH 输出字节表示和材料失效的恢复流程，见 §4.3。

### 可在 M1 实现阶段解决，但须在相应功能处理真实数据前完成

- 修正有效时间和清理的保守性，包括缺失／损坏元数据及原子持久化（H1）。
- 让读取限长与实际读取共享快照，补元数据入口的长度约束（H3）。
- 按绝对截止时间取消配对 I/O，补齐 XX 确认后的发送前登记（H5、H6）。
- 明确配对次数的统计单位、重启行为和客户端重试的概率界限（H8），并完成锁定状态下授权记录变更的持久化规则（§4.4）。
- 处理记录 §8 已列明的打包、原生授权、Touch ID 等事项仍按原计划验收。本报告不把这些已知未实现事项重复列为漏洞。

这里的“可以开发”不代表当前开发服务已可用于真实凭据；spec/ipc.md:65 本身就要求固定 cdhash 校验完成前不得处理真实数据。

### 验证记录

环境：macOS 27.0.1（26A434）、arm64；rustc 1.97.1（8bab26f4f）、cargo 1.97.1。所有构建、测试及测试代码修改都在由目标提交导出的临时副本中进行，未修改原仓库源码、未提交、未推送。Cargo 使用 --offline；只查询了 SQLite、RFC、Apple、Sigstore 的公开文档，没有向外部服务发送仓库内容。

临时证据目录：

    /private/var/folders/p8/bjft35g17819y_4qdk65x_4w0000gn/T/keevo-round3-mwd2lfkt/

其中 repo/ 是验证副本；review-tests-round3.patch 包含 26 个移植测试及 23 个新增测试，SHA-256 为：

    550d78c6548a7e530dfddf637b702c3515640fb4d7dfb58e1e02ab3ec0e1a2cc

补丁只增加／移植测试，以及为确定性调度 SQLite 竞态开启 rusqlite 的测试用 trace 特性，没有修补待评审的生产逻辑。原始日志与 test-results.json 保存在同一目录。临时目录不是永久的仓库交付物；关键反例的构造也写在本报告中。

| 命令／验证 | 实测结果 | 执行位置及记录 |
|---|---|---|
| git rev-parse HEAD；git diff d3d2faf..6f49829 | 目标提交匹配；审阅 39 个文件的改动 | 原仓库，只读 |
| cargo test --offline --workspace --no-fail-fast -- --skip r2_ | 124 个原有测试中 118 通过、6 失败；6 个失败集中在 macOS 签名检查及 native-host 集成测试 | 沙箱内，baseline.log；这次执行早于新增 r3_ 测试 |
| cargo test --offline -p keevo-macos -p keevo-native-host --no-fail-fast -- --skip r2_ --skip r3_ | 9 个全部通过，覆盖上述 6 个失败；其余 3 个也重跑通过 | **沙箱外重跑**，platform-unsandboxed.log |
| cargo test --offline --workspace --no-fail-fast r2_ -- --nocapture | 25 通过，1 个需独立进程的测试暂忽略 | 沙箱内，ported-tests.log |
| 子 shell 中 ulimit -n 128，再单独运行 r2_registration_clone_failure_should_close_connection，附 --ignored --test-threads=1 | 1 通过；合计 **26/26 个移植测试通过** | 沙箱内，fd-review.log；只降低测试子进程的描述符上限 |
| cargo test --offline --workspace --no-fail-fast r3_ -- --nocapture | 22 个：12 通过、10 失败 | 沙箱内，r3-tests-final.log |
| cargo test --offline -p keevo-service r3_xx_confirmation_must_register_before_paired_send -- --nocapture | 后续新增的 1 个测试失败；合计 **23 个新增测试，12 通过、11 失败** | 沙箱内，g7-test.log |
| 已有隔离 Python 环境运行 python -I spec/reference/generate_vectors.py --check | “测试向量与参考实现一致” | 沙箱内，vectors.log；没有重新下载依赖 |
| Python Unicode 16.0.0 的 Cf 集合与 message.rs 中区间逐项比较 | 无遗漏的 Cf，也无额外已分配字符 | 沙箱内；另用 Rust 测试核对两端清洗及标量截断 |

沙箱内的 macOS 失败分别是 Apple anchor 测试得到 Ok(false)，以及五个 native-host 测试在创建本地 socket 时得到 Operation not permitted。沙箱外重跑消除了这些失败，未把它们计入产品缺陷。新增边界测试的失败均在沙箱内得到明确断言结果，不依赖网络、系统时钟修改或真实凭据。

原有测试通过不是修复充分性的依据；下面分别给出独立测试与逐步推导。新增测试中也有刻画限制的测试，因此“测试通过”不一概表示安全声明成立。

## 2. 第二轮发现的复核表

| 项目 | 结论 | 独立核实的结果与依据（6f49829） | 复核测试 |
|---|---|---|---|
| G1 配对承诺、尝试预算 | **部分成立** | 原始二进制负载承诺确实封住 JSON 编码别名；公钥 32 字节、nonce 32 字节、最后为变长名称，拼接无歧义。跨连接的闸门及中途放弃计数有效。但绝对超时未完整落实，小时预算仅在内存中，概率论证还需限定客户端重试，见 H5、H8。依据：crypto/noise.rs:32；ipc/client.rs:101；ipc/service.rs:39、:373、:452；ipc.md §4.2。 | r2_same_commitment_same_prefix_different_sas；r2_commitment_accepts_different_json_encodings；r3_every_third_payload_byte_is_bound；r3_gate_counts_drops_across_connections；r3_display_name_rules_shared_on_both_sides |
| G2 对象删除与合并 | **部分成立** | 旧 G2 反例已修复；墓碑的 purged 版本及被撤销的删除候选均保留，500 个混合修订图上的可写回中间视图分组测试通过。写时收敛已明确为用户确认恢复的操作。但保留键校验未落实，已删除结果的“纯合并”定义仍需收窄，见 H4。依据：format/merge.rs:120、:175；item.rs:258；revisions.md §5.2–§5.4、§6。 | r2_object_tombstone_grouping_should_preserve_deletion；r2_settle_for_write_is_not_a_pure_join；r3_random_mixed_live_partial_joins_500_graphs；r3_purged_current_live_value_must_be_rejected |
| G3 历史有效时间 | **部分成立** | v1 迁移按迁移时间赋龄、单次大幅前跳的旧反例已修复；但“只会延长保留”不成立，缺失或格式合法但损坏的时钟值也不保守，见 H1。依据：store/lib.rs:245、:587、:619；revisions.md §7.2。 | r2_migration_should_conservatively_keep_existing_history；r2_clock_jump_should_not_destroy_recent_history；r3_clock_oscillation_must_not_expire_fresh_history；r3_missing_clock_metadata_must_fail_conservatively；r3_corrupt_effective_clock_must_not_prune |
| G4 读取限长、KDF 预算 | **部分成立** | 静态数据库中的账户和修订 BLOB 超限会先被拒绝；Argon2 调用处的 static Mutex 覆盖全部调用，确认比较完整 KdfParams，包括 salt。长度预检与读取不同快照、meta 和对象 ID 枚举入口仍有缺口，见 H3。依据：store/lib.rs:292、:316、:472、:508、:561；crypto/kdf.rs:159；core/vault.rs:246、:264。 | r2_database_envelope_size_should_be_checked_before_read；r3_all_revision_and_account_blob_readers_reject_oversize；r3_preflight_and_fetch_must_share_snapshot；r3_kdf_confirmation_binds_salt_and_cost |
| G5 合并大小预算 | **引入了新问题** | 超长的单个值被拒绝，encode_for_write 和一次性处理冲突的 compact_item 对常见大值冲突有效。但是新父数量上限与无限头矛盾；删除全部键后仍可能超限，精简并不覆盖全部合法状态，见 H2。依据：revisions.md §2、§7.1；store/lib.rs:76、:394；core/vault.rs:542、:581；format/item.rs:160、:212。 | r2_concurrent_growth_exceeds_serializable_limit；r3_257_valid_heads_must_be_compactable；r3_deleting_every_key_must_make_valid_merge_serializable |
| G6 cdhash 信任锚 | **修复成立** | **规范层面成立**：先签 helper、把其 cdhash 编译进主程序，再签主程序；更新时重启服务，运行时不从被替换文件重新取白名单。主程序替换已明确列入非目标，不再借用未写明的豁免。打包实现仍属已知 M1.1 工作。依据：ipc.md §3.1；ADR-0003 决策 4、6；security.md §1。 | 条文与构建依赖顺序的逐步核对；本轮没有实际发布包可测 |
| G7 登记失败及撤销 | **部分成立** | try_clone 失败会令 handle 关闭连接；正常登记／撤销两种顺序和 32 次并发测试通过；IK 已移到首次发送前登记。但 XX 的确认在 emit 内完成，paired 仍先于登记发送，见 H6。依据：service/server.rs:157、:161、:171、:209；ipc.md §4.4。 | r2_registration_clone_failure_should_close_connection；r2_revocation_and_registration_both_orders；r2_simultaneous_register_and_revoke_32_times；r3_xx_confirmation_must_register_before_paired_send |
| G8 完整性告警含义 | **修复成立** | §5.6 现在明确告警仅反映本次候选中观察到的矛盾、写回后可能消失、空告警不认证历史，保存前须提示。这是可接受的产品取舍，不要求一定持久化证据。实现行为与此一致；原值真实性仍依赖未来接收／认证层。依据：revisions.md §5.6；format/merge.rs:230、:246；core/vault.rs:446。 | r2_integrity_issues_should_survive_unrelated_write；r2_forged_ancestor_value_should_be_reported_in_single_head；r2_port_f5_equivocation_is_order_independent |

表中简写的 crypto/、ipc/、format/、store/、core/、service/ 分别指 crates/keevo-对应名称/src/。

### 移植测试的预期调整

保留 r2_ 测试名用于追溯，但不保留已经过时的断言：旧 JSON 第 3 条负载现在应被拒绝；修改原始字节应改变承诺；写时确认恢复不是纯合并；G8 改为验证“告警可以消失且不能认证祖先原值”；远端极端 HLC 不应推进本机时钟，真正耗尽应报错。大小测试由 40 个约 512 KiB 的值调整为 80 个约 220 KiB 的值，使每个输入符合新 256 KiB 上限；合并编码仍达到 18,029,458 字节。迁移、prune、register 的调用按新接口调整，生产代码未改。

下面列出所有移植测试；表中“通过”均指调整后的预期，而不是旧名称字面上的安全结论。

| 测试名 | 实测结果 | 调整后的预期／覆盖范围 |
|---|---|---|
| `r2_port_url_attack_inputs` | 通过 | 原有域名混淆输入仍不匹配。 |
| `r2_port_f6_old_value_survives_recent_edits` | 通过 | 近期连续覆盖的旧值仍在保留历史中。 |
| `r2_port_ik_replay_does_not_replay_transport` | 通过 | 重放 IK 首消息不能重放旧传输请求。 |
| `r2_same_commitment_same_prefix_different_sas` | 通过 | 旧字节变体会改变新的原始字节承诺；不同 SAS 不再对应同一有效承诺。 |
| `r2_hlc_maximum_does_not_generate_new_timestamps` | 通过 | 极端远端值不被采纳；本机正常递增；持久化最大值报耗尽。 |
| `r2_port_f5_equivocation_is_order_independent` | 通过 | 同 rev 矛盾内容的选择与输入顺序无关。 |
| `r2_forged_ancestor_value_should_be_reported_in_single_head` | 通过 | 按新告警契约，祖先成员关系不认证复制的原值；空告警是预期限制。 |
| `r2_graph_duplicate_metadata_conflict_is_rejected` | 通过 | 同修订元数据不一致时拒绝。 |
| `r2_integrity_issues_should_survive_unrelated_write` | 通过 | 按 §5.6 改为验证写回后告警可消失。 |
| `r2_nontrash_concurrent_only_should_be_rejected` | 通过 | 普通键只有并发版本时解码失败。 |
| `r2_object_tombstone_grouping_should_preserve_deletion` | 通过 | 旧 G2 的活的部分合并反例已通过。 |
| `r2_port_f4_grouping_preserves_record_maxima` | 通过 | 保留全部极大元的分组结果一致。 |
| `r2_unknown_and_cyclic_graphs_should_be_rejected` | 通过 | 未知父和自环在插入时拒绝。 |
| `r2_settle_for_write_is_not_a_pure_join` | 通过 | 确认恢复改变输入，与纯合并结果不同是新规范预期。 |
| `r2_random_record_join_200_graphs` | 通过 | 200 个随机普通记录图的排列、重复、分组检查通过。 |
| `r2_concurrent_growth_exceeds_serializable_limit` | 通过 | 80 个各约 220 KiB 的合法头合并超过信封预算；封装拒绝。 |
| `r2_port_f1_revoked_session_rejects_fill_after_unlock` | 通过 | 撤销后解锁不会恢复旧会话的填充权限。 |
| `r2_commitment_accepts_different_json_encodings` | 通过 | 旧测试名保留；断言已改为两种旧 JSON 负载都不获确认。 |
| `r2_deadline_rejects_late_message_and_confirmation` | 通过 | 迟到的完整第三帧和确认均被拒绝。 |
| `r2_registration_clone_failure_should_close_connection` | 通过 | 独立限额进程中，登记失败按新 handle 行为关闭，另一端读到 EOF。 |
| `r2_simultaneous_register_and_revoke_32_times` | 通过 | 32 次同时开始的登记和撤销均关闭连接。 |
| `r2_revocation_and_registration_both_orders` | 通过 | 先撤销／先登记两种顺序均关闭，后续请求拒绝。 |
| `r2_cross_object_parent_and_duplicate_rejected` | 通过 | 存储拒绝跨对象父、重复修订及未存在的自父。 |
| `r2_migration_should_conservatively_keep_existing_history` | 通过 | v1 迁移后旧修订按迁移时间保留。 |
| `r2_clock_jump_should_not_destroy_recent_history` | 通过 | 单次墙钟前跳 91 天不立即清理近期历史；不覆盖 H1 的重复校正。 |
| `r2_database_envelope_size_should_be_checked_before_read` | 通过 | 稳定数据库中超长详情列返回错误。 |

### 本轮新增测试

| 测试名 | 实测结果及意义 |
|---|---|
| `r3_kdf_confirmation_binds_salt_and_cost` | 通过：不同 salt／成本不获确认，同一完整参数可解锁。 |
| `r3_257_valid_heads_must_be_compactable` | 失败：编辑、精简、永久删除均为 Store(TooLarge)，H2。 |
| `r3_hlc_boundary_restore_and_exhaustion` | 通过：24 小时边界、规范过滤恢复、耗尽错误。 |
| `r3_duplicate_keys_rejected_at_all_json_levels` | 通过：四种顶层／嵌套重复键样本被拒绝。 |
| `r3_record_value_canonical_bytes_match_explicit_rule` | 通过：七类值的显式字节样本及实际 null 比较表示。 |
| `r3_purged_direct_set_must_be_rejected` | 失败：普通 set 可写保留属性，H4。 |
| `r3_deleted_merge_view_is_not_a_closed_join_state` | 通过（刻画限制）：None 写成新墓碑后不是同一纯合并状态，H4。 |
| `r3_overview_safe_integer_range_is_enforced` | 失败：概要接受超出统一安全整数范围的 trashed_at，H7。 |
| `r3_purged_current_live_value_must_be_rejected` | 失败：当前 Bool(false)、HLC 7 的 purged 文档被接受，H4。 |
| `r3_random_mixed_live_partial_joins_500_graphs` | 通过：500 个混合图、500 个活的中间视图分组检查，另含排列／重复检查。 |
| `r3_deleting_every_key_must_make_valid_merge_serializable` | 失败：全部删为墓碑仍为 16,796,115 字节，H2。 |
| `r3_display_name_rules_shared_on_both_sides` | 通过：Cc/Cf 清洗、Unicode 标量截断和两端结果一致。 |
| `r3_one_service_contribution_allows_multiple_extension_trials` | 通过（刻画限制）：一个服务待确认期间可产生两次扩展 SAS，H8。 |
| `r3_gate_counts_drops_across_connections` | 通过：并发请求拒绝、主动放弃和错误帧仍计数；新闸门预算重置，H8。 |
| `r3_every_third_payload_byte_is_bound` | 通过：逐字节改变第三负载均不获确认。 |
| `r3_socket_read_timeout_is_not_absolute_deadline` | 失败：100 ms 相对超时的帧约 274 ms 后仍读取成功，H5。 |
| `r3_malformed_clock_metadata_fails_closed` | 通过：格式错误时拒绝清理。 |
| `r3_corrupt_effective_clock_must_not_prune` | 失败：合法长度的 u64::MAX 使 5 个新历史被清理，H1。 |
| `r3_missing_clock_metadata_must_fail_conservatively` | 失败：缺失 last_wall 后重置年龄，清理 5 个，H1。 |
| `r3_clock_oscillation_must_not_expire_fresh_history` | 失败：91 次时钟往返使 5 个新历史被清理，H1。 |
| `r3_all_revision_and_account_blob_readers_reject_oversize` | 通过：稳定数据库的 revision／heads／history／graph／account 超长列拒绝。 |
| `r3_preflight_and_fetch_must_share_snapshot` | 失败：返回 17,301,563 字节账户 BLOB，H3。 |
| `r3_xx_confirmation_must_register_before_paired_send` | 失败：paired 已发送时登记表仍为空，H6。 |

## 3. 新发现

### H1．中：有效时间并不保证只延长保留，异常持久化状态会提前清理历史

**位置：** spec/revisions.md §7.2；crates/keevo-store/src/lib.rs:78、:587、:603、:607、:619。

**问题与前提：** 实现忠实执行了“每次调用最多增加一天”的公式，但这个公式并不能推出“时钟调快、倒退再校正只会延长保留”。每次调用都会覆盖 last_wall_ms；一次倒退后再次回到原来的较大时间，正差会被重复计入。无需持钥攻击者；时钟异常即可触发。修改本地时钟元数据的损坏情形另行列出，不把它说成云端攻击者可直接执行的攻击。

**复现：**

1. 在内存 Store 中写入 25 个连续修订，确保都刚创建。保持真实时钟不变。
2. 将 advance_clock 的 wall_ms 参数在 T 与 T + 1 天间往返 91 次，然后调用 prune(object, 20, 90 天, T)。
3. r3_clock_oscillation_must_not_expire_fresh_history 实测清理 **5 个**刚创建的历史修订，预期 0。一个向前跳一天再校正的周期也会多计一天，只是需要随后正常经过约 89 天才体现出提前过期。
4. 单独删除 clock.last_wall_ms，再以 T + 100 天调用 prune：缺失任一时钟字段走“首次调用取墙上时间”的分支，r3_missing_clock_metadata_must_fail_conservatively 同样清理 **5 个**。
5. 单独把 clock.effective_ms 写为合法的 8 字节 u64::MAX：prune 的截止时间转换饱和为 i64::MAX，r3_corrupt_effective_clock_must_not_prune 也清理 **5 个**。相反，3 字节等格式错误的时钟值会报错并保留历史，控制测试通过。

另外，两项时钟元数据由两个独立 set_meta 调用写入。若第一次写成功、第二次失败或进程在中间退出，重试会把同一墙上时间增量再次加到已推进的 effective 值上；这由调用顺序可直接推导，本轮没有做断电注入。

**影响：** 最近 20 个修订仍保留，但更早、原本按“不会提前清理”的承诺应可恢复的值被清除。若把“90 天”仅定义为当前公式算出的有效时间，代码没有违反这个循环定义；错误在于同时承诺该时间不会比真实经过时间更快，以及在元数据缺失时不保守地重建年龄。

**严重程度与置信度：中／已确认。** 已确认的是过早清理和缺失／损坏分支；未声称有攻击者能绕过 AEAD 修改条目值。

**建议：** 使用进程内单调经过时间推进，重启／无法确认经过时间时保守少计；墙上时间主要用于显示或受限校准。把两个时钟值原子持久化，验证范围和状态完整性，缺失／矛盾时暂停清理或重建保守年龄，而不是直接接到当前墙上时间。若接受更弱的策略，应删除“只会延长”的保证并明确产品历史承诺，不能仅靠单次增量上限证明它。

### H2．中：合法状态可能既无法保存，也无法通过精简恢复

**位置：** spec/revisions.md §2、§7.1；crates/keevo-store/src/lib.rs:76、:394；crates/keevo-core/src/vault.rs:542、:560、:581、:609；crates/keevo-format/src/item.rs:160、:212。

**问题与前提：** 单个值 256 KiB 的上限不约束键和墓碑的总量；最多 256 个父修订又与“父为全部头”“头没有硬上限”冲突。只需要合法的并发输入，不需要伪造认证数据。大量分支是较强前提，但它们确实属于规范允许的状态。

**复现 A——头数量：**

- 创建一个很小的条目，基于同一个初始修订写出 257 个不同的头，每个头只有一个父、文档合法且很小。
- 读取、合并成功，head_count 为 257。
- 分别调用 update_item、compact_item（甚至删除全部内容）和 purge_item。
- r3_257_valid_heads_must_be_compactable 实测三者均返回 **Err(Store(TooLarge))**，原因是新修订引用 257 个父。内容变小不能减少这个父集合。

**复现 B——墓碑下界：**

- 初始条目有一个标题。两个并发分支分别加入 26,000 个互不相同的标签；标签名为“分支号-五位序号-240 个 x”，共 248 字节，每个值是合法的 tag。
- 两个分支各编码 **8,710,137 字节**，encode_for_write 及重新 decode 均通过。
- 合并后把全部 52,001 个键都删除。delete 必须保留键、HLC、rev 的墓碑；不存在尚待选择的大值冲突。
- 剩余纯墓碑文档仍为 **16,796,115 字节**，超过 16 MiB（16,777,216）。r3_deleting_every_key_must_make_valid_merge_serializable 失败。

**影响：** A 的对象连永久删除也不能通过当前接口收敛；B 可以整体删除或导出后另建对象，但规范承诺的同对象精简无法完成。当前失败没有静默丢弃版本，也没有证明秘密泄露；问题是正常恢复／编辑路径不完备。

**严重程度与置信度：中／已确认。**

**建议：** 冻结前选择可证明覆盖所有合法输入的策略：例如可分块的状态、经过因果证明的墓碑压缩、受约束且保留信息的分批合并，或明确另一种恢复表示。分批合并还必须与“parents 为全部头”、已删除状态及 §5.3 的适用域一致。不能靠直接丢头、删并发版本或无证明地移除墓碑解决。若产品决定某些状态只能导出重建，应把这一限制写入规范和错误协议，撤回普遍“精简后可保存”的承诺，并说明对象身份与历史如何保留。

### H3．低：长度预检与读取之间存在竞态，部分元数据入口未限长

**位置：** spec/crypto.md §8.5；crates/keevo-store/src/lib.rs:292、:316、:334、:472、:489、:508、:522、:549、:561。

**已修复的部分：** 对稳定的、保持 STRICT BLOB 列定义的数据库，length(BLOB) 可以利用 BLOB 长度信息，无需完整加载内容；当前独立预检确实能挡住超长账户和修订列。SQLite 官方也区分了 BLOB 与需要读取字符内容的 TEXT。因此问题不在“length 本身一定读入 BLOB”。[SQLite length 文档](https://www.sqlite.org/lang_corefunc.html#length)

**问题与复现：**

1. account() 先执行 SELECT EXISTS 的长度检查，随后另行 SELECT 内容；两条语句没有包在同一读事务内。revision、heads、history、graph 使用同样的预检／读取分离方式。
2. r3_preflight_and_fetch_must_share_snapshot 用正常 WAL 数据库和第二个 SQLite 连接。只在测试中开启 trace，在第二条 SELECT 开始、取得读取快照之前，让第二个连接把 keyset_ct 换成 MAX_ENVELOPE_LEN + 1 的 zeroblob。
3. account() 实测成功返回 **17,301,563 字节**的 keyset_ct，没有给出超限错误。trace 只是确定性安排两个合法操作的先后，不改变生产 SQL 或长度函数。
4. meta() 直接读取任意长度 Vec 后由调用方检查 8／16 字节；objects() 从 head.object_id 直接读 Vec 后才解析 ID，也不经过 check_sizes。账户和 revision 的主要内容入口有检查，不等于全部数据库入口都有检查。

**前提与影响：** 需要另一个能修改本地数据库的连接，或损坏的本地元数据；本轮没有证明仅能改云端密文的 A2 能触发该本地竞态。大小预算可被绕过，可能造成过量分配；测试只使用“上限 + 1”，没有运行内存耗尽攻击或证明解密成功。考虑同用户可写数据库本来就能破坏本地可用性，按纵深防御不足评为低。

**严重程度与置信度：低／已确认。**

**建议：** 预检与读取共享读事务／快照，或在同一语句内对长度合格的内容才进行投影，并把不合格输入显式报错，不能静默过滤成“对象不存在”。对固定长度 meta、head ID 也先限长；区分单列上限和批量读取预算。规范应写“读取前且同一快照验证”，不应把保证归因于 length 只能出现在哪个 SQL 子句。

### H4．低：新保留删除键的格式边界未落实，纯合并性质仍需限定

**位置：** spec/vault-format.md §2.1；spec/revisions.md §5.2–§5.4；crates/keevo-format/src/record.rs:46、:236、:276；item.rs:172、:196；merge.rs:106、:175、:188。

**问题与前提：** 规范说客户端不得直接写 attr:purged，文档中只能出现被撤销删除的并发版本或确定恢复的墓碑。实现仍把它当普通 Attr：set 接受任意 text／bool／int，decode 不限制它出现的位置、取值或 HLC；merge 只检查“不是墓碑”，所以 false 也会被当作永久删除候选。

**复现：**

- r3_purged_direct_set_must_be_rejected：调用 ItemDoc::set(attr:purged, Bool(true), Hlc(2), rev) 成功，预期拒绝。
- r3_purged_current_live_value_must_be_rejected：在 records 中放入当前版本 attr:purged，值为 Bool(false)、HLC 为 7；encode 后 decode 成功，预期拒绝。
- 对一个只含上述 purged 及同修订普通记录的头，merge.rs:175 以后会把 false 收入 purges；没有与自身并发的普通记录，因而判为已删除。这是代码可逐步复现的推导。

这要求能构造条目明文／调用格式 API；未发现无密钥攻击者可越过 AEAD 注入该值，也未发现现有普通标题编辑 UI 可直接写入它。

**纯合并的另一项边界：** 原 G2 的“活的部分合并丢墓碑”反例已经通过，新增 500 个含回收站、墓碑和编辑的图也通过交换、重复输入及活的中间视图分组检查。但 Merged.doc = None 不携带候选集合：把这个 None 写成一个新的对象墓碑会产生新的 purged.rev，而非原样保存旧合并状态。

r3_deleted_merge_view_is_not_a_closed_join_state 构造根 R、删除头 D、携带根内容的并发头 B，以及在根上新增 note 的头 C。先合并 D、B 得到 None；把它写成新墓碑 M 后再与 C 合并，文档中的 purged 版本身份与直接合并 D、B、C 不同。该测试按“结果应不同”的刻画性断言通过。**当前 §5.4 禁止已删除视图写回，产品路径仍保留原头，所以这不是当前产品再次发生旧 G2 数据丢失的证据；需要修正的是 §5.3 和 §9 对任意纯合并分组的无条件措辞。**

**影响：** 不合法的删除状态被接受，库调用者可以产生规范不允许的文档；不同实现可能拒绝、保留或删除同一输入。性质的适用域模糊还会误导未来缓存或分批合并实现。

**严重程度与置信度：低／已确认。**

**建议：** 普通 set／resolve／编辑 API 禁止写保留键，内部合并与明确恢复走受限接口；解码验证 purged 的允许位置及版本形态，真实删除候选为 Bool(true)、HLC 0，恢复墓碑另行规定。性质声明明确限于完整保留候选且可表示的中间状态；若保留“不写回已删除视图”，测试生成器也应明确排除该写回操作，而非将新墓碑当作纯合并。

### H5．低：socket 的相对读超时不能保证配对在绝对截止时间断开

**位置：** spec/ipc.md §4.2 第 7 条；crates/keevo-service/src/server.rs:142；crates/keevo-ipc/src/frame.rs:27、:65；ipc/service.rs:205、:241。

**问题与前提：** handle 在每个完整帧之前设置一次 remaining timeout，但 read_socket_frame 内部通过 read_exact 多次 read。每次及时到达的部分数据都可以让下一次 read 重新等待这个相对时长；到达 deadline 本身不会调用 release_gate。需要对端能拖延 socket 的字节交付。

**复现：** r3_socket_read_timeout_is_not_absolute_deadline 建立 UnixStream 对，读超时为 100 ms；发送 8 字节帧的长度后，每 30 ms 发一个字节。读取在约 **274 ms** 后成功，而不是在 100 ms 截止时失败。这直接对应生产代码使用的读法，测试没有等待真实 60 秒。

**影响：** 连接及全局唯一的配对闸门可以超过规定时间被占用，阻碍其他配对。完整第三帧到达后，状态机仍会拒绝过期握手；本项不意味着迟到配对能被接受，也不影响已有会话请求的授权检查。

**严重程度与置信度：低／已确认。**

**建议：** 读长度及帧体的每一次 read 都重新计算绝对 deadline，或用可取消的 I/O／定时器在到期时关闭连接。发送和等待确认也应服从同一截止时间。状态机的到期检查应继续保留。

### H6．低：发送前登记的修复遗漏了 XX 确认中建立会话的路径

**位置：** spec/ipc.md §4.4；crates/keevo-service/src/server.rs:157、:161、:209；crates/keevo-ipc/src/service.rs:290、:323。

**问题与复现：**

1. 第三条握手消息使连接进入 AwaitConfirm，handle 在 emit 前调用 register；此时 peer_public 为 None，register 直接成功返回，没有登记。
2. emit 调用用户确认，再调用 confirm_pairing。后者保存配对并把连接改成 Established，返回待发送的 paired 事件。
3. emit 递归发送这个事件。只有整个 emit 返回后，handle:161 才再次 register。
4. r3_xx_confirmation_must_register_before_paired_send 按此顺序执行，成功从 socket 另一端读到 paired 帧，同时 sessions 中仍没有该连接，因此断言失败。

**影响：** 新增的“会话建立后、发出任何内容之前登记”不对 XX 成立。若撤销发生在这一段，会漏掉主动关闭；后续登记复查仍会发现撤销并关闭，且任何后续秘密请求仍受每请求复查保护。这里只确认短窗口与规范不一致，没有证明秘密泄露，也没有证明正常 socket 缓冲条件下这条很小的 paired 响应能被长期阻塞。

**严重程度与置信度：低／已确认。**

**建议：** 让确认后的 Established 转移也经过“登记成功才发送”的统一路径，例如将确认结果交回连接驱动层，或在递归 emit 前用连接编号完成登记。保留本轮已修复的 try_clone 失败即关闭、IK 发送前登记及撤销线性化点。

### H7．低：整数约束有读取入口遗漏，规范编码尚未覆盖墓碑比较

**位置：** spec/vault-format.md §1；spec/revisions.md §5.1；crates/keevo-format/src/item.rs:160、:403；record.rs:276；merge.rs:246；处理记录 §5。

**已成立的部分：** 固定结构的 RecordValue 字段顺序、UTF-8、控制字符转义、布尔值和安全范围整数与 Rust 输出一致。r3_record_value_canonical_bytes_match_explicit_rule 逐字节核对 text、bool、int、tag、section、含 kv/codes 的 field；包含引号、反斜线、控制字符、汉字和 U+2028。重复顶层键、记录版本键、枚举键及 concurrent 映射键的拒绝测试通过；普通键只有 concurrent 的旧反例也已被拒绝。

**剩余问题与复现：**

- 整数范围检查只存在于 RecordValue::Int。ItemOverview::decode 在反序列化后仅检查 v；r3_overview_safe_integer_range_is_enforced 将 trashed_at 设为 2⁵³，编码后仍能被 decode 接受，而 §1 的统一规则上限是 2⁵³−1。更大的 i64 同样未经过该范围判断。
- 同一 rev 内容不一致时，代码序列化的是 Option<RecordValue>：墓碑的比较字节为 ASCII **null**。规范只描述省略 val 的线格式和“记录值的规范编码”，没有明确墓碑的比较表示；这会影响墓碑与普通值的字节排序。测试确认了 Rust 实际输出 null，但这不能替代规范定义。
- encode_for_write 只检查文档总长度，不验证公开 records／concurrent 字段的结构和单值限制。正常 set 与 decode 有验证，直接构造 ItemDoc 的库调用者则可能写出自己之后不能解码的文档。接口需要验证或明确限定只接受已验证状态。

**影响：** 新整数规则并未覆盖全部相关文档；另一语言实现可能接受集合不同或在异常版本决胜时选择不同结果。未证明正常 UI 会生成超范围时间，也未证明此处能绕过认证。

**严重程度与置信度：低／已确认**（入口遗漏和 Rust 实际比较编码）；其他语言已经发生分歧则未验证。

**建议：** 抽出统一整数／文档校验；写入边界保证不变量。规范显式定义“墓碑比较编码为 null”、可选 null 与缺省的关系、数组顺序，以及规范编码只用于 RecordValue 还是整个文档；若覆盖整个文档，还需规定动态记录映射的排序，不能只引用示例的键序。

不采用 RFC 8785 本身可以接受。处理记录所称“RFC 8785 必须先转成通用 JSON 值并在不清零内存复制秘密”并不是 RFC 的要求；它规定输出规则，不规定必须使用 serde_json::Value。可将理由改为固定 schema 的定制编码更简单、便于控制秘密缓冲区，前提是规则和向量完整。[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)

### H8．建议：Q·2⁻⁴⁸ 的统计单位和跨重启范围需要写清

**位置：** spec/ipc.md §4.2 安全界限、§6 威胁表；crates/keevo-ipc/src/service.rs:28、:39；crates/keevo-service/src/server.rs:97；ipc/client.rs:96。

**成立的推导：** 固定一次诚实扩展尝试、假定其随机数新鲜不可预测、承诺隐藏且绑定、Noise／哈希／HKDF 满足文中所需假设，并且用户完整比较可信界面的 48 位 SAS，则第二条消息后发起方没有尚未承诺的第三条负载自由度。服务端每次新贡献产生一次约 2⁻⁴⁸ 的匹配机会；独立理想化下为 1−(1−2⁻⁴⁸)^Q，联合界不超过 Q·2⁻⁴⁸。Q=10 时约 3.55×10⁻¹⁴。变长名称位于固定字段之后，不造成分割歧义；静态公钥也被承诺，第三条 Noise 密文在固定握手状态及明文下由 AEAD 确定。旧 JSON 别名不再提供额外选择。

**计数核对：**

- begin 在产生第二条消息前计数；即使之后断开、发错第三帧或用户拒绝，starts 不被删除，只有 active 被释放。所有 VaultService 克隆共享同一闸门。跨连接／中断测试通过，没有发现通过这些路径免费取得新的服务贡献。
- 对无效第一条消息，实际计数可能早于成功产生第二条消息，因而会多计而非少计；这是可用性取舍。
- starts 只存在于内存，服务重启后清零。r3_gate_counts_drops_across_connections 同时刻画了这一点。因此“每小时最多 10 次”目前只能保证在同一个持续运行的服务实例内，不涵盖重启。
- 如果把“配对”理解为包含多次扩展重试的整个交互，单独计真实服务的 Q 不足。可以让一个真实服务尝试保持待确认，用户在扩展侧重新发起 R 次尝试；中间人作为这些尝试的响应方会得到 R 次新的匹配机会。r3_one_service_contribution_allows_multiple_extension_trials 确认状态机允许一个服务待确认期间完成两个扩展侧 SAS 计算。没有生成碰撞或编写完整利用。
- 对含 Q_s 个服务尝试和 Q_e 个扩展尝试的笼统统计窗口，保守的候选配对联合界可写为 Q_s·Q_e·2⁻⁴⁸，再用交互约束收紧。若仍用 Q·2⁻⁴⁸，应明确它是**一次固定扩展尝试**的界；客户端重试另计，不能把小时服务预算直接当成整个交互的总机会数。

**影响：** 这是概率承诺的适用范围问题。它不恢复 G1 的离线编码枚举能力，也未使小规模正常重试变成实际可行的 SAS 碰撞攻击。

**严重程度与置信度：建议／已确认**（计数实现、重启及重试路径）；完整的自适应多会话安全证明本轮未给出，应作为剩余疑虑。

**建议：** 在规范中固定统计窗口、客户端重试单位、重启后预算行为和可信 UI 前提。若要求跨重启限频，需持久化或外部可信计数；否则如实限定为每次服务运行的预算。保留完整 48 位比较，不能用清洗后的显示名代替身份核对。

## 4. 规范与实现的不一致

本节只覆盖本轮改动。已在 H1–H8 说明的问题仅列修改责任；已知的 M1/M2/M3 未实现事项列为验证边界，不重复计为漏洞。

### 4.1 第二轮 §4 的逐项复核

| 第二轮指出的差异／本轮新增约束 | 本轮结果与依据 | 应修改哪一方 |
|---|---|---|
| 第三条消息承诺只覆盖解析字段 | **修复成立**。crypto/noise.rs:32 对原始 third_payload 哈希；ipc/service.rs:452 先验证承诺，再解析 32 字节之后的 UTF-8 名称。旧别名和逐字节变化测试通过。 | 此项无需再改；实际截止时间与预算范围见 H5、H8。 |
| 内层 nonce 的 base64 变体未定义 | **修复成立**。第三条负载现在是原始 nonce 和 UTF-8 字节，不存在内层 base64。外层 d 继续采用已有的 base64url 无填充编码，不属于承诺外的新握手内容。 | 无。 |
| 规范 JSON 未定义 | **部分成立**。固定 RecordValue 的顺序与转义已定义并通过字节核对；墓碑比较编码仍未定义，整数约束存在入口遗漏，见 H7。 | 规范补比较域和 null；实现补验证。 |
| (hlc, origin) 相同时无最终决胜规则 | **修复成立**。revisions.md §5.1 与 format/merge.rs:292 均为 (hlc, origin_device, rev)，最后按 rev 决胜。 | 无。 |
| 任意键可只有 concurrent | **修复成立**。format/record.rs:236 拒绝普通键无当前版本；两个删除键是明确例外。例外内部的 purged 形态仍有 H4。 | purged 的进一步限制改代码；不要撤回普通键检查。 |
| 对象存在性并非所称的极大元状态 | **部分成立**。删除候选现在进入合并状态，旧 G2 反例修复；None 的不可写回条件仍须进入性质定义，见 H4。 | 规范限定适用域，或扩充可表示的状态。 |
| 90 天承诺与迁移／时钟行为不符 | **部分成立**。v1 迁移正确；单次限增不能证明只会延长保留，见 H1。 | 规范与代码。 |
| 数据库读入前限长、进程级 KDF | **部分成立**。KDF 全进程调用点互斥已落实；列预检需要一致快照及元数据入口覆盖，见 H3。 | 存储代码及 crypto §8.5 的保证条件。 |
| 全部并发版本缺少可容纳保证 | **引入了新问题**。普通大值冲突可精简；新父上限和墓碑总量形成其他保存死角，见 H2。 | 规范先确定完整策略，再实现。 |
| deadline 注释仍称握手完成起算 | **修复成立**。ipc/service.rs:18 的注释与收到第一条完整配对帧时建立 deadline 一致；on_frame 和 confirm_pairing 检查同一时限。socket 取消另见 H5。 | I/O 实现需要补齐；不能用改好的注释代替绝对超时。 |
| 规范编码比较产生未清零的额外副本 | **修复成立**。format/merge.rs:242 使用 Zeroizing<Vec<u8>> 保存排序键，移除了该处普通 Vec 副本，且仅在同 rev 内容矛盾时编码。 | 此处无；已知 serde 临时转义缓冲不在本轮重复报告。 |
| 新重复键拒绝规则 | 已核实记录映射、concurrent、自带字段的结构及被测嵌套枚举拒绝重复；未知字段仍拒绝。依据：format/record.rs:302；item.rs:119；serde 派生声明；r3_duplicate_keys_rejected_at_all_json_levels。 | 未发现本轮被测路径的重复键绕过；保留多层回归测试。 |
| “墓碑头并入合并修订后 resurrected 不再出现” | revisions.md §5.3 的这句话与新机制不符：即使没有实际 Deleted 头，merge.rs:175 仍从文档 concurrent 中取得 purged，并在撤销时设 resurrected。写时 settle 将其覆盖后提示才可消失。 | 改规范的提示生命周期描述；不删除保留的候选来迎合旧句子。 |
| 删除状态不作为字段冲突 | merge.rs:151 只排除了 purged；两个不同 trashed 候选产生的 Conflict 在后续 suppress(trashed) 后没有从 conflicts 列表移除。可按根上两个不同回收站时间头，再加一个并发普通编辑头逐步推导；与 revisions.md §5.5 “撤销删除不算字段冲突”不一致。 | 代码在撤销 trashed 后移除其字段 Conflict，或统一定义冲突展示口径。本轮未额外运行专门测试，不据此增加漏洞级别。 |
| 两端显示相同的清洗名称 | Rust ExtensionClient::display_name 与服务共用 message.rs:274，Cc/Cf 及 64 标量截断独立测试通过。当前浏览器 background.ts:54 固定传入 Chrome；WASM 的 ShowSas 事件及 popup 只显示 SAS，没有把 display_name 接到名称展示。 | M1 展示层落实同一规则；本轮只确认库规则一致，不声称已验证完整的双端名称 UI。 |

字段顺序之外的密码格式本轮没有改动：132 字节 AAD、keyset binding、既有 HKDF 域标签及 Padmé 填充仍通过独立向量。新配对承诺准确为 SHA-256(ASCII 标签 || pk[32] || nonce[32] || UTF8(name))；prologue 仍为 ASCII keevo/v1/ipc || 0x00 || pair/session || 0x00 || origin；SAS 使用完成后的握手 hash 作 IKM、空 salt、ASCII keevo/v1/ipc-sas 作 info，输出 6 字节。字节绑定不能证明显示名所描述的浏览器身份；显示名仍只是标签。

### 4.2 修订图、HLC 与写入路径

**修订图：修复主体成立。** RevisionGraph::insert 在排序去重父列表后比较重复元数据，未知父、自环及元数据不一致的同 rev 均被拒绝（crates/keevo-format/src/graph.rs:38）。当前生产构图入口是 core/vault.rs:654：调用 Store::graph，按本地 seq 取得元数据，再逐个 insert；Store::insert_revision 先要求父已经存在并属于同一 object_id。因此对通过存储 API 写入的图，新增的拓扑前提得到满足；被篡改的顺序会报错，不会接受成环。

最多 256 个父的上限目前由 Store 强制，RevisionGraph::insert 本身没有同样的数量检查，Store 还在父集合去重前检查数量。未来接收器若直接使用 RevisionGraph，应明确先做数量／对象边界验证，或把上限也放入图层；不能把“图插入成功”当成全部元数据已验证。M2 完整接收校验已列为未实现，本轮不把它本身当新漏洞。

**HLC：新增规则本身自洽，注释和恢复集成还需对齐。** observe 只采纳不超过 now + 24 小时的远端物理时间，但合并使用原值；next 在 last + 1 溢出时返回 ClockExhausted。r3_hlc_boundary_restore_and_exhaustion 验证了边界上可采纳、u64::MAX 不被采纳、正常递增及耗尽报错。

revisions.md §3 的恢复条款已经写成“持久化值与符合 24 小时条件的本地修订最大值”，没有无条件重引入被拒绝的远端极值。hlc.rs:63 的 restore 注释却仍让调用者取所有记录最大值，**应改注释**。当前 Vault::open_with_store（core/vault.rs:195）只恢复持久化 META_HLC，没有扫描修订；M2 接收／恢复接线时必须执行规范中的过滤和持久化契约。已有持久化值耗尽时拒绝写入符合当前规范，不能悄悄降回较小 HLC。

**写时收敛：定义已清楚改善。** revise 先 settle_for_write，再执行编辑，再以全部头为父写入；恢复删除确实改变输入，不能再用纯合并结合律约束它。规范已要求保存前向用户说明“保存即确认恢复”，G8 也要求保存前提示完整性问题。核心 API 不带“用户已确认”的能力凭证，故这些要求是调用者/UI 契约；确认面板属于已列明的 M1 工作。H2 的容量问题及 H4 的可表示性需要先解决，才能把同一论证用于未来分批收敛。

### 4.3 本机密钥包裹：结构方向成立，尚不足以宣称字节规范完全定稿

依据 spec/crypto.md §8.6，当前字段前缀有明确长度：version 1、purpose 1、eph_pub 65、nonce 12，tag 是末尾 16 字节；临时公钥采用 X9.63 未压缩表示，密文占中间剩余部分。HKDF 的 salt 是 account_id，info 包含 purpose；AAD 再绑定 version、purpose、account_id、device_id，且各用途使用不同 SE 密钥。没有发现这些定长字段的拼接歧义或用途之间缺少域分隔。

需要在该本机格式定稿／实现前补充：

- 列出每个 purpose 的**精确明文布局及字节数**。SK 的原始值是 16 字节、Noise 私钥是 32 字节，但目前“按用途固定”没有给表；AUK 是只存 32 字节密钥、还是同时带 kid，设备标记到底存什么，也没有明确。§9.2 的 child_kid || child_key 不应靠实现者猜测是否适用于 §8.6。
- 明确 shared 是 P-256 原始 ECDH 输出的定长字节表示，eph_pub 的有效点／编码检查，以及每种本机文件在分配前的总长度上限。固定宽度应保留前导零，不能采用平台任意字符串或已派生过的秘密。
- 补 SE 可访问性策略及锁屏行为。privateKeyUsage／biometryCurrentSet 是用途访问条件，不能替代完整的创建和恢复参数说明。
- “失败视为材料不存在，退回主密码与账户密钥”适用于停止使用损坏材料，但不是四种材料相同的恢复过程。丢失 Noise 静态私钥会改变扩展固定的服务身份；凭主密码不会自动还原它。设备标记失效会生成新的 device_id，而其他本机包裹的 AAD 也绑定旧 device_id，需明确迁移／重包顺序及失败原子性。不要在用户取消 Touch ID 时静默改身份或覆盖旧文件。

保护范围的修改与第二轮证据相符：不需要用户在场的 blob 可由本机同用户另一程序使用；隔离的是原始 SE 私钥和离机副本的可用性，不是同机应用身份。被包裹的 AUK／SK／Noise 私钥解包后仍进入普通进程内存。用途与 AAD 不提供文件新鲜度，也不阻止具有本机解包能力的人重新包裹其选择的数据。需要用户在场的 AUK 不等于绑定 Keevo 的代码身份；其完整 Touch ID、取消、锁屏及指纹变更流程仍未实测。

§8.6 明确不参与同步、独立负责版本迁移是合理的，因此这些本机布局问题不必阻塞其他已定稿的信封字节格式；它们也不能被“已有独立向量一致”覆盖，因为现有 Python 向量不包含 §8.6。

### 4.4 配对记录：加密存储方向成立，锁定期间的持久化契约需补齐

把授权记录放入加密保险库，而非可由同用户无提示重包的 SE 文件，解决了第二轮指出的设计冲突。首次解锁前 IK 返回 locked，首次解锁后保留公开配对信息和授权缓存，使锁定状态下仍可查询 status；这与“非 status 的请求在锁定时失败”相容。撤销修改同一内存记录并在每个请求前复查，也与该缓存模型相容。

但下列设计问题尚需明确，当前开发 JSON 存储不能验证它们：

- 第一次解锁前能否接受 XX？若可以，确认后没有数据库解密／写入密钥时如何持久化配对？若不可以，应明确返回 locked 或先要求原生解锁，而不只是规定 IK。
- 锁定后若 AUK、密钥集和数据密钥已清零，撤销／新配对如何持久化？可以要求解锁、保留明确的待提交撤销，或使用另有威胁说明的可写授权域，但不能未经说明保留整个数据库的解密能力。
- 重新解锁时不得用旧磁盘记录覆盖内存中的撤销；若写盘失败，§4.4 已要求警告“重启后可能失效”，应明确内存撤销优先级及下一次解锁的补提交流程。
- PairingStore::save（ipc/service.rs:85）目前不返回 Result。正式数据库实现需要把失败交回协议层，否则可能发送 paired 后实际未保存。新增正式持久化实现时应一起定义成功确认的时机。
- ipc.md §4.3 一句“会话不跨越锁定”，随后又说“锁定时不断开”，文字仍矛盾。依现有状态机与本轮缓存设计，合理表述是**传输会话可以保留，解锁授权不能保留**；如作者选择相反策略，代码和新缓存用途也需相应调整。

这些是新持久化设计需要完成的状态约定，不是把处理记录 §8 已声明的“正式配对数据库未实现”重新报一次漏洞。

### 4.5 ADR-0003 与安全文档的修订

| 项目 | 复核结论 |
|---|---|
| Library Validation | **表述修复成立。** ADR:17、:54 与 security.md:170 现在区分默认启用的验证和“没有 Team ID，不能按同团队规则放行自家 dylib”。保留验证、Rust 静态链接两者相容；静态链接不替代对 dlopen／插件的运行时检查。与第二轮 Apple 系统库可加载、另一 adhoc dylib 被拒绝的实测相符，也与 Apple 文档一致。[Apple Library Validation](https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.security.cs.disable-library-validation) |
| Sigstore、校验和及首次信任 | **表述修复成立。** ADR:23 固定发布 workflow 身份、v* 标签和 GitHub Actions OIDC issuer，并要求透明日志证明；:24 不再把同渠道的普通校验和当来源认证；:25 把 Sparkle 更新公钥的首次信任接到已验证安装包。正式验证还需明确完整身份匹配、仓库与 ref 约束、工具取得及降级策略，已合理留到 M3；本轮无发布产物可验。[Sigstore 验证文档](https://docs.sigstore.dev/cosign/verifying/verify/) |
| 账户密钥与服务静态私钥的不同后果 | **表述修复成立。** ADR:49–:50 和 security A7 分开说明：SK 泄露使保险库保护退化为主密码与 KDF；Noise 私钥泄露直接损害服务身份，不以主密码再保护该身份。后者的本机冒充是明确接受的 A7 残余风险，不应写成持钥仍无法冒充。 |
| 两张能力表 | **前轮指出的过度绝对表述已收窄。** Safari 区分正式分发与开发者设置；iOS 改为项目支持政策，不声称排除所有地区安装例外；钥匙串区分传统登录钥匙串与访问组保护／同步能力；手动通过 Gatekeeper 标为待验证。临时签名可声明本地 entitlement 与项目决定不使用它们也已分开。完整的受管设备、分发渠道和应用包行为本轮没有实际验证。 |
| 主程序替换的非目标 | **边界现在明确且可接受。** 主程序本身是信任锚；把它替换等于替换受信实现。security.md:18 明确承认同用户可能可写，未依赖尚未验证的 App 管理保护。编译固定 helper cdhash 仍必须防住“只换 helper”，不能把主程序非目标扩大成整个包内任意替换都不用检查。 |
| SE 设备标记与本机包裹 | **风险说明修复成立，布局仍需 §4.3 的补充。** 已删除“比钥匙串更可靠”的无依据比较，明确无法发现同机数据库克隆、损坏和缺失按新设备处理；不再把无用户在场包裹当授权记录完整性保护。第二轮跨进程解包证据仍适用；本轮没有把它扩大为已验证 Touch ID 流程或跨硬件迁移。 |

本轮对 ADR 的核实是条文、公开平台规则及第二轮本机实验的交叉核对。真实 SwiftUI 发布包、下载隔离属性、公证替代安装流程、更新时服务重启、Apple App 管理保护和完整生物识别流程均未由这些小型实验得到证明。

## 5. 仍未覆盖的部分

- **新配对协议的独立密码实现和完整多会话证明。** 当前 Rust 双端共用 snow 和协议库；逐字节变异、旧别名、重放和来源绑定测试不能替代另一实现。H8 给出条件化概率分析，没有做 48 位碰撞搜索；第三条消息的固定向量和真实双端 UI 仍待实现计划中的验证。
- **真实平台与发布链。** 本轮只在一台 Mac、一个系统版本运行；没有登记指纹的完整 Touch ID 测试、第二台 Mac、完整签名应用包或正式 Sigstore 发布包。第二轮非用户在场跨进程解包、Library Validation 的实验是既有证据，本轮没有冒充重新完成这些平台测试。M1.1／M3 的已知事项未当漏洞报告。
- **所有修订图的形式化性质。** 移植的 200 个普通记录随机图、作者原有模拟，以及新增 500 个含删除状态图都只提供测试证据。新增分组检验覆盖活的中间视图，已删除视图按 H4 单独刻画，未声称证明了无条件闭合的结合律。对 M2 写新墓碑清理残留头的方案只核对了它属于新删除操作，没有运行尚未实现的同步路径。
- **持久化故障和大规模资源压力。** 长度竞态用第二连接确定性调度；时钟缺失／损坏是定点测试；未做真实断电、磁盘满、杀进程恢复矩阵。最大新增大小反例约 17 MiB 级，未用 GB 级输入压垮机器。头、修订图总规模没有硬上限；祖先集合及候选两两因果判断的成本仍随图和候选增长，单值／单信封限长不构成全进程内存或 CPU 上限。
- **正式加密配对记录、撤销持久化及本机包裹。** §4.3、§4.4 给出设计检查和待澄清之处，当前开发实现无法证明其落盘、锁屏和恢复行为。同步签名、认证历史摘要、附件格式等仍按 spec/REVIEW.md §5 与处理记录 §8 的已知范围处理。
- **未改动部分的重新全面审计。** 仅运行已有测试并移植相关 r2_ 回归，没有重新穷举全部网址匹配、全部密码原语实现或供应链。本报告也不把原有向量通过解释为所有新机制均已覆盖。没有重跑完整模糊测试、浏览器 UI 测试或 M1 应用 smoke test。

## 6. 给作者的问题

这些问题不影响已经给出的确定性反例；需要答案的是最终设计选择和冻结边界。

1. **大小策略：** 对 257 个头以及删除全部键仍超过 16 MiB 的状态，选择什么可验证的恢复表示？是否仍承诺保留对象身份和历史，并通过同对象精简恢复编辑，还是明确允许只能导出重建？若分批合并，如何修改“全部头为父”的规则并处理已删除中间状态？
2. **保留时间：** 产品到底承诺“按保守计时不会早于真实经过的 90 天”，还是接受墙上时钟校正使历史更早消失？缺失任一时钟字段、检测到异常值及两次元数据写入中断时，是否统一暂停清理？
3. **删除状态与规范编码：** 是否确认 attr:purged 仅能由内部合并／恢复构造，磁盘上的活删除候选必须是 true、HLC 0？是否采用 null 作为墓碑比较编码，并将已删除视图排除在可写回纯合并的定义域之外？
4. **配对概率与预算：** “一次配对”是否严格指一次扩展发起、不可自动重启的尝试？每小时 10 次是否要求跨服务重启成立？如果允许一个服务确认窗口中多次扩展重试，概率和用户提示如何计数？
5. **锁定与授权记录：** 首次解锁前的 XX、锁定后撤销／新配对、写盘失败后的再解锁，分别采用什么状态转移和持久化策略？paired 的成功消息是否必须晚于可靠落盘？
6. **本机包裹冻结范围：** §8.6 是否明确留在 M1.1 单独定稿，而不随共享信封／条目格式冻结？四个 purpose 的精确明文、SE 可访问性条件、Noise 身份丢失后的重新配对，以及 device_id 更新时其他包裹的处理顺序是什么？

