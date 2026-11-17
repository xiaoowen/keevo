## 做了什么

<!-- 一两句话说明改动与动机；关联的 issue 或 ADR -->

## 检查清单

- [ ] 涉及密码学、数据格式或协议时：已先更新 `spec/`，并重新生成测试向量
- [ ] 新增或修改的行为有测试覆盖
- [ ] `cargo fmt`、`cargo clippy`、`cargo test` 本地通过
- [ ] 新增依赖已说明理由，并通过 `cargo deny check` 与 `cargo vet`
- [ ] 没有新增网络请求；如有，已登记在 `docs/governance.md` §5
- [ ] 日志、错误信息中没有秘密
- [ ] 所有提交都带有 `Signed-off-by`（`git commit -s`）
