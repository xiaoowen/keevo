# 参与贡献

感谢你愿意参与 Keevo！Keevo 是一个以安全为核心的项目，所以贡献流程比一般项目严格一些。下面的规则都是为了让每一行代码都经得起审查。

> 发现安全漏洞？**请不要提交公开 issue**，按 [SECURITY.md](SECURITY.md) 私下报告。

## 先读这些

- [docs/README.md](docs/README.md)：产品与技术设计总览
- [docs/security.md](docs/security.md)：威胁模型与安全设计
- [spec/](spec/)：可审计的规范，包括加密格式与修订模型

## 工作流程

1. **讨论先行**：
   - 新功能、架构调整、依赖变更，先开 issue 讨论。
   - 重大决策写 ADR，放在 `docs/adr/`，模板见 [0000-template.md](docs/adr/0000-template.md)。
2. **规范先行**：任何涉及密码学、数据格式或协议的改动，必须先修改 `spec/` 中的规范并更新测试向量，再修改实现。两者在同一个 PR 中提交。
3. **小步提交**：一个 PR 只做一件事。
4. **审查**：
   - 安全敏感路径（见 [.github/CODEOWNERS](.github/CODEOWNERS)）需要安全负责人批准。
   - 涉及密码学的改动需要两名维护者批准。

## 开发环境

Rust 工具链版本固定在 `rust-toolchain.toml` 中，rustup 会自动安装对应版本。

```bash
cargo fmt --all --check                     # 格式
cargo clippy --workspace --all-targets      # lint（CI 中警告即失败）
cargo test --workspace                      # 测试
python3 scripts/check-crypto-deps.py        # 密码学边界检查
cargo deny check                            # 安全公告、许可证、来源
cargo vet                                   # 供应链审计
scripts/build-macos.sh --smoke              # macOS 空壳应用 + Swift 端冒烟测试
```

模糊测试需要 nightly 与 cargo-fuzz：

```bash
cd fuzz && cargo +nightly fuzz run envelope_open -- -max_total_time=60
```

测试向量由独立的 Python 参考实现生成（只在修改规范时需要）：

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes --no-deps -r spec/reference/requirements.txt
.venv/bin/python -I spec/reference/generate_vectors.py           # 重新生成
.venv/bin/python -I spec/reference/generate_vectors.py --check   # 只比对
```

## 硬性规则

- **密码学边界**：
  - 只有 `crates/keevo-crypto` 可以直接依赖密码学原语库，由 CI 检查。
  - 不自创原语或协议。
- **秘密不落地**：
  - 密钥类型不得实现 `Debug`、`Display`、`Clone` 或序列化。
  - 日志、错误信息、崩溃信息中不得出现秘密。
- **不 `unwrap`**：非测试代码中禁止 `unwrap` / `expect` / `panic!`，由 clippy 强制。
- **引入依赖**：
  - 每个新依赖都要在 PR 中说明理由。
  - 必须通过 `cargo deny check`，并通过 `cargo vet` 审计：要么由已导入的审计覆盖，要么自行 `cargo vet certify`。
  - 能不加就不加。
- **网络请求**：
  - 新增任何网络请求，都必须在 [docs/governance.md §5](docs/governance.md#5-隐私承诺产品层面) 的清单中登记。
  - 默认关闭。

## 提交信息

使用 [Conventional Commits](https://www.conventionalcommits.org/zh-hans/)：

```
<type>(<scope>): <描述>

- 要点一
- 要点二

Signed-off-by: 你的名字 <you@example.com>
```

- **常用 type**：`feat`、`fix`、`docs`、`refactor`、`test`、`build`、`ci`、`chore`、`security`。
- **scope**：取模块名，如 `crypto`、`spec`、`docs`、`ci`。
- 中文或英文均可。

## DCO（开发者原创声明）

每个提交都必须带 `Signed-off-by` 行，表示你同意 [Developer Certificate of Origin 1.1](https://developercertificate.org/)：你有权按本项目的许可证提交这份贡献。

用 `git commit -s` 可以自动加上这一行。

## 许可证

你的贡献按其所在路径对应的许可证授权，见根目录 [LICENSE](LICENSE)。其中 `apps/` 与 `crates/keevo-cli/` 为 GPL-3.0-or-later，并附加 App Store 许可。提交即表示你同意这些条款。

## 行为准则

参与本项目即表示你同意遵守 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。
