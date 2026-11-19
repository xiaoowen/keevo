# 导入测试的样例文件

全部是虚构的数据，用于 `crates/keevo-core/src/import/tests.rs` 与 `fuzz/` 的初始语料。

| 文件 | 来源 | 说明 |
|---|---|---|
| `chrome.csv` | Chrome | 含逗号、引号与换行的字段 |
| `safari.csv` | Safari | CRLF 换行，含 `OTPAuth` |
| `firefox.csv` | Firefox | 没有标题列，标题取网址的主机 |
| `lastpass.csv` | LastPass | 文件夹以 `\` 分隔；`http://sn` 为安全笔记 |
| `bitwarden.json` | Bitwarden | 明文导出：登录、安全笔记、银行卡、身份、SSH 密钥、Steam 令牌 |
| `bitwarden-encrypted.json` | Bitwarden | 用 `correct horse battery` 保护的 `bitwarden.json`（PBKDF2 5000 次） |
| `sample.1pux` | 1Password | 登录、银行卡、安全笔记、数据库、SSH 密钥、文档（附件）、已归档的登录 |

`bitwarden-encrypted.json` 与 `sample.1pux` 由 `make_samples.py` 生成：AES-256-CBC 用 `openssl` 命令行、
PBKDF2 与 HMAC 用 Python 标准库，与 Rust 的实现互相独立，因此也是一次交叉验证。重新生成：

```sh
python3 -I crates/keevo-core/src/import/testdata/make_samples.py crates/keevo-core/src/import/testdata
```

（AES 的 IV 固定，重新生成的 `bitwarden-encrypted.json` 与仓库中的相同；zip 中有时间戳，`sample.1pux` 会略有不同。）
