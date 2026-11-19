# 支持一次性密码的网站

`totp_sites.txt`：安全中心"未开启两步验证"使用的网站列表（`docs/product.md` §5.6），每行一个域名。条目的网址是其中某个域名或它的子域、而条目中没有一次性密码时提醒。

- **来源**：2fa.directory（<https://github.com/2factorauth/twofactorauth>）的公开数据 `https://api.2fa.directory/v4/totp.json`，取 `methods` 含 `totp` 的网站。
- **许可**：MIT（© 2021 2factorauth and Contributors；© 2014-2020 Josh Davis）。
- **更新**：`python3 -I scripts/update-2fa-directory.py`。Keevo 运行时不联网，列表随源码一起审查与提交。
- **当前版本**：2026-11-19，1653 个网站，原始数据 SHA-256 `981d982d79277962ba992ca7709fbf82b7db30ab46a45a87990c7917d3ebb37c`。
