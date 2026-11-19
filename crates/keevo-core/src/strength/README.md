# 密码强度评估的词频表

`../strength.rs` 实现与 zxcvbn 等价的强度评估（`docs/product.md` §5.6），这里是它用到的词频表：每行一个词，按常见程度排序（第一行排名为 1）。

- **来源**：Dropbox zxcvbn 的 `src/frequency_lists.coffee`（<https://github.com/dropbox/zxcvbn>，master 分支，由其 `data-scripts/build_frequency_lists.py` 生成）。原文件的 SHA-256 为 `664d32190713e42b7726072a5cf7533bd4a469e5588c7c1bd2ff9485cdf83276`。
- **改动**：把每个列表拆成一个文件，逗号换成换行，词与顺序不变。
- **许可**：MIT。

```
Copyright (c) 2012-2016 Dan Wheeler and Dropbox, Inc.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

| 文件 | 词数 | SHA-256 |
|---|---|---|
| `passwords.txt` | 30000 | `f65b16793f0d335c87bf5bb4b19bcfc457462396169080b8c11a7c6f1d8b3731` |
| `english_wikipedia.txt` | 30000 | `b29af10c62218f948eb299e0c68b176ab1c5ecdfe9813bd957bf2c434e90813e` |
| `female_names.txt` | 3712 | `08346ad80d8d829fda1064485420da1e0771ba1e0dcd954252d43b61c5116aaf` |
| `surnames.txt` | 10000 | `87be6d1c0ab405012ae1a23d5552ed2da29d792bdfb0f898c2e806768ec33d65` |
| `us_tv_and_film.txt` | 19160 | `f146e15ecba3f37adcd7aa4fb23797555d1ab55489fbb0b989c60073f638aaa0` |
| `male_names.txt` | 983 | `5035ab3871a0dd421c960731bb5a77d6c5de784c554dcf67cdc2f01b3a0260da` |
