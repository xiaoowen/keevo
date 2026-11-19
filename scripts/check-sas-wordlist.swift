// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 检查 SAS 词表（spec/sas-wordlist-v1.tsv）的中文词去掉声调后拼音互不相同，念出来也不会混淆。
// 其余性质（字数、汉字不重复、英文前缀与编辑距离）由 crates/keevo-ipc 的测试检查。
// 用法：swift scripts/check-sas-wordlist.swift [spec/sas-wordlist-v1.tsv]
// 拼音来自系统的 Mandarin-Latin 转换：多音字取默认读音，可能漏掉少数同音，不会误报。

import Foundation

let path = CommandLine.arguments.dropFirst().first ?? "spec/sas-wordlist-v1.tsv"
guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
    FileHandle.standardError.write("读不到 \(path)\n".data(using: .utf8)!)
    exit(2)
}
var seen: [String: String] = [:]
var failures = 0
for line in text.split(separator: "\n") {
    let cols = line.split(separator: "\t")
    guard cols.count == 3 else { continue }
    let zh = String(cols[2])
    let pinyin = (zh.applyingTransform(.mandarinToLatin, reverse: false) ?? zh)
        .applyingTransform(.stripDiacritics, reverse: false)?
        .lowercased()
        .replacingOccurrences(of: " ", with: "") ?? zh
    if let other = seen[pinyin] {
        print("✗ 同音：\(other) / \(zh)（\(pinyin)）")
        failures += 1
    }
    seen[pinyin] = zh
}
if failures > 0 { exit(1) }
print("拼音检查通过（\(seen.count) 个词）")
