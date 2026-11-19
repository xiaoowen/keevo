// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 界面文字的翻译（docs/ux.md §9）。中文是源语言：界面代码写 `tr("模板", 参数…)`，模板中的 `{}` 依次对应参数；
// 英文时按 apps/macos/Localization/en.json（生成为 LocalizationTable.swift）查找英文模板，可以用 `{0}`、`{1}`
// 调整参数顺序。表由 scripts/i18n.py 检查是否完整。

import Foundation

/// 界面语言：中文或英文。"设置 → 通用"中选定的语言写在本应用的 AppleLanguages 中，重新打开后生效；
/// 跟随系统时，系统首选语言是中文就用中文，其他语言都用英文。
enum UILanguage: Sendable {
    case zh, en

    static let current: UILanguage = {
        if let forced = ProcessInfo.processInfo.environment["KEEVO_LANG"] {
            return forced.hasPrefix("en") ? .en : .zh
        }
        let preferred = (UserDefaults.standard.array(forKey: "AppleLanguages") as? [String])?.first
            ?? Locale.preferredLanguages.first ?? "zh"
        return preferred.hasPrefix("zh") ? .zh : .en
    }()
}

private let englishTable: [String: String] = {
    guard let data = englishTableJSON.data(using: .utf8),
          let table = try? JSONDecoder().decode([String: String].self, from: data)
    else { return [:] }
    return table
}()

/// 翻译一段界面文字。`args` 依次填入模板中的 `{}`（英文模板可以用 `{0}`、`{1}` 指定顺序）。
func tr(_ key: String, _ args: String...) -> String {
    let template = UILanguage.current == .en ? (englishTable[key] ?? key) : key
    return fillTemplate(template, args)
}

func fillTemplate(_ template: String, _ args: [String]) -> String {
    guard !args.isEmpty, template.contains("{") else { return template }
    var out = ""
    var next = 0
    var i = template.startIndex
    while i < template.endIndex {
        if template[i] == "{", let close = template[i...].firstIndex(of: "}") {
            let inner = template[template.index(after: i) ..< close]
            if inner.isEmpty {
                out += next < args.count ? args[next] : ""
                next += 1
                i = template.index(after: close)
                continue
            }
            if let n = Int(inner) {
                out += n < args.count ? args[n] : ""
                i = template.index(after: close)
                continue
            }
        }
        out.append(template[i])
        i = template.index(after: i)
    }
    return out
}
