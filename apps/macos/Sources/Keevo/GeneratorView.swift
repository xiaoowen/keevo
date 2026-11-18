// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 密码生成器（keevo-core::generator）：随机字符、口令短语、PIN。熵由 Rust 按实际取值空间计算。

import KeevoKit
import SwiftUI

struct GeneratorView: View {
    enum Mode: String, CaseIterable, Identifiable {
        case password = "随机字符"
        case passphrase = "口令短语"
        case pin = "PIN"
        var id: String { rawValue }
    }

    /// 选择"使用"时调用；为 `nil` 时只提供复制（独立打开的生成器）。
    var use: ((String) -> Void)?
    @Environment(\.dismiss) private var dismiss

    @AppStorage("generator.mode") private var modeRaw = Mode.password.rawValue
    @AppStorage("generator.length") private var length = 20.0
    @AppStorage("generator.lowercase") private var lowercase = true
    @AppStorage("generator.uppercase") private var uppercase = true
    @AppStorage("generator.digits") private var digits = true
    @AppStorage("generator.symbols") private var symbols = true
    @AppStorage("generator.avoidAmbiguous") private var avoidAmbiguous = false
    @AppStorage("generator.words") private var words = 5.0
    @AppStorage("generator.separator") private var separator = "-"
    @AppStorage("generator.capitalize") private var capitalize = false
    @AppStorage("generator.number") private var includeNumber = true
    @AppStorage("generator.pinLength") private var pinLength = 6.0

    @ViewState private var result: GeneratedPassword?
    @ViewState private var failed = false

    private var mode: Mode { Mode(rawValue: modeRaw) ?? .password }

    private var recipe: GeneratorRecipe {
        switch mode {
        case .password:
            .password(length: UInt32(length), lowercase: lowercase, uppercase: uppercase, digits: digits,
                      symbols: symbols, avoidAmbiguous: avoidAmbiguous)
        case .passphrase:
            .passphrase(words: UInt32(words), separator: separator, capitalize: capitalize, includeNumber: includeNumber)
        case .pin:
            .pin(length: UInt32(pinLength))
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: KV.Space.s4) {
            Picker("方式", selection: $modeRaw) {
                ForEach(Mode.allCases) { Text($0.rawValue).tag($0.rawValue) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            preview

            Form {
                switch mode {
                case .password:
                    Slider(value: $length, in: 8...64, step: 1) { Text("长度 \(Int(length))") }
                    Toggle("小写字母", isOn: $lowercase)
                    Toggle("大写字母", isOn: $uppercase)
                    Toggle("数字", isOn: $digits)
                    Toggle("符号（!#$%&*+-.:;=?@^_~）", isOn: $symbols)
                    Toggle("排除容易看错的字符（0 O o 1 l I）", isOn: $avoidAmbiguous)
                case .passphrase:
                    Slider(value: $words, in: 3...10, step: 1) { Text("\(Int(words)) 个单词") }
                    Picker("分隔符", selection: $separator) {
                        Text("连字符 -").tag("-")
                        Text("空格").tag(" ")
                        Text("句点 .").tag(".")
                        Text("下划线 _").tag("_")
                    }
                    Toggle("首字母大写", isOn: $capitalize)
                    Toggle("加一位数字", isOn: $includeNumber)
                    Text("单词来自 EFF 大词表（7776 个英文单词，CC BY 3.0 US）。")
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                case .pin:
                    Slider(value: $pinLength, in: 4...12, step: 1) { Text("\(Int(pinLength)) 位") }
                }
            }
            .formStyle(.grouped)
            .onChange(of: recipe.description) { regenerate() }

            HStack {
                Button { regenerate() } label: { Label("重新生成", systemImage: "arrow.clockwise") }
                Spacer()
                Button("复制") {
                    if let result { Clipboard.copy(result.value.expose()) }
                }
                .disabled(result == nil)
                if let use {
                    Button("使用") {
                        if let result { use(result.value.expose()) }
                        dismiss()
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(result == nil)
                } else {
                    Button("完成") { dismiss() }.keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(20)
        .frame(width: 440)
        .onAppear(perform: regenerate)
        .onDisappear { result = nil }
    }

    private var preview: some View {
        VStack(alignment: .leading, spacing: KV.Space.s2) {
            Group {
                if let result {
                    classifiedText(result.value.expose(), font: KV.Typography.monoLarge)
                        .textSelection(.enabled)
                        .lineLimit(3)
                } else {
                    Text(failed ? "请至少选择一种字符" : " ").foregroundStyle(KV.Colors.statusDangerFg)
                }
            }
            .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
            .padding(KV.Space.s3)
            .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: KV.Radius.md))
            if let result {
                StrengthLabel(bits: result.entropyBits)
            }
        }
    }

    private func regenerate() {
        do {
            result = try generatePassword(recipe: recipe)
            failed = false
        } catch {
            result = nil
            failed = true
        }
    }
}

/// 熵与强度。强度同时用文字与颜色表示（docs/ux.md §8）。
struct StrengthLabel: View {
    let bits: Double

    private var level: (String, Color) {
        switch bits {
        case ..<40: ("弱", KV.Colors.statusDangerFg)
        case ..<60: ("一般", KV.Colors.statusWarningFg)
        case ..<80: ("强", KV.Colors.statusSuccessFg)
        default: ("很强", KV.Colors.statusSuccessFg)
        }
    }

    var body: some View {
        HStack(spacing: KV.Space.s2) {
            Text(level.0).font(KV.Typography.bodyStrong).foregroundStyle(level.1)
            Text("约 \(Int(bits.rounded())) 比特熵").font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
        }
        .accessibilityElement(children: .combine)
    }
}

extension GeneratorRecipe {
    /// 用于检测设置变化后重新生成。
    var description: String { "\(self)" }
}
