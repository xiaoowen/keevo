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

        /// 显示名（原始值写在偏好中，保持不变）。
        var title: String {
            switch self {
            case .password: tr("随机字符")
            case .passphrase: tr("口令短语")
            case .pin: "PIN"
            }
        }
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
    @ViewState private var copied = false

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
        SheetScaffold(
            title: tr("密码生成器"),
            systemImage: "wand.and.stars",
            width: 460
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s4) {
                KVSegmented(options: Mode.allCases.map { ($0.rawValue, $0.title) }, selection: $modeRaw)
                preview
                KVCard { options }
                    .onChange(of: recipe.description) { regenerate() }
            }
        } footer: {
            Button(tr("复制")) {
                if let result {
                    Clipboard.copy(result.value.expose())
                    copied = true
                }
            }
            .buttonStyle(.kvSecondary)
            .disabled(result == nil)
            if let use {
                Button(tr("使用")) {
                    if let result { use(result.value.expose()) }
                    dismiss()
                }
                .buttonStyle(.kvPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(result == nil)
            } else {
                Button(tr("完成")) { dismiss() }
                    .buttonStyle(.kvPrimary)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .onAppear(perform: regenerate)
        .onDisappear { result = nil }
    }

    @ViewBuilder
    private var options: some View {
        switch mode {
        case .password:
            sliderRow(tr("长度"), value: $length, range: 8...64, unit: tr("个字符"))
            CardRowDivider()
            toggleRow(tr("大写字母（A–Z）"), $uppercase)
            CardRowDivider()
            toggleRow(tr("小写字母（a–z）"), $lowercase)
            CardRowDivider()
            toggleRow(tr("数字（0–9）"), $digits)
            CardRowDivider()
            toggleRow(tr("符号（!#$%&*+-.:;=?@^_~）"), $symbols)
            CardRowDivider()
            toggleRow(tr("排除容易看错的字符（0 O o 1 l I）"), $avoidAmbiguous)
        case .passphrase:
            sliderRow(tr("单词数"), value: $words, range: 3...10, unit: tr("个单词"))
            CardRowDivider()
            SettingsRow(title: tr("分隔符")) {
                Picker(tr("分隔符"), selection: $separator) {
                    Text(tr("连字符 -")).tag("-")
                    Text(tr("空格")).tag(" ")
                    Text(tr("句点 .")).tag(".")
                    Text(tr("下划线 _")).tag("_")
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
            }
            CardRowDivider()
            toggleRow(tr("首字母大写"), $capitalize)
            CardRowDivider()
            toggleRow(tr("加一位数字"), $includeNumber)
            CardRowDivider()
            Text(tr("单词来自 EFF 大词表（7776 个英文单词，CC BY 3.0 US）。"))
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
        case .pin:
            sliderRow(tr("位数"), value: $pinLength, range: 4...12, unit: tr("位"))
        }
    }

    private func sliderRow(_ title: String, value: Binding<Double>, range: ClosedRange<Double>, unit: String) -> some View {
        HStack(spacing: KV.Space.s3) {
            Text(title).font(KV.Typography.body).foregroundStyle(KV.Colors.fgPrimary)
            Slider(value: value, in: range, step: 1)
                .tint(KV.Colors.accentFill)
                .accessibilityLabel(title)
                .accessibilityValue("\(Int(value.wrappedValue)) \(unit)")
            Text("\(Int(value.wrappedValue))")
                .font(KV.Typography.mono.weight(.semibold))
                .foregroundStyle(KV.Colors.fgPrimary)
                .frame(minWidth: 28)
                .padding(.vertical, 2)
                .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: 5, style: .continuous))
                .accessibilityHidden(true)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    private func toggleRow(_ title: String, _ isOn: Binding<Bool>) -> some View {
        SettingsRow(title: title) {
            Toggle(title, isOn: isOn).kvSwitch(title)
        }
    }

    private var preview: some View {
        VStack(alignment: .leading, spacing: KV.Space.s2) {
            HStack(alignment: .center, spacing: KV.Space.s2) {
                Group {
                    if let result {
                        classifiedText(result.value.expose(), font: KV.Typography.monoLarge)
                            .textSelection(.enabled)
                            .lineLimit(3)
                    } else {
                        Text(failed ? tr("请至少选择一种字符") : " ")
                            .font(KV.Typography.body)
                            .foregroundStyle(KV.Colors.statusDangerFg)
                    }
                }
                .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                IconButton(systemImage: "arrow.clockwise", label: tr("重新生成")) { regenerate() }
                    .keyboardShortcut("r")
            }
            .padding(.leading, KV.Space.s4)
            .padding(.trailing, KV.Space.s2)
            .padding(.vertical, KV.Space.s3)
            .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            if let result {
                StrengthMeter(bits: result.entropyBits)
            }
        }
    }

    private func regenerate() {
        do {
            result = try generatePassword(recipe: recipe)
            failed = false
            copied = false
        } catch {
            result = nil
            failed = true
        }
    }
}

/// 熵与强度。强度同时用文字、四段条与颜色表示（docs/ux.md §8）。
struct StrengthMeter: View {
    let bits: Double

    private var level: (Int, String, Color) {
        switch bits {
        case ..<40: (1, tr("弱"), KV.Colors.statusDangerFg)
        case ..<60: (2, tr("一般"), KV.Colors.statusWarningFg)
        case ..<80: (3, tr("强"), KV.Colors.statusSuccessFg)
        default: (4, tr("很强"), KV.Colors.statusSuccessFg)
        }
    }

    var body: some View {
        HStack(spacing: KV.Space.s2) {
            HStack(spacing: 3) {
                ForEach(0 ..< 4, id: \.self) { i in
                    Capsule()
                        .fill(i < level.0 ? level.2 : KV.Colors.borderSubtle)
                        .frame(width: 22, height: 4)
                }
            }
            Text(level.1).font(KV.Typography.footnote.weight(.semibold)).foregroundStyle(level.2)
            Text(tr("约 {} 比特熵", "\(Int(bits.rounded()))")).font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(tr("强度：{}，约 {} 比特熵", "\(level.1)", "\(Int(bits.rounded()))"))
    }
}

extension GeneratorRecipe {
    /// 用于检测设置变化后重新生成。
    var description: String { "\(self)" }
}
