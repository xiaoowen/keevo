// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 设置窗口（⌘,）：左侧分页（参考系统设置与 1Password），右侧为分组卡片。

import SwiftUI

struct SettingsView: View {
    enum Page: Int, CaseIterable, Identifiable {
        case security, browser, developer
        var id: Int { rawValue }

        var title: String {
            switch self {
            case .security: "安全"
            case .browser: "浏览器"
            case .developer: "开发者"
            }
        }

        var symbol: String {
            switch self {
            case .security: "lock.shield"
            case .browser: "puzzlepiece.extension"
            case .developer: "terminal"
            }
        }
    }

    @ViewState private var page: Page

    init(initialTab: Int = 0) {
        _page = ViewState(initialValue: Page(rawValue: initialTab) ?? .security)
    }

    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 2) {
                ForEach(Page.allCases) { p in
                    SidebarRow(title: p.title, symbol: p.symbol, count: 0, selected: page == p, verticalPadding: 6) {
                        page = p
                    }
                }
                Spacer()
            }
            .padding(KV.Space.s2)
            .padding(.top, KV.Space.s2)
            .frame(width: 180)
            .background(KV.Colors.bgSurface)
            Rectangle().fill(KV.Colors.borderSubtle).frame(width: 1)
            ScrollView {
                VStack(alignment: .leading, spacing: KV.Space.s5) {
                    Text(page.title)
                        .font(KV.Typography.title)
                        .foregroundStyle(KV.Colors.fgPrimary)
                    switch page {
                    case .security: SecuritySettings()
                    case .browser: BrowserSettings()
                    case .developer: DeveloperSettings()
                    }
                }
                .padding(KV.Space.s6)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(KV.Colors.bgCanvas)
        }
        .frame(width: 720, height: 560)
    }
}

private struct SecuritySettings: View {
    @Environment(AppModel.self) private var model
    @ViewState private var askPassword = false
    @ViewState private var askDisable = false

    var body: some View {
        @Bindable var model = model
        VStack(alignment: .leading, spacing: KV.Space.s5) {
            SettingsSection(
                title: "自动锁定",
                footer: "睡眠、锁定屏幕、启动屏幕保护程序或切换用户时会立即锁定。"
            ) {
                SettingsRow(title: "闲置后锁定", detail: "这台 Mac 在这段时间内没有任何键盘、鼠标或触控板操作时锁定。") {
                    Picker("闲置后锁定", selection: $model.autoLockMinutes) {
                        ForEach(AppModel.autoLockChoices, id: \.self) { minutes in
                            Text(minutes < 60 ? "\(minutes) 分钟" : "1 小时").tag(minutes)
                        }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .fixedSize()
                }
            }
            SettingsSection(
                title: "解锁",
                footer: "以下情况必须输入主密码：Mac 重启后的首次解锁、超过上面的天数、Touch ID 连续 3 次未能识别、指纹有变化。这样你不会忘记主密码。"
            ) {
                SettingsRow(title: "使用 Touch ID 解锁", detail: touchIDDetail) {
                    Toggle("使用 Touch ID 解锁", isOn: Binding(
                        get: { model.touchIDEnabled },
                        set: { on in
                            if on { askPassword = true } else { askDisable = true }
                        }
                    ))
                    .kvSwitch("使用 Touch ID 解锁")
                    // 启用与关闭都需要在已解锁时验证身份
                    .disabled(model.phase != .unlocked || (!model.touchIDEnabled && !model.touchIDAvailable))
                }
                CardRowDivider()
                SettingsRow(title: "定期输入主密码", detail: "每 \(model.passwordIntervalDays) 天至少输入一次") {
                    Stepper(
                        "每 \(model.passwordIntervalDays) 天至少输入一次主密码",
                        value: Binding(
                            get: { Int(model.passwordIntervalDays) },
                            set: { model.setPasswordInterval(days: UInt8(clamping: $0)) }
                        ),
                        in: 1...30
                    )
                    .labelsHidden()
                    .disabled(model.phase != .unlocked)
                }
            }
            SettingsSection(
                title: "隐私",
                footer: "并非所有截屏方式都遵守这一设置，它不能防范这台 Mac 上的恶意软件。"
            ) {
                SettingsRow(
                    title: "不允许截屏或屏幕共享 Keevo 的窗口",
                    detail: "遵守 macOS 窗口共享设置的截屏、录屏与屏幕共享软件看不到 Keevo，避免共享屏幕时意外露出密码。"
                ) {
                    Toggle("不允许截屏或屏幕共享", isOn: $model.hideFromScreenCapture)
                        .kvSwitch("不允许截屏或屏幕共享 Keevo 的窗口")
                }
            }
        }
        .sheet(isPresented: $askPassword) {
            ConfirmPasswordSheet()
        }
        .sheet(isPresented: $askDisable) {
            DisableTouchIDSheet()
        }
    }

    private var touchIDDetail: String? {
        if !model.touchIDAvailable { return "这台 Mac 没有可用的 Touch ID，或还没有登记指纹。" }
        if model.phase != .unlocked { return "解锁 Keevo 之后才能更改。" }
        return nil
    }
}

/// 启用 Touch ID 前确认主密码（spec/crypto.md §8.7"启用 Touch ID"）。
private struct ConfirmPasswordSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @ViewState private var password = ""

    var body: some View {
        SheetScaffold(title: "启用 Touch ID", subtitle: "请输入主密码以确认。", systemImage: "touchid", width: 420) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                LabeledInput(label: "主密码") {
                    SecureField("", text: $password).onSubmit(enable)
                }
                ErrorText()
            }
        } footer: {
            Button("取消") { dismiss() }
                .buttonStyle(.kvSecondary)
                .keyboardShortcut(.cancelAction)
            Button("启用", action: enable)
                .buttonStyle(.kvPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty || model.busy)
        }
    }

    private func enable() {
        guard !password.isEmpty, !model.busy else { return }
        Task {
            if await model.enableTouchID(password: password) { dismiss() }
        }
    }
}

/// 关闭 Touch ID 前重新验证：Touch ID 或主密码（docs/ux.md §5"重新验证"）。
private struct DisableTouchIDSheet: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ReverifySheet(
            title: "关闭 Touch ID",
            message: "请先确认是你本人。关闭后，解锁时需要输入主密码。",
            confirmTitle: "关闭 Touch ID"
        ) { password in
            await model.disableTouchID(password: password)
        }
    }
}
