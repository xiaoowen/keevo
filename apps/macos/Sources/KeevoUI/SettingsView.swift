// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 设置窗口（⌘,）：左侧分页（参考系统设置与 1Password），右侧为分组卡片。

import SwiftUI

struct SettingsView: View {
    enum Page: Int, CaseIterable, Identifiable {
        case general, security, backup, browser, developer
        var id: Int { rawValue }

        var title: String {
            switch self {
            case .general: tr("通用")
            case .security: tr("安全")
            case .backup: tr("备份")
            case .browser: tr("浏览器")
            case .developer: tr("开发者")
            }
        }

        var symbol: String {
            switch self {
            case .general: "gearshape"
            case .security: "lock.shield"
            case .backup: "archivebox"
            case .browser: "puzzlepiece.extension"
            case .developer: "terminal"
            }
        }
    }

    @ViewState private var page: Page

    init(initialPage: Page = .general) {
        _page = ViewState(initialValue: initialPage)
    }

    @Environment(AppModel.self) private var model

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
                    case .general: GeneralSettings()
                    case .security: SecuritySettings()
                    case .backup: BackupSettings()
                    case .browser: BrowserSettings()
                    case .developer: DeveloperSettings()
                    }
                }
                .padding(KV.Space.s6)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(KV.Colors.bgCanvas)
        }
        .frame(width: 720, height: 620)
        .onAppear(perform: showRequestedPage)
        .onChange(of: model.requestedSettingsPage) { showRequestedPage() }
    }

    private func showRequestedPage() {
        if let requested = model.requestedSettingsPage {
            page = requested
            model.requestedSettingsPage = nil
        }
    }
}

private struct SecuritySettings: View {
    @Environment(AppModel.self) private var model
    @ViewState private var askPassword = false
    @ViewState private var askDisable = false
    @ViewState private var askKit = false
    @ViewState private var showingKit = false

    var body: some View {
        @Bindable var model = model
        VStack(alignment: .leading, spacing: KV.Space.s5) {
            SettingsSection(
                title: tr("自动锁定"),
                footer: tr("睡眠、锁定屏幕、启动屏幕保护程序或切换用户时会立即锁定。")
            ) {
                SettingsRow(title: tr("闲置后锁定"), detail: tr("这台 Mac 在这段时间内没有任何键盘、鼠标或触控板操作时锁定。")) {
                    Picker(tr("闲置后锁定"), selection: $model.autoLockMinutes) {
                        ForEach(AppModel.autoLockChoices, id: \.self) { minutes in
                            Text(minutes < 60 ? tr("{} 分钟", "\(minutes)") : tr("1 小时")).tag(minutes)
                        }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .fixedSize()
                }
            }
            SettingsSection(
                title: tr("解锁"),
                footer: tr("以下情况必须输入主密码：Mac 重启后的首次解锁、超过上面的天数、Touch ID 连续 3 次未能识别、指纹有变化。这样你不会忘记主密码。")
            ) {
                SettingsRow(title: tr("使用 Touch ID 解锁"), detail: touchIDDetail) {
                    Toggle(tr("使用 Touch ID 解锁"), isOn: Binding(
                        get: { model.touchIDEnabled },
                        set: { on in
                            if on { askPassword = true } else { askDisable = true }
                        }
                    ))
                    .kvSwitch(tr("使用 Touch ID 解锁"))
                    // 启用与关闭都需要在已解锁时验证身份
                    .disabled(model.phase != .unlocked || (!model.touchIDEnabled && !model.touchIDAvailable))
                }
                CardRowDivider()
                SettingsRow(title: tr("定期输入主密码"), detail: tr("每 {} 天至少输入一次", "\(model.passwordIntervalDays)")) {
                    Stepper(
                        tr("每 {} 天至少输入一次主密码", "\(model.passwordIntervalDays)"),
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
                title: tr("应急包"),
                footer: tr("在新设备上登录、或从备份恢复时，需要主密码和应急包中的账户密钥。")
            ) {
                SettingsRow(title: tr("重新保存应急包"), detail: tr("先确认是你本人，然后可以保存 PDF 或打印。")) {
                    Button(tr("保存应急包…")) { askKit = true }
                        .buttonStyle(.kvBordered)
                        .disabled(model.phase != .unlocked)
                }
            }
            SettingsSection(
                title: tr("隐私"),
                footer: tr("并非所有截屏方式都遵守这一设置，它不能防范这台 Mac 上的恶意软件。")
            ) {
                SettingsRow(
                    title: tr("不允许截屏或屏幕共享 Keevo 的窗口"),
                    detail: tr("遵守 macOS 窗口共享设置的截屏、录屏与屏幕共享软件看不到 Keevo，避免共享屏幕时意外露出密码。")
                ) {
                    Toggle(tr("不允许截屏或屏幕共享"), isOn: $model.hideFromScreenCapture)
                        .kvSwitch(tr("不允许截屏或屏幕共享 Keevo 的窗口"))
                }
            }
        }
        .sheet(isPresented: $askPassword) {
            ConfirmPasswordSheet()
        }
        .sheet(isPresented: $askDisable) {
            DisableTouchIDSheet()
        }
        .sheet(isPresented: $askKit) {
            ReverifySheet(title: tr("保存应急包"), message: tr("请先确认是你本人。应急包中有账户密钥。"), confirmTitle: tr("继续")) { password in
                let ok = await model.revealEmergencyKit(password: password)
                if ok { DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { showingKit = true } }
                return ok
            }
        }
        .sheet(isPresented: $showingKit) {
            EmergencyKitSheet()
        }
    }

    private var touchIDDetail: String? {
        if !model.touchIDAvailable { return tr("这台 Mac 没有可用的 Touch ID，或还没有登记指纹。") }
        if model.phase != .unlocked { return tr("解锁 Keevo 之后才能更改。") }
        return nil
    }
}

/// 启用 Touch ID 前确认主密码（spec/crypto.md §8.7"启用 Touch ID"）。
private struct ConfirmPasswordSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @ViewState private var password = ""

    var body: some View {
        SheetScaffold(title: tr("启用 Touch ID"), subtitle: tr("请输入主密码以确认。"), systemImage: "touchid", width: 420) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                LabeledInput(label: tr("主密码")) {
                    SecureField("", text: $password).onSubmit(enable)
                }
                ErrorText()
            }
        } footer: {
            Button(tr("取消")) { dismiss() }
                .buttonStyle(.kvSecondary)
                .keyboardShortcut(.cancelAction)
            Button(tr("启用"), action: enable)
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
            title: tr("关闭 Touch ID"),
            message: tr("请先确认是你本人。关闭后，解锁时需要输入主密码。"),
            confirmTitle: tr("关闭 Touch ID")
        ) { password in
            await model.disableTouchID(password: password)
        }
    }
}
