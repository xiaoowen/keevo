// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 设置窗口（⌘,）。M1.1 只有"安全"一页：自动锁定、Touch ID、必须输入主密码的间隔。

import SwiftUI

struct SettingsView: View {
    var body: some View {
        TabView {
            SecuritySettings()
                .tabItem { Label("安全", systemImage: "lock.shield") }
            BrowserSettings()
                .tabItem { Label("浏览器", systemImage: "puzzlepiece.extension") }
        }
        .frame(width: 480)
    }
}

private struct SecuritySettings: View {
    @Environment(AppModel.self) private var model
    @ViewState private var askPassword = false
    @ViewState private var askDisable = false

    var body: some View {
        @Bindable var model = model
        Form {
            Section("自动锁定") {
                Picker("闲置后锁定", selection: $model.autoLockMinutes) {
                    ForEach(AppModel.autoLockChoices, id: \.self) { minutes in
                        Text(minutes < 60 ? "\(minutes) 分钟" : "1 小时").tag(minutes)
                    }
                }
                Text("这台 Mac 在这段时间内没有任何键盘、鼠标或触控板操作时锁定。睡眠、锁定屏幕、启动屏幕保护程序或切换用户时会立即锁定。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Section("隐私") {
                Toggle("不允许截屏或屏幕共享 Keevo 的窗口", isOn: $model.hideFromScreenCapture)
                Text("开启后，遵守 macOS 窗口共享设置的截屏、录屏与屏幕共享软件看不到 Keevo 的窗口，可以避免在共享屏幕时意外露出密码。并非所有截屏方式都遵守这一设置，它不能防范这台 Mac 上的恶意软件。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Section("解锁") {
                Toggle("使用 Touch ID 解锁", isOn: Binding(
                    get: { model.touchIDEnabled },
                    set: { on in
                        if on { askPassword = true } else { askDisable = true }
                    }
                ))
                // 启用与关闭都需要在已解锁时验证身份
                .disabled(model.phase != .unlocked || (!model.touchIDEnabled && !model.touchIDAvailable))
                if !model.touchIDAvailable {
                    Text("这台 Mac 没有可用的 Touch ID，或还没有登记指纹。")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } else if model.phase != .unlocked {
                    Text("解锁 Keevo 之后才能更改。")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Stepper(
                    "每 \(model.passwordIntervalDays) 天至少输入一次主密码",
                    value: Binding(
                        get: { Int(model.passwordIntervalDays) },
                        set: { model.setPasswordInterval(days: UInt8(clamping: $0)) }
                    ),
                    in: 1...30
                )
                .disabled(model.phase != .unlocked)
                Text("以下情况必须输入主密码：Mac 重启后的首次解锁、超过上面的天数、Touch ID 连续 3 次未能识别、指纹有变化。这样你不会忘记主密码。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .padding()
        .sheet(isPresented: $askPassword) {
            ConfirmPasswordSheet()
        }
        .sheet(isPresented: $askDisable) {
            DisableTouchIDSheet()
        }
    }
}

/// 启用 Touch ID 前确认主密码（spec/crypto.md §8.7"启用 Touch ID"）。
private struct ConfirmPasswordSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @ViewState private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("启用 Touch ID").font(.title3.weight(.semibold))
            Text("请输入主密码以确认。").foregroundStyle(.secondary)
            SecureField("主密码", text: $password)
                .frame(width: 320)
            ErrorText()
            HStack {
                Spacer()
                Button("取消") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("启用") {
                    Task {
                        if await model.enableTouchID(password: password) { dismiss() }
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty || model.busy)
            }
        }
        .padding(24)
    }
}

/// 关闭 Touch ID 前重新验证：Touch ID 或主密码（docs/ux.md §5"重新验证"）。
private struct DisableTouchIDSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @ViewState private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("关闭 Touch ID").font(.title3.weight(.semibold))
            Text("请先确认是你本人。关闭后，解锁时需要输入主密码。").foregroundStyle(.secondary)
            if model.touchIDUsable {
                Button {
                    Task { if await model.disableTouchID(password: nil) { dismiss() } }
                } label: {
                    Label("用 Touch ID 确认", systemImage: "touchid")
                }
                .disabled(model.busy)
                Text("或者输入主密码：").font(.callout).foregroundStyle(.secondary)
            }
            SecureField("主密码", text: $password)
                .frame(width: 320)
            ErrorText()
            HStack {
                Spacer()
                Button("取消") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("关闭 Touch ID") {
                    Task { if await model.disableTouchID(password: password) { dismiss() } }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty || model.busy)
            }
        }
        .padding(24)
    }
}
