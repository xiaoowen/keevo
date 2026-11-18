// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 设置窗口（⌘,）。M1.1 只有"安全"一页：Touch ID。

import SwiftUI

struct SettingsView: View {
    var body: some View {
        TabView {
            SecuritySettings()
                .tabItem { Label("安全", systemImage: "lock.shield") }
        }
        .frame(width: 480)
    }
}

private struct SecuritySettings: View {
    @Environment(AppModel.self) private var model
    @ViewState private var askPassword = false

    var body: some View {
        Form {
            Section("解锁") {
                Toggle("使用 Touch ID 解锁", isOn: Binding(
                    get: { model.touchIDEnabled },
                    set: { on in
                        if on { askPassword = true } else { model.disableTouchID() }
                    }
                ))
                .disabled(!model.touchIDEnabled && (!model.touchIDAvailable || model.phase != .unlocked))
                if !model.touchIDAvailable {
                    Text("这台 Mac 没有可用的 Touch ID，或还没有登记指纹。")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } else if model.phase != .unlocked && !model.touchIDEnabled {
                    Text("解锁 Keevo 之后才能启用。")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Text("指纹有变化时 Touch ID 会自动失效，需要输入一次主密码。主密码仍然是唯一能在任何情况下解锁的方式。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .padding()
        .sheet(isPresented: $askPassword) {
            ConfirmPasswordSheet()
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
