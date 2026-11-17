// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 首次使用与解锁界面（docs/ux.md §3.1–§3.2）。

import SwiftUI

struct OnboardingView: View {
    @Environment(AppModel.self) private var model
    @ViewState private var password = ""
    @ViewState private var confirm = ""

    private var canCreate: Bool { password.count >= 10 && password == confirm && !model.busy }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Label("欢迎使用 Keevo", systemImage: "lock.shield")
                .font(.largeTitle.weight(.semibold))
            VStack(alignment: .leading, spacing: 6) {
                Text("你的数据只保存在这台 Mac 上。")
                Text("没有人能读取它，包括我们。")
                Text("Keevo 的代码完全开源，任何人都可以验证。")
            }
            .foregroundStyle(.secondary)

            Form {
                SecureField("主密码（至少 10 个字符）", text: $password)
                SecureField("再输入一次", text: $confirm)
            }
            .formStyle(.grouped)
            .frame(maxWidth: 440)

            Text("忘记主密码且丢失应急包时，数据将无法恢复。")
                .font(.callout)
                .foregroundStyle(.orange)

            HStack {
                Button("创建保险库") {
                    Task { await model.createAccount(password: password) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canCreate)
                if model.busy { ProgressView().controlSize(.small) }
            }
            ErrorText()
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

struct LockView: View {
    @Environment(AppModel.self) private var model
    @ViewState private var password = ""
    @ViewState private var secretKey = ""

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.fill")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
            Text("Keevo 已锁定").font(.title2.weight(.semibold))
            Form {
                SecureField("主密码", text: $password)
                // M0 需要手动输入；M1 从钥匙串读取，并支持 Touch ID
                TextField("账户密钥（K1-…）", text: $secretKey)
                    .font(.body.monospaced())
            }
            .formStyle(.grouped)
            .frame(width: 420)
            HStack {
                Button("解锁") {
                    Task { await model.unlock(password: password, secretKey: secretKey) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty || secretKey.isEmpty || model.busy)
                if model.busy { ProgressView().controlSize(.small) }
            }
            ErrorText()
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onChange(of: model.phase) { password = ""; secretKey = "" }
    }
}

/// 新建账户后展示一次账户密钥，用户确认已保存后才能关闭（docs/ux.md §3.1 第 4 步）。
struct SecretKeySheet: View {
    @Environment(AppModel.self) private var model
    let secretKey: String
    @ViewState private var saved = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("你的账户密钥").font(.title2.weight(.semibold))
            Text("在新设备上登录、或从备份恢复时，需要主密码和这把账户密钥。请把它抄写或打印后离线保存。")
                .foregroundStyle(.secondary)
            Text(secretKey)
                .font(.system(.title3, design: .monospaced).weight(.medium))
                .textSelection(.enabled)
                .padding(12)
                .frame(maxWidth: .infinity)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
            Button("复制") { Clipboard.copy(secretKey) }
            Toggle("我已妥善保存账户密钥", isOn: $saved)
            HStack {
                Spacer()
                Button("继续") { model.pendingSecretKey = nil }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!saved)
            }
        }
        .padding(28)
        .frame(width: 520)
    }
}

struct ErrorText: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if let message = model.errorMessage {
            Text(message).foregroundStyle(.red).font(.callout)
        }
    }
}
