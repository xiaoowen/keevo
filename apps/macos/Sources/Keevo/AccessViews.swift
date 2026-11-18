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

            Banner(kind: .warning, message: "忘记主密码且丢失应急包时，数据将无法恢复。")
                .frame(maxWidth: 440)

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
                // 账户密钥平时取自本机的 Secure Enclave 包裹；只有本机没有可用的包裹时才询问
                if model.needsSecretKey {
                    TextField("账户密钥（K1-…，见应急包）", text: $secretKey)
                        .font(.body.monospaced())
                }
            }
            .formStyle(.grouped)
            .frame(width: 420)
            HStack {
                Button("解锁") {
                    Task { await model.unlock(password: password, secretKey: secretKey) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty || (model.needsSecretKey && secretKey.isEmpty) || model.busy)
                if model.touchIDEnabled {
                    Button {
                        Task { await model.unlockWithTouchID() }
                    } label: {
                        Label("使用 Touch ID", systemImage: "touchid")
                    }
                    .disabled(model.busy)
                }
                if model.busy { ProgressView().controlSize(.small) }
            }
            ErrorText()
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onChange(of: model.phase) { password = ""; secretKey = "" }
    }
}

/// Secure Enclave 暂时不可用，无法打开数据库（spec/crypto.md §8.7"暂时不可用也不是失败"）。
struct EnclaveUnavailableView: View {
    @Environment(AppModel.self) private var model
    @ViewState private var confirmReenroll = false

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "exclamationmark.lock")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
            Text("暂时无法打开 Keevo").font(.title2.weight(.semibold))
            Text("这台 Mac 的 Secure Enclave 暂时不可用，Keevo 没有做任何改动。请确认屏幕已解锁，然后重试。")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 440)
            HStack {
                Button("重试") { model.open(reenrolling: false) }
                    .keyboardShortcut(.defaultAction)
                Button("重新登记这台 Mac…") { confirmReenroll = true }
            }
            ErrorText()
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .confirmationDialog("重新登记这台 Mac？", isPresented: $confirmReenroll) {
            Button("重新登记") { model.open(reenrolling: true) }
            Button("取消", role: .cancel) {}
        } message: {
            Text("Keevo 会丢弃这台 Mac 上保存的账户密钥与 Touch ID 设置。保险库中的数据不受影响，但下次解锁需要从应急包输入账户密钥。")
        }
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
            // 数字与字母分色，便于抄写（docs/ux.md §5）
            classifiedText(secretKey, font: KV.Typography.monoLarge)
                .textSelection(.enabled)
                .padding(KV.Space.s3)
                .frame(maxWidth: .infinity)
                .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: KV.Radius.md))
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
            Banner(kind: .danger, message: message).frame(maxWidth: 440)
        }
    }
}
