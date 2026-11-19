// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 首次使用与解锁界面（docs/ux.md §3.1–§3.2，设计稿"macOS · 锁屏"）。

import KeevoKit
import SwiftUI

/// 锁屏（设计稿）：图标、标题、需要主密码的原因、主密码、解锁按钮，"或"之后是 Touch ID。
struct LockView: View {
    @Environment(AppModel.self) private var model
    @ViewState private var password = ""
    @ViewState private var secretKey = ""
    @FocusState private var focus: Field?

    private enum Field { case password, secretKey }

    private var canUnlock: Bool {
        !password.isEmpty && !(model.needsSecretKey && secretKey.isEmpty) && !model.busy
    }

    var body: some View {
        @Bindable var model = model
        VStack(spacing: KV.Space.s4) {
            HeroIcon(systemImage: "lock")
            Text("Keevo 已锁定")
                .font(KV.Typography.largeTitle)
                .foregroundStyle(KV.Colors.fgPrimary)
            if let notice = model.lockNotice {
                Banner(kind: .success, message: notice)
            }
            // 命令行工具或 SSH 正在等待解锁（spec/cli.md §4.1、spec/ssh-agent.md §6）
            if let waiter = model.unlockWaiter {
                Banner(kind: .info, message: waiter.text)
            }
            // 说明为什么这次需要主密码，避免用户困惑（docs/ux.md §3.2）
            if let reason = model.passwordReasonText {
                Banner(kind: .info, message: reason)
            }
            VStack(spacing: KV.Space.s3) {
                LabeledInput(label: "主密码", focused: focus == .password) {
                    SecureField("", text: $password)
                        .focused($focus, equals: .password)
                        .onSubmit { unlock() }
                }
                // 账户密钥平时取自本机的 Secure Enclave 包裹；只有本机没有可用的包裹时才询问
                if model.needsSecretKey {
                    LabeledInput(label: "账户密钥", hint: "见应急包，以 K1- 开头", focused: focus == .secretKey) {
                        TextField("K1-", text: $secretKey)
                            .font(KV.Typography.mono)
                            .focused($focus, equals: .secretKey)
                            .onSubmit { unlock() }
                    }
                }
                Button { unlock() } label: {
                    HStack(spacing: KV.Space.s2) {
                        if model.busy { ProgressView().controlSize(.small).tint(.white) }
                        Text("解锁")
                    }
                }
                .buttonStyle(KVButtonStyle(kind: .primary, fullWidth: true))
                .keyboardShortcut(.defaultAction)
                .disabled(!canUnlock)
                if model.touchIDEnabled {
                    TextDivider(text: "或").padding(.vertical, KV.Space.s1)
                    Button {
                        Task { await model.unlockWithTouchID() }
                    } label: {
                        Label(
                            model.touchIDUsable ? "使用 Touch ID" : "使用 Touch ID（输入一次主密码后可用）",
                            systemImage: "touchid"
                        )
                    }
                    .buttonStyle(KVButtonStyle(kind: .secondary, fullWidth: true))
                    .disabled(!model.touchIDUsable || model.busy)
                }
            }
            .frame(width: 360)
            ErrorText()
            Text(autoLockText)
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
                .padding(.top, KV.Space.s2)
        }
        .frame(maxWidth: 400)
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(KV.Colors.bgCanvas)
        .onAppear { focus = .password }
        .onChange(of: model.phase) { password = ""; secretKey = "" }
        .sheet(item: $model.pendingKdf) { info in
            KdfConfirmSheet(info: info) {
                Task { await model.unlockConfirmingKdf(password: password, secretKey: secretKey, confirmed: info) }
            }
        }
    }

    private var autoLockText: String {
        let minutes = model.autoLockMinutes
        let idle = minutes < 60 ? "闲置 \(minutes) 分钟" : "闲置 1 小时"
        return "自动锁定：\(idle)、睡眠或锁屏时"
    }

    private func unlock() {
        guard canUnlock else { return }
        Task { await model.unlock(password: password, secretKey: secretKey) }
    }
}

extension KdfInfo: Identifiable {
    public var id: String { "\(memoryKib)-\(iterations)-\(parallelism)" }
}

/// 解锁参数异常地高：说明可能的原因，由用户决定是否继续（spec/crypto.md §5.3）。
struct KdfConfirmSheet: View {
    @Environment(\.dismiss) private var dismiss
    let info: KdfInfo
    let confirm: () -> Void

    var body: some View {
        SheetScaffold(
            title: "解锁参数异常",
            subtitle: "这个保险库要求的密钥派生强度远高于 Keevo 的默认值。",
            systemImage: "exclamationmark.triangle.fill",
            tint: KV.Colors.statusWarningFg,
            width: 460
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                Text("这可能是你在别的设备上特意调高的，也可能是数据被人改过，目的是让解锁耗尽这台 Mac 的内存或时间。")
                    .font(KV.Typography.body)
                    .fixedSize(horizontal: false, vertical: true)
                KVCard {
                    CardRow(label: "内存") { Text("\(info.memoryKib / 1024) MiB").font(KV.Typography.mono) } actions: {}
                    CardRowDivider()
                    CardRow(label: "迭代次数") { Text("\(info.iterations)").font(KV.Typography.mono) } actions: {}
                    CardRowDivider()
                    CardRow(label: "并行度") { Text("\(info.parallelism)").font(KV.Typography.mono) } actions: {}
                }
                Text("如果你不确定，请选择取消。继续解锁可能需要较长时间。")
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
            }
        } footer: {
            // 安全的选择（取消）是默认按钮；有风险的选择不加强调
            Button("仍然解锁") { dismiss(); confirm() }
                .buttonStyle(.kvSecondary)
            Button("取消") { dismiss() }
                .buttonStyle(.kvPrimary)
                .keyboardShortcut(.defaultAction)
        }
    }
}

/// Secure Enclave 暂时不可用，无法打开数据库（spec/crypto.md §8.7"暂时不可用也不是失败"）。
struct EnclaveUnavailableView: View {
    @Environment(AppModel.self) private var model
    @ViewState private var confirmReenroll = false

    var body: some View {
        VStack(spacing: KV.Space.s4) {
            HeroIcon(systemImage: "exclamationmark.lock", tint: KV.Colors.statusWarningFg, background: KV.Colors.statusWarningBg)
            Text("暂时无法打开 Keevo")
                .font(KV.Typography.largeTitle)
                .foregroundStyle(KV.Colors.fgPrimary)
            Text("这台 Mac 的 Secure Enclave 暂时不可用，Keevo 没有做任何改动。请确认屏幕已解锁，然后重试。")
                .font(KV.Typography.body)
                .foregroundStyle(KV.Colors.fgSecondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 400)
            VStack(spacing: KV.Space.s2) {
                Button("重试") { model.open(reenrolling: false) }
                    .buttonStyle(KVButtonStyle(kind: .primary, fullWidth: true))
                    .keyboardShortcut(.defaultAction)
                Button("重新登记这台 Mac…") { confirmReenroll = true }
                    .buttonStyle(KVButtonStyle(kind: .secondary, fullWidth: true))
            }
            .frame(width: 360)
            ErrorText()
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(KV.Colors.bgCanvas)
        .confirmationDialog("重新登记这台 Mac？", isPresented: $confirmReenroll) {
            Button("重新登记") { model.open(reenrolling: true) }
            Button("取消", role: .cancel) {}
        } message: {
            Text("Keevo 会丢弃这台 Mac 上保存的账户密钥与 Touch ID 设置。保险库中的数据不受影响，但下次解锁需要从应急包输入账户密钥。")
        }
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
