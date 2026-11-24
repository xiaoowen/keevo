// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 首次使用与解锁界面（docs/ux.md §3.1–§3.2，设计稿"锁屏改版"）。

import AppKit
import KeevoKit
import SwiftUI

/// 锁屏（设计稿"锁屏改版"）：Keevo 标志、一个主密码输入框（框内箭头或回车解锁），旁边是 Touch ID。原因、主密码
/// 错误与大写锁定在输入框下方一行说明；本机没有账户密钥时改为两个带标签的输入框与"解锁"按钮。
struct LockView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @ViewState private var password = ""
    @ViewState private var secretKey = ""
    @ViewState private var capsLock = false
    @ViewState private var capsMonitor: Any?
    @ViewState private var showingForgot = false
    @FocusState private var focus: Field?

    private enum Field { case password, secretKey }

    private var canUnlock: Bool {
        !password.isEmpty && !(model.needsSecretKey && secretKey.isEmpty) && !model.busy
    }

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 0) {
            Spacer(minLength: KV.Space.s6)
            VStack(spacing: 14) {
                notices
                BrandLogo(size: model.needsSecretKey ? 56 : 64)
                Text(tr("Keevo 已锁定"))
                    .font(.system(size: 22, weight: .bold))
                    .foregroundStyle(KV.Colors.fgPrimary)
                    .padding(.top, 4)
                    .padding(.bottom, model.needsSecretKey ? 0 : 8)
                if model.needsSecretKey {
                    secretKeyForm
                } else {
                    passwordForm
                }
                ErrorText()
            }
            .frame(maxWidth: 440)
            Spacer(minLength: KV.Space.s6)
            footer
        }
        .padding(.horizontal, 40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(KV.Colors.bgSurface)
        .onAppear {
            focus = .password
            startWatchingCapsLock()
        }
        .onDisappear { stopWatchingCapsLock() }
        .onChange(of: model.phase) { password = ""; secretKey = "" }
        .onChange(of: password) { model.wrongCredentials = false }
        .onChange(of: secretKey) { model.wrongCredentials = false }
        .onChange(of: model.needsSecretKey) { _, needed in if needed { focus = .secretKey } }
        .onChange(of: model.failedUnlocks) { selectPasswordAfterFailure() }
        .sheet(item: $model.pendingKdf) { info in
            KdfConfirmSheet(info: info) {
                Task { await model.unlockConfirmingKdf(password: password, secretKey: secretKey, confirmed: info) }
            }
        }
    }

    /// 标志上方的胶囊："已恢复备份"、谁在等待解锁（spec/cli.md §4.1、spec/ssh-agent.md §6）。
    @ViewBuilder
    private var notices: some View {
        if let notice = model.lockNotice {
            NoticePill(text: notice, systemImage: "checkmark.circle", tint: KV.Colors.statusSuccessFg, background: KV.Colors.statusSuccessBg)
        }
        if let waiter = model.unlockWaiter {
            NoticePill(text: waiter.text, systemImage: waiter.systemImage, tint: KV.Colors.statusInfoFg, background: KV.Colors.statusInfoBg)
        }
    }

    /// 平时：一个输入框，框内的箭头解锁；Touch ID 可以使用时旁边是 Touch ID 按钮。
    private var passwordForm: some View {
        VStack(alignment: .leading, spacing: KV.Space.s2) {
            HStack(spacing: KV.Space.s2) {
                ZStack(alignment: .trailing) {
                    SecureField(tr("输入主密码"), text: $password)
                        .textFieldStyle(.plain)
                        .font(.system(size: 15))
                        .focused($focus, equals: .password)
                        .onSubmit { unlock() }
                        .disabled(model.busy)
                        .padding(.leading, KV.Space.s3)
                        .padding(.trailing, 44)
                        .frame(height: 40)
                        .background(KV.Colors.bgCanvas, in: RoundedRectangle(cornerRadius: KV.Radius.md, style: .continuous))
                        .overlay(
                            RoundedRectangle(cornerRadius: KV.Radius.md, style: .continuous)
                                .strokeBorder(fieldBorder, lineWidth: focus == .password || model.wrongCredentials ? 2 : 1)
                        )
                        .accessibilityLabel(tr("主密码"))
                    UnlockArrowButton(enabled: canUnlock, busy: model.busy) { unlock() }
                        .padding(.trailing, 6)
                }
                .modifier(Shake(amount: reduceMotion ? 0 : 6, trigger: CGFloat(model.failedUnlocks)))
                .animation(.linear(duration: 0.4), value: model.failedUnlocks)
                if model.touchIDUsable {
                    TouchIDButton(disabled: model.busy) { Task { await model.unlockWithTouchID() } }
                }
            }
            messages
        }
        .frame(width: 330)
    }

    /// 本机没有可用的账户密钥（例如从别处恢复的数据）：两个带标签的输入框与"解锁"按钮。
    private var secretKeyForm: some View {
        VStack(spacing: 10) {
            Text(tr("这台 Mac 上没有可用的账户密钥，请从应急包输入一次，之后只需主密码。"))
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.bottom, 4)
            LabeledInput(label: tr("主密码"), focused: focus == .password) {
                SecureField("", text: $password)
                    .focused($focus, equals: .password)
                    .onSubmit { unlock() }
                    .disabled(model.busy)
            }
            LabeledInput(label: tr("账户密钥"), hint: tr("见应急包，以 K1- 开头"), focused: focus == .secretKey) {
                TextField("K1-", text: $secretKey)
                    .font(KV.Typography.mono)
                    .focused($focus, equals: .secretKey)
                    .onSubmit { unlock() }
                    .disabled(model.busy)
            }
            Button { unlock() } label: {
                HStack(spacing: KV.Space.s2) {
                    if model.busy { ProgressView().controlSize(.small).tint(.white) }
                    Text(model.busy ? tr("正在解锁…") : tr("解锁"))
                }
            }
            .buttonStyle(KVButtonStyle(kind: .primary, fullWidth: true))
            .keyboardShortcut(.defaultAction)
            .disabled(!canUnlock)
            .padding(.top, 2)
            messages
        }
        .frame(width: 330)
    }

    /// 输入框下方的说明：主密码错误、大写锁定、为什么这次需要主密码（docs/ux.md §3.2"锁屏要说明原因"）。
    @ViewBuilder
    private var messages: some View {
        VStack(alignment: .leading, spacing: 4) {
            if model.wrongCredentials {
                InlineNote(
                    text: model.needsSecretKey ? tr("主密码或账户密钥不正确。") : tr("主密码不正确。"),
                    systemImage: "exclamationmark.circle", color: KV.Colors.statusDangerFg
                )
            }
            if capsLock && focus != nil {
                InlineNote(text: tr("大写锁定已打开。"), systemImage: "capslock.fill", color: KV.Colors.statusWarningFg)
            }
            if !model.needsSecretKey, let reason = model.passwordReasonText {
                InlineNote(text: reason, systemImage: "info.circle", color: KV.Colors.fgSecondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .frame(minHeight: 18, alignment: .top)
    }

    private var footer: some View {
        HStack(spacing: 4) {
            Text(autoLockText)
            Text("·").accessibilityHidden(true)
            Button(tr("忘记主密码？")) { showingForgot = true }
                .buttonStyle(.kvLink)
                .popover(isPresented: $showingForgot, arrowEdge: .top) { ForgotPasswordPopover() }
        }
        .font(KV.Typography.footnote)
        .foregroundStyle(KV.Colors.fgSecondary)
        .padding(.bottom, KV.Space.s4)
    }

    private var fieldBorder: Color {
        if model.wrongCredentials { return KV.Colors.statusDangerFg }
        return focus == .password ? KV.Colors.focusRing : KV.Colors.borderControl
    }

    private var autoLockText: String {
        let minutes = model.autoLockMinutes
        let idle = minutes < 60 ? tr("闲置 {} 分钟", "\(minutes)") : tr("闲置 1 小时")
        return tr("自动锁定：{}、睡眠或锁屏时", "\(idle)")
    }

    private func unlock() {
        guard canUnlock else { return }
        Task { await model.unlock(password: password, secretKey: secretKey) }
    }

    /// 主密码错误后：焦点回到主密码，全选其内容，直接输入即可替换。
    private func selectPasswordAfterFailure() {
        guard model.wrongCredentials else { return }
        focus = .password
        DispatchQueue.main.async { NSApp.sendAction(#selector(NSText.selectAll(_:)), to: nil, from: nil) }
    }

    private func startWatchingCapsLock() {
        capsLock = NSEvent.modifierFlags.contains(.capsLock)
        guard capsMonitor == nil else { return }
        capsMonitor = NSEvent.addLocalMonitorForEvents(matching: .flagsChanged) { event in
            capsLock = event.modifierFlags.contains(.capsLock)
            return event
        }
    }

    private func stopWatchingCapsLock() {
        if let capsMonitor { NSEvent.removeMonitor(capsMonitor) }
        capsMonitor = nil
    }
}

/// 输入框内的圆形箭头：没有内容时为灰色、不可点；正在解锁时换成转圈。
private struct UnlockArrowButton: View {
    let enabled: Bool
    let busy: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            ZStack {
                Circle().fill(enabled || busy ? KV.Colors.accentFill : KV.Colors.borderSubtle)
                if busy {
                    ProgressView().controlSize(.small).tint(.white).scaleEffect(0.7)
                } else {
                    Image(systemName: "arrow.right")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundStyle(enabled ? KV.Colors.fgOnAccent : KV.Colors.fgTertiary)
                }
            }
            .frame(width: 28, height: 28)
            .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .help(tr("解锁"))
        .accessibilityLabel(busy ? tr("正在解锁…") : tr("解锁"))
    }
}

/// 输入框旁的 Touch ID 按钮。
private struct TouchIDButton: View {
    let disabled: Bool
    let action: () -> Void
    @ViewState private var hovering = false

    var body: some View {
        Button(action: action) {
            Image(systemName: "touchid")
                .font(.system(size: 20, weight: .regular))
                .foregroundStyle(KV.Colors.accentFg)
                .frame(width: 40, height: 40)
                .background(hovering ? KV.Colors.bgHover : KV.Colors.bgCanvas, in: RoundedRectangle(cornerRadius: KV.Radius.md, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: KV.Radius.md, style: .continuous).strokeBorder(KV.Colors.borderSubtle))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(disabled)
        .onHover { hovering = $0 }
        .help(tr("使用 Touch ID 解锁"))
        .accessibilityLabel(tr("使用 Touch ID 解锁"))
    }
}

/// 输入框下方的一行说明：图标加文字，颜色表示性质（文字本身说明内容，不只靠颜色，docs/ux.md §8）。
private struct InlineNote: View {
    let text: String
    let systemImage: String
    let color: Color

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: systemImage).font(.system(size: 11, weight: .semibold)).accessibilityHidden(true)
            Text(text).fixedSize(horizontal: false, vertical: true)
        }
        .font(KV.Typography.footnote)
        .foregroundStyle(color)
    }
}

/// 锁屏上方的提示胶囊。
private struct NoticePill: View {
    let text: String
    let systemImage: String
    let tint: Color
    let background: Color

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: systemImage).font(.system(size: 11, weight: .semibold)).accessibilityHidden(true)
            Text(text).fixedSize(horizontal: false, vertical: true)
        }
        .font(KV.Typography.footnote)
        .foregroundStyle(tint)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(background, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .padding(.bottom, 4)
    }
}

/// "忘记主密码？"：Keevo 无法重置主密码（docs/ux.md §3.1"忘记主密码且丢失应急包，数据将无法恢复"）。
private struct ForgotPasswordPopover: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(tr("Keevo 无法重置主密码"))
                .font(KV.Typography.bodyStrong)
                .foregroundStyle(KV.Colors.fgPrimary)
            Text(tr("主密码只有你知道，Keevo 和任何人都无法替你找回。如果你把主密码写在了应急包上，请查看应急包。"))
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .frame(width: 320, alignment: .leading)
    }
}

/// 主密码错误时输入框左右抖动一次。`trigger` 每变一次抖一次；`amount` 为 0 时不动（减少动态效果）。
private struct Shake: GeometryEffect {
    var amount: CGFloat
    var trigger: CGFloat

    var animatableData: CGFloat {
        get { trigger }
        set { trigger = newValue }
    }

    func effectValue(size: CGSize) -> ProjectionTransform {
        ProjectionTransform(CGAffineTransform(translationX: amount * sin(trigger * .pi * 6), y: 0))
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
            title: tr("解锁参数异常"),
            subtitle: tr("这个保险库要求的密钥派生强度远高于 Keevo 的默认值。"),
            systemImage: "exclamationmark.triangle.fill",
            tint: KV.Colors.statusWarningFg,
            width: 460
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                Text(tr("这可能是你在别的设备上特意调高的，也可能是数据被人改过，目的是让解锁耗尽这台 Mac 的内存或时间。"))
                    .font(KV.Typography.body)
                    .fixedSize(horizontal: false, vertical: true)
                KVCard {
                    CardRow(label: tr("内存")) { Text("\(info.memoryKib / 1024) MiB").font(KV.Typography.mono) } actions: {}
                    CardRowDivider()
                    CardRow(label: tr("迭代次数")) { Text("\(info.iterations)").font(KV.Typography.mono) } actions: {}
                    CardRowDivider()
                    CardRow(label: tr("并行度")) { Text("\(info.parallelism)").font(KV.Typography.mono) } actions: {}
                }
                Text(tr("如果你不确定，请选择取消。继续解锁可能需要较长时间。"))
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
            }
        } footer: {
            // 安全的选择（取消）是默认按钮；有风险的选择不加强调
            Button(tr("仍然解锁")) { dismiss(); confirm() }
                .buttonStyle(.kvSecondary)
            Button(tr("取消")) { dismiss() }
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
            Text(tr("暂时无法打开 Keevo"))
                .font(KV.Typography.largeTitle)
                .foregroundStyle(KV.Colors.fgPrimary)
            Text(tr("这台 Mac 的 Secure Enclave 暂时不可用，Keevo 没有做任何改动。请确认屏幕已解锁，然后重试。"))
                .font(KV.Typography.body)
                .foregroundStyle(KV.Colors.fgSecondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 400)
            VStack(spacing: KV.Space.s2) {
                Button(tr("重试")) { model.open(reenrolling: false) }
                    .buttonStyle(KVButtonStyle(kind: .primary, fullWidth: true))
                    .keyboardShortcut(.defaultAction)
                Button(tr("重新登记这台 Mac…")) { confirmReenroll = true }
                    .buttonStyle(KVButtonStyle(kind: .secondary, fullWidth: true))
            }
            .frame(width: 360)
            ErrorText()
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(KV.Colors.bgCanvas)
        .confirmationDialog(tr("重新登记这台 Mac？"), isPresented: $confirmReenroll) {
            Button(tr("重新登记")) { model.open(reenrolling: true) }
            Button(tr("取消"), role: .cancel) {}
        } message: {
            Text(tr("Keevo 会丢弃这台 Mac 上保存的账户密钥与 Touch ID 设置。保险库中的数据不受影响，但下次解锁需要从应急包输入账户密钥。"))
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
