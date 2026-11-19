// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）

import AppKit
import SwiftUI

/// 直接引用 `State` 属性包装器。新版 SDK 中 `@State` 会解析为宏，而 Command Line Tools 不带
/// SwiftUIMacros 插件；用别名可以绕开宏，语义与 `@State` 相同。只用 Command Line Tools 也能构建，是有意保留的。
typealias ViewState<Value> = SwiftUI.State<Value>

@main
struct KeevoApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @ViewState private var model = AppModel()

    var body: some Scene {
        WindowGroup("Keevo") {
            RootView().tinted
                .environment(model)
                .frame(minWidth: 860, minHeight: 540)
        }
        .commands {
            CommandGroup(after: .appInfo) {
                Button("立即锁定") { model.lock() }
                    .keyboardShortcut("l", modifiers: [.command, .shift])
            }
        }
        Settings {
            SettingsView().tinted
                .environment(model)
        }
    }
}

/// SwiftPM 构建的可执行文件默认没有 Dock 图标，也不会成为前台应用。
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        Group {
            switch model.phase {
            case .onboarding: OnboardingView()
            case .unavailable: EnclaveUnavailableView()
            case .locked: LockView()
            case .unlocked: MainView()
            }
        }
        // 浏览器配对：每次尝试都对用户可见；确认界面只出现在 Keevo.app 中（spec/ipc.md §4.2、§5.2）
        .overlay(alignment: .top) {
            VStack(spacing: KV.Space.s2) {
                if let browser = model.pairingNotice {
                    Banner(kind: .info, message: "\(browserName(browser)) 中的扩展正在请求与 Keevo 配对……")
                        .task {
                            try? await Task.sleep(for: .seconds(60))
                            model.pairingNotice = nil
                        }
                }
                // 查询过于频繁（spec/ipc.md §5.2）：可能有人在冒用配对枚举账户，用户关闭前一直显示
                if let warning = model.browserWarning {
                    HStack(alignment: .top) {
                        Banner(kind: .warning, message: warning)
                        Button {
                            model.browserWarning = nil
                        } label: {
                            Image(systemName: "xmark.circle.fill").foregroundStyle(KV.Colors.fgTertiary)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("关闭提示")
                    }
                }
                // 浏览器保存了新登录（spec/ipc.md §5.5）：每次写入都对用户可见
                if let notice = model.browserNotice {
                    Banner(kind: .success, message: notice)
                        .task(id: notice) {
                            try? await Task.sleep(for: .seconds(8))
                            model.browserNotice = nil
                        }
                }
            }
            .frame(maxWidth: 440)
            .padding(.top, KV.Space.s3)
        }
        .sheet(item: $model.browserDialog) { item in
            switch item {
            case .pairing(let request): PairingConfirmSheet(request: request).interactiveDismissDisabled()
            case .fill(let request): FillAuthorizationSheet(request: request).interactiveDismissDisabled()
            case .update(let request): UpdateConfirmationSheet(request: request).interactiveDismissDisabled()
            }
        }
        // 频率限制触发的暂停（spec/ipc.md §5.2 第 3 条）：用户确认后才恢复
        .alert(
            "已暂停「\(model.pausedPairing?.name ?? "")」的填充",
            isPresented: Binding(get: { model.pausedPairing != nil }, set: { if !$0 { model.pausedPairing = nil } }),
            presenting: model.pausedPairing
        ) { paused in
            Button("保持暂停", role: .cancel) { model.pausedPairing = nil }
            Button("恢复") { model.resumeBrowserPairing(id: paused.id) }
        } message: { paused in
            Text("\(browserName(paused.browser)) 中的这个扩展在 10 分钟内为太多不同的条目取用了凭据，可能已被冒用。确认是你本人在操作后再恢复；也可以在「设置 → 浏览器」中解除配对。")
        }
    }
}

extension View {
    /// 全局使用 Keevo 品牌色作为强调色。
    var tinted: some View {
        self.tint(KV.Colors.accentFill)
    }
}
