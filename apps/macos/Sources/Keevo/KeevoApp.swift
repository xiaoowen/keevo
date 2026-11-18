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
        switch model.phase {
        case .onboarding: OnboardingView()
        case .unavailable: EnclaveUnavailableView()
        case .locked: LockView()
        case .unlocked: MainView()
        }
    }
}

extension View {
    /// 全局使用 Keevo 品牌色作为强调色。
    var tinted: some View {
        self.tint(KV.Colors.accentFill)
    }
}
