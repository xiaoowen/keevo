// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）

import AppKit
import SwiftUI

/// 直接引用 `State` 属性包装器。新版 SDK 中 `@State` 会解析为宏，而 Command Line Tools 不带
/// SwiftUIMacros 插件；用别名可以绕开宏，语义与 `@State` 相同。只用 Command Line Tools 也能构建，是有意保留的。
typealias ViewState<Value> = SwiftUI.State<Value>

/// 应用。入口在 `Sources/Keevo/main.swift`：界面代码放在 KeevoUI 库中，调试用的截图程序
/// （`keevo-snapshots`）也能用同一份代码渲染各个页面。
public struct KeevoApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @ViewState private var model = AppModel()

    public init() {}

    public var body: some Scene {
        WindowGroup("Keevo", id: "main") {
            RootView().tinted
                .frame(minWidth: 960, minHeight: 600)
                .background(MainWindowOpener())
                // 放在最后：环境只传给它修饰的视图，之后再加的背景视图拿不到模型（启动即崩溃）
                .environment(model)
        }
        // 设计稿：没有标题栏与工具栏，各栏自己的顶部区域放搜索与操作
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1200, height: 760)
        .commands {
            CommandGroup(after: .appInfo) {
                Button(tr("立即锁定")) { model.lock() }
                    .keyboardShortcut("l", modifiers: [.command, .shift])
            }
            // ⌘Q 退到后台，不结束进程：浏览器扩展、命令行工具、SSH Agent 与快速访问都要 Keevo 在运行。
            // 真正退出用 ⌥⌘Q，或菜单栏、程序坞中的"退出"
            CommandGroup(replacing: .appTermination) {
                Button(tr("退到后台")) { AppDelegate.moveToBackground() }
                    .keyboardShortcut("q")
                Button(tr("退出 Keevo")) { NSApp.terminate(nil) }
                    .keyboardShortcut("q", modifiers: [.command, .option])
            }
            CommandGroup(replacing: .newItem) {
                let unlocked = model.phase == .unlocked && !model.vaults.isEmpty
                Button(tr("新建登录")) { model.mainRequest = .newItem(NewItemChoice.all[0]) }
                    .keyboardShortcut("n")
                    .disabled(!unlocked)
                Menu(tr("新建")) {
                    ForEach(NewItemChoice.all.dropFirst()) { choice in
                        Button(choice.name) { model.mainRequest = .newItem(choice) }
                    }
                }
                .disabled(!unlocked)
                Divider()
                Button(tr("生成密码…")) { model.mainRequest = .generator }
                    .keyboardShortcut("g", modifiers: [.command, .shift])
                    .disabled(model.phase != .unlocked)
            }
            CommandGroup(after: .importExport) {
                Button(tr("导入…")) { model.showingImport = true }
                    .keyboardShortcut("i", modifiers: [.command, .shift])
                    .disabled(model.phase != .unlocked || model.vaults.isEmpty)
                Button(tr("导出…")) { model.showingExport = true }
                    .keyboardShortcut("e", modifiers: [.command, .shift])
                    .disabled(model.phase != .unlocked)
            }
            CommandGroup(after: .textEditing) {
                Button(tr("搜索条目")) { model.mainRequest = .focusSearch }
                    .keyboardShortcut("f")
                    .disabled(model.phase != .unlocked)
            }
        }
        Settings {
            SettingsView().tinted
                .environment(model)
        }
        // 独立的生成器：锁定时也可以使用（菜单栏"生成密码…"）
        Window(tr("生成密码"), id: "generator") {
            GeneratorView().tinted
                .environment(model)
                .frame(width: 460)
        }
        .windowResizability(.contentSize)
        // 菜单栏（设计稿"菜单栏 · 已解锁 / 已锁定"）
        MenuBarExtra(isInserted: Binding(get: { model.menuBarEnabled }, set: { model.menuBarEnabled = $0 })) {
            MenuBarContent().environment(model)
        } label: {
            MenuBarLabel().environment(model)
        }
    }
}

/// 记下"打开主窗口"的动作，供快速访问与菜单栏在主窗口关闭后使用。
private struct MainWindowOpener: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Color.clear.onAppear { model.openMainWindow = { openWindow(id: "main") } }
    }
}

private struct MenuBarLabel: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        // 与应用图标同一图形：已解锁为实心盾形，已锁定为盾形轮廓
        Image(nsImage: BrandMark.menuBarImage(unlocked: model.phase == .unlocked))
            .accessibilityLabel(model.phase == .unlocked ? tr("Keevo 已解锁") : tr("Keevo 已锁定"))
            .onAppear { model.openMainWindow = { openWindow(id: "main") } }
    }
}

private struct MenuBarContent: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let unlocked = model.phase == .unlocked
        if unlocked {
            Text(tr("Keevo 已解锁"))
            Text(tr("闲置 {} 分钟后自动锁定", "\(model.autoLockMinutes)"))
        } else {
            Text(tr("Keevo 已锁定"))
        }
        Divider()
        if !unlocked, model.phase == .locked, model.touchIDUsable {
            Button(tr("用 Touch ID 解锁…")) { Task { await model.unlockWithTouchID() } }
        }
        Button(tr("快速访问…")) { QuickAccessController.shared.show(model: model) }
            .keyboardShortcut(KeyEquivalent(Character(Shortcut.saved.key.lowercased())), modifiers: Shortcut.saved.eventModifiers)
            .disabled(!unlocked)
        Button(tr("生成密码…")) {
            NSApp.activate()
            openWindow(id: "generator")
        }
        Divider()
        Button(tr("打开 Keevo")) { model.showMainWindow() }
        if unlocked {
            Button(tr("立即锁定")) { model.lock() }
        }
        Divider()
        SettingsLink { Text(tr("设置…")) }
            .keyboardShortcut(",")
        Button(tr("退出 Keevo")) { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }
}

/// SwiftPM 构建的可执行文件默认没有 Dock 图标，也不会成为前台应用。
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
        // 退到后台之后，普通窗口再次出现（菜单栏"打开 Keevo"、浏览器的确认界面、再次打开应用、设置、生成器）时
        // 恢复程序坞图标与应用菜单。快速访问是不激活应用的浮窗（NSPanel），不算在内
        NotificationCenter.default.addObserver(forName: NSWindow.didBecomeKeyNotification, object: nil, queue: .main) { note in
            guard let window = note.object as? NSWindow, !(window is NSPanel) else { return }
            MainActor.assumeIsolated { Self.returnToForeground() }
        }
    }

    /// ⌘Q：退到后台。隐藏全部窗口（窗口里的状态保留）；菜单栏中显示 Keevo 时同时隐藏程序坞图标，只留菜单栏图标。
    /// 解锁状态不变，照常按设置的时间自动锁定。
    @MainActor static func moveToBackground() {
        NSApp.hide(nil)
        if UserDefaults.standard.object(forKey: AppModel.menuBarKey) as? Bool ?? true {
            NSApp.setActivationPolicy(.accessory)
        }
    }

    @MainActor private static func returnToForeground() {
        guard NSApp.activationPolicy() != .regular else { return }
        NSApp.setActivationPolicy(.regular)
        // 从 accessory 切回 regular 时，应用菜单要重新激活一次才会出现在屏幕顶部
        DispatchQueue.main.async { NSApp.activate() }
    }

    /// 菜单栏中显示 Keevo 时，关闭窗口后继续运行（快速访问与菜单栏仍可用）。
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        !(UserDefaults.standard.object(forKey: AppModel.menuBarKey) as? Bool ?? true)
    }
}

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        Group {
            switch model.phase {
            case .onboarding: OnboardingFlow()
            case .unlocked where model.onboardingStep != nil: OnboardingFlow()
            case .unavailable: EnclaveUnavailableView()
            case .locked: LockView()
            case .unlocked: MainView()
            }
        }
        // 浏览器配对：每次尝试都对用户可见；确认界面只出现在 Keevo.app 中（spec/ipc.md §4.2、§5.2）
        .overlay(alignment: .top) {
            VStack(spacing: KV.Space.s2) {
                if let browser = model.pairingNotice {
                    Banner(kind: .info, message: tr("{} 中的扩展正在请求与 Keevo 配对……", "\(browserName(browser))"))
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
                        .accessibilityLabel(tr("关闭提示"))
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
        // 复制等操作的短暂提示
        .overlay(alignment: .bottom) {
            if let toast = model.toast {
                ToastView(message: toast)
                    .padding(.bottom, KV.Space.s6)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.easeOut(duration: KV.Motion.base), value: model.toast)
        .sheet(item: $model.browserDialog) { item in
            switch item {
            case .pairing(let request): PairingConfirmSheet(request: request).interactiveDismissDisabled()
            case .fill(let request): FillAuthorizationSheet(request: request).interactiveDismissDisabled()
            case .update(let request): UpdateConfirmationSheet(request: request).interactiveDismissDisabled()
            case .search(let request): SearchAuthorizationSheet(request: request).interactiveDismissDisabled()
            case .cli(let request): CliAuthorizationSheet(request: request).interactiveDismissDisabled()
            case .ssh(let request): SshSignSheet(request: request).interactiveDismissDisabled()
            }
        }
        // 频率限制触发的暂停（spec/ipc.md §5.2 第 3 条）：用户确认后才恢复
        .alert(
            tr("已暂停「{}」的填充", "\(model.pausedPairing?.name ?? "")"),
            isPresented: Binding(get: { model.pausedPairing != nil }, set: { if !$0 { model.pausedPairing = nil } }),
            presenting: model.pausedPairing
        ) { paused in
            Button(tr("保持暂停"), role: .cancel) { model.pausedPairing = nil }
            Button(tr("恢复")) { model.resumeBrowserPairing(id: paused.id) }
        } message: { paused in
            Text(tr("{} 中的这个扩展在 10 分钟内为太多不同的条目取用了凭据，可能已被冒用。确认是你本人在操作后再恢复；也可以在「设置 → 浏览器」中解除配对。", "\(browserName(paused.browser))"))
        }
    }
}

extension View {
    /// 全局使用 Keevo 品牌色作为强调色。
    var tinted: some View {
        self.tint(KV.Colors.accentFill)
    }
}
