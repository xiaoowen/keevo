// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 快速访问（docs/ux.md §3.4，设计稿"macOS · 附件、快速访问、菜单栏与通用设置"）：全局快捷键（默认 ⌥⌘K）
// 唤起的浮动面板，类似 Spotlight。↩ 复制密码、⌘C 复制用户名、⌥↩ 复制验证码、⌘O 在主窗口打开、esc 关闭；
// 锁定时先解锁。面板不激活 Keevo：复制后焦点仍在原来的应用中，可以直接粘贴。
// 全局快捷键用 Carbon 的 RegisterEventHotKey，不需要辅助功能权限，也不监听其他按键。

import AppKit
import Carbon.HIToolbox
import KeevoKit
import SwiftUI

// MARK: - 快捷键

/// 一个快捷键：按键码与 Carbon 修饰键，以及显示用的按键名。
struct Shortcut: Equatable {
    var keyCode: UInt32
    var modifiers: UInt32
    var key: String

    static let `default` = Shortcut(keyCode: UInt32(kVK_ANSI_K), modifiers: UInt32(cmdKey | optionKey), key: "K")

    private static let defaultsKey = "quickAccess.shortcut"

    static var saved: Shortcut {
        get {
            guard let d = UserDefaults.standard.dictionary(forKey: defaultsKey),
                  let code = d["keyCode"] as? Int, let mods = d["modifiers"] as? Int, let key = d["key"] as? String
            else { return .default }
            return Shortcut(keyCode: UInt32(code), modifiers: UInt32(mods), key: key)
        }
        set {
            UserDefaults.standard.set(
                ["keyCode": Int(newValue.keyCode), "modifiers": Int(newValue.modifiers), "key": newValue.key],
                forKey: defaultsKey
            )
        }
    }

    /// 显示用的符号，按 macOS 的顺序：⌃⌥⇧⌘。
    var symbols: [String] {
        var out: [String] = []
        if modifiers & UInt32(controlKey) != 0 { out.append("⌃") }
        if modifiers & UInt32(optionKey) != 0 { out.append("⌥") }
        if modifiers & UInt32(shiftKey) != 0 { out.append("⇧") }
        if modifiers & UInt32(cmdKey) != 0 { out.append("⌘") }
        return out + [key]
    }

    var display: String { symbols.joined() }

    /// SwiftUI 的修饰键（菜单中显示快捷键）。
    var eventModifiers: SwiftUI.EventModifiers {
        var m: SwiftUI.EventModifiers = []
        if modifiers & UInt32(controlKey) != 0 { m.insert(.control) }
        if modifiers & UInt32(optionKey) != 0 { m.insert(.option) }
        if modifiers & UInt32(shiftKey) != 0 { m.insert(.shift) }
        if modifiers & UInt32(cmdKey) != 0 { m.insert(.command) }
        return m
    }

    /// 由按键事件得到快捷键。至少要有 ⌘、⌥ 或 ⌃ 之一，否则返回 `nil`（单独的字母会妨碍正常输入）。
    init?(event: NSEvent) {
        let flags = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
        var mods: UInt32 = 0
        if flags.contains(.command) { mods |= UInt32(cmdKey) }
        if flags.contains(.option) { mods |= UInt32(optionKey) }
        if flags.contains(.control) { mods |= UInt32(controlKey) }
        if flags.contains(.shift) { mods |= UInt32(shiftKey) }
        guard mods & UInt32(cmdKey | optionKey | controlKey) != 0 else { return nil }
        let key = (event.charactersIgnoringModifiers ?? "").uppercased()
        guard !key.isEmpty, !key.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return nil }
        self.init(keyCode: UInt32(event.keyCode), modifiers: mods, key: key)
    }

    init(keyCode: UInt32, modifiers: UInt32, key: String) {
        self.keyCode = keyCode
        self.modifiers = modifiers
        self.key = key
    }
}

/// 全局快捷键（Carbon）。同一时刻只登记一个。
@MainActor
final class GlobalHotKey {
    static let shared = GlobalHotKey()
    private var ref: EventHotKeyRef?
    private var handler: EventHandlerRef?
    var action: (() -> Void)?

    /// 登记；被其他应用占用时返回 `false`。
    @discardableResult
    func register(_ shortcut: Shortcut) -> Bool {
        unregister()
        if handler == nil {
            var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
            InstallEventHandler(GetApplicationEventTarget(), { _, _, _ in
                DispatchQueue.main.async { MainActor.assumeIsolated { GlobalHotKey.shared.action?() } }
                return noErr
            }, 1, &spec, nil, &handler)
        }
        let id = EventHotKeyID(signature: OSType(0x4B45_564F), id: 1) // 'KEVO'
        return RegisterEventHotKey(shortcut.keyCode, shortcut.modifiers, id, GetApplicationEventTarget(), 0, &ref) == noErr
    }

    func unregister() {
        if let ref { UnregisterEventHotKey(ref) }
        ref = nil
    }
}

// MARK: - 面板

/// 无边框、不激活应用、但可以接收键盘输入的面板。
private final class QuickPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}

@MainActor
final class QuickAccessController: NSObject, NSWindowDelegate {
    static let shared = QuickAccessController()
    private var panel: QuickPanel?
    private weak var model: AppModel?
    static let width: CGFloat = 640

    func toggle(model: AppModel) {
        if let panel, panel.isVisible { close() } else { show(model: model) }
    }

    func show(model: AppModel) {
        self.model = model
        let panel = self.panel ?? makePanel(model: model)
        self.panel = panel
        model.quickAccessSession &+= 1
        position(panel, height: 72)
        panel.makeKeyAndOrderFront(nil)
    }

    func close() {
        panel?.orderOut(nil)
    }

    /// 内容高度变化时调整面板，保持顶边不动。
    func resize(height: CGFloat) {
        guard let panel else { return }
        var frame = panel.frame
        let top = frame.maxY
        frame.size.height = height
        frame.origin.y = top - height
        panel.setFrame(frame, display: true)
    }

    private func position(_ panel: NSPanel, height: CGFloat) {
        guard let screen = NSScreen.main ?? NSScreen.screens.first else { return }
        let visible = screen.visibleFrame
        let x = visible.midX - Self.width / 2
        let top = visible.maxY - visible.height * 0.22
        panel.setFrame(NSRect(x: x, y: top - height, width: Self.width, height: height), display: false)
    }

    private func makePanel(model: AppModel) -> QuickPanel {
        let panel = QuickPanel(
            contentRect: NSRect(x: 0, y: 0, width: Self.width, height: 72),
            styleMask: [.nonactivatingPanel, .borderless, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        panel.level = .floating
        panel.isFloatingPanel = true
        panel.hidesOnDeactivate = false
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]
        panel.isReleasedWhenClosed = false
        panel.delegate = self
        // 与主窗口相同：遵守"不允许截屏"设置
        panel.sharingType = model.hideFromScreenCapture ? .none : .readOnly
        panel.contentView = NSHostingView(rootView: QuickAccessView().environment(model).tinted)
        return panel
    }

    func windowDidResignKey(_ notification: Notification) {
        // 点到别处即关闭（与 Spotlight 相同）
        close()
    }
}

// MARK: - 内容

struct QuickAccessView: View {
    @Environment(AppModel.self) private var model
    @ViewState private var query: String
    private let initialQuery: String

    init(initialQuery: String = "") {
        self.initialQuery = initialQuery
        _query = ViewState(initialValue: initialQuery)
    }
    @ViewState private var selection = 0
    @ViewState private var copied: String?
    @FocusState private var focused: Bool

    private var results: [ItemEntry] {
        let live = model.items.filter { !$0.trashed }
        if query.trimmingCharacters(in: .whitespaces).isEmpty {
            return Array(live.filter(\.favorite).prefix(8))
        }
        let ids = model.search(query)
        let byId = Dictionary(live.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        return Array(ids.compactMap { byId[$0] }.prefix(8))
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass").font(.system(size: 18)).foregroundStyle(KV.Colors.fgSecondary)
                TextField(tr("搜索 Keevo"), text: $query)
                    .textFieldStyle(.plain)
                    .font(.system(size: 20))
                    .focused($focused)
                    .disabled(model.phase != .unlocked)
                Image(systemName: model.phase == .unlocked ? "checkmark.shield" : "lock")
                    .font(.system(size: 15))
                    .foregroundStyle(KV.Colors.accentFg)
                    .accessibilityLabel(model.phase == .unlocked ? tr("已解锁") : tr("已锁定"))
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
            if model.phase != .unlocked {
                Divider()
                locked
            } else if let copied {
                Divider()
                if let item = results[safe: selection] { row(item, selected: true).padding(8) }
                HStack(spacing: 8) {
                    Image(systemName: "checkmark").foregroundStyle(KV.Colors.statusSuccessFg)
                    Text(copied).font(KV.Typography.footnote.weight(.semibold)).foregroundStyle(KV.Colors.statusSuccessFg)
                    Spacer()
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .background(KV.Colors.statusSuccessBg)
            } else if !results.isEmpty {
                Divider()
                VStack(spacing: 2) {
                    ForEach(Array(results.enumerated()), id: \.element.id) { i, item in
                        row(item, selected: i == selection)
                            .onTapGesture { selection = i; copyPassword() }
                    }
                }
                .padding(8)
                Divider()
                hints
            } else if !query.isEmpty {
                Divider()
                Text(tr("没有找到「{}」", "\(query)")).font(KV.Typography.body).foregroundStyle(KV.Colors.fgSecondary).padding(16)
            }
        }
        .frame(width: QuickAccessController.width)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(KV.Colors.borderSubtle))
        .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { QuickAccessController.shared.resize(height: $0) }
        .onChange(of: model.quickAccessSession) { reset() }
        .onChange(of: query) { selection = 0 }
        .onChange(of: model.phase) { if model.phase == .unlocked { focused = true } }
        .onAppear { reset() }
        .onKeyPress(.escape) { QuickAccessController.shared.close(); return .handled }
        .onKeyPress(.downArrow) { selection = min(selection + 1, max(results.count - 1, 0)); return .handled }
        .onKeyPress(.upArrow) { selection = max(selection - 1, 0); return .handled }
        .onKeyPress(keys: [.return]) { press in
            if press.modifiers.contains(.option) { copyCode() } else { copyPassword() }
            return .handled
        }
        .onKeyPress(characters: CharacterSet(charactersIn: "co")) { press in
            guard press.modifiers.contains(.command) else { return .ignored }
            if press.characters == "c" { copyUsername() } else { openInMain() }
            return .handled
        }
    }

    private var locked: some View {
        VStack(spacing: 10) {
            Image(systemName: "lock").font(.system(size: 26)).foregroundStyle(KV.Colors.accentFg)
            Text(tr("Keevo 已锁定")).font(KV.Typography.headline)
            if model.touchIDUsable {
                Button { Task { await model.unlockWithTouchID() } } label: { Label(tr("用 Touch ID 解锁"), systemImage: "touchid") }
                    .buttonStyle(.kvPrimary)
            } else {
                Button(tr("打开 Keevo 解锁")) {
                    QuickAccessController.shared.close()
                    model.showMainWindow()
                }
                .buttonStyle(.kvPrimary)
            }
            Text(tr("解锁后继续这次搜索。")).font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 24)
    }

    private var hints: some View {
        HStack(spacing: 14) {
            hint(["↩"], tr("复制密码"))
            hint(["⌘", "C"], tr("复制用户名"))
            hint(["⌥", "↩"], tr("复制验证码"))
            hint(["⌘", "O"], tr("在主窗口打开"))
            Spacer()
            hint(["esc"], tr("关闭"))
        }
        .font(.system(size: 11))
        .foregroundStyle(KV.Colors.fgSecondary)
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    private func hint(_ keys: [String], _ text: String) -> some View {
        HStack(spacing: 3) {
            ForEach(keys, id: \.self) { k in
                Text(k)
                    .font(.system(size: 11, weight: .medium))
                    .padding(.horizontal, 4)
                    .frame(minWidth: 18)
                    .background(KV.Colors.bgRaised, in: RoundedRectangle(cornerRadius: 4))
                    .overlay(RoundedRectangle(cornerRadius: 4).strokeBorder(KV.Colors.borderSubtle))
            }
            Text(text).padding(.leading, 2)
        }
    }

    private func row(_ item: ItemEntry, selected: Bool) -> some View {
        HStack(spacing: 10) {
            SiteIcon(title: item.title, url: item.urls.first, size: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.title).font(KV.Typography.bodyStrong).foregroundStyle(selected ? .white : KV.Colors.fgPrimary)
                Text(item.subtitle.isEmpty ? ItemTypeInfo.name(item.itemType) : item.subtitle)
                    .font(KV.Typography.footnote)
                    .foregroundStyle(selected ? .white.opacity(0.8) : KV.Colors.fgSecondary)
            }
            Spacer()
            if selected, copied == nil {
                Text(tr("↩ 复制密码")).font(.system(size: 11, weight: .medium)).foregroundStyle(.white.opacity(0.85))
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(selected ? KV.Colors.accentFill : .clear, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    // MARK: 操作

    private func reset() {
        query = initialQuery
        selection = 0
        copied = nil
        focused = true
    }

    private var current: ItemEntry? { results[safe: selection] }

    private func field(_ item: ItemEntry, _ match: (FieldEntry) -> Bool) -> (ItemDetail, FieldEntry)? {
        guard let detail = model.detail(of: item.id), let f = detail.fields.first(where: match) else { return nil }
        return (detail, f)
    }

    private func copyPassword() {
        guard let item = current else { return }
        guard let (_, f) = field(item, { $0.purpose == "password" && !$0.value.expose().isEmpty }) else {
            return done(tr("「{}」没有密码", "\(item.title)"), copiedValue: false)
        }
        Clipboard.copy(f.value.expose())
        done(tr("已复制「{}」的密码，90 秒后从剪贴板清除", "\(item.title)"))
    }

    private func copyUsername() {
        guard let item = current else { return }
        guard let (_, f) = field(item, { $0.purpose == "username" && !$0.value.expose().isEmpty }) else {
            return done(tr("「{}」没有用户名", "\(item.title)"), copiedValue: false)
        }
        Clipboard.copy(f.value.expose())
        done(tr("已复制「{}」的用户名", "\(item.title)"))
    }

    private func copyCode() {
        guard let item = current else { return }
        guard let (_, f) = field(item, { $0.kind == "totp" }), let code = model.otpCode(itemId: item.id, fieldId: f.id) else {
            return done(tr("「{}」没有一次性密码", "\(item.title)"), copiedValue: false)
        }
        Clipboard.copy(code.code.expose())
        done(tr("已复制「{}」的验证码，{} 秒后更新", "\(item.title)", "\(code.remainingMs / 1000)"))
    }

    private func openInMain() {
        guard let item = current else { return }
        QuickAccessController.shared.close()
        model.mainRequest = .showItem(item.id)
        model.showMainWindow()
    }

    private func done(_ message: String, copiedValue: Bool = true) {
        copied = message
        guard copiedValue else { return }
        Task {
            try? await Task.sleep(for: .seconds(1.2))
            QuickAccessController.shared.close()
        }
    }
}

extension Array {
    subscript(safe index: Int) -> Element? { indices.contains(index) ? self[index] : nil }
}

// MARK: - 模型

extension AppModel {
    /// 打开主窗口并把 Keevo 带到前台（快速访问、菜单栏）。
    func showMainWindow() {
        NSApp.activate()
        if let window = NSApp.windows.first(where: { $0.identifier?.rawValue.hasPrefix("main") == true && $0.canBecomeMain }) {
            window.makeKeyAndOrderFront(nil)
        } else {
            openMainWindow?()
        }
    }

    /// 按设置登记全局快捷键。
    func registerQuickAccessShortcut() {
        guard isBackground else { return }
        GlobalHotKey.shared.action = { [weak self] in
            guard let self else { return }
            QuickAccessController.shared.toggle(model: self)
        }
        quickAccessShortcutTaken = !GlobalHotKey.shared.register(Shortcut.saved)
    }
}

// MARK: - 设置 → 通用

/// 快捷键录制：点一下后按新的组合键（至少带 ⌘、⌥ 或 ⌃）；esc 取消。
struct ShortcutRecorder: View {
    @Environment(AppModel.self) private var model
    @ViewState private var recording = false
    @ViewState private var shortcut = Shortcut.saved
    @ViewState private var monitor: Any?

    var body: some View {
        Button { recording ? stop() : start() } label: {
            HStack(spacing: 4) {
                if recording {
                    Text(tr("按下新的组合键…")).font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
                } else {
                    ForEach(shortcut.symbols, id: \.self) { k in
                        Text(k)
                            .font(.system(size: 11, weight: .medium))
                            .padding(.horizontal, 4)
                            .frame(minWidth: 18)
                            .background(KV.Colors.bgRaised, in: RoundedRectangle(cornerRadius: 4))
                            .overlay(RoundedRectangle(cornerRadius: 4).strokeBorder(KV.Colors.borderSubtle))
                    }
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .strokeBorder(recording ? KV.Colors.focusRing : KV.Colors.borderControl, lineWidth: recording ? 2 : 1)
            )
        }
        .buttonStyle(.plain)
        .accessibilityLabel(tr("快速访问的快捷键：{}", "\(shortcut.display)"))
        .accessibilityHint(tr("按下后输入新的组合键"))
        .onDisappear(perform: stop)
    }

    private func start() {
        recording = true
        GlobalHotKey.shared.unregister()
        monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            if event.keyCode == UInt16(kVK_Escape) {
                stop()
                return nil
            }
            if let s = Shortcut(event: event) {
                Shortcut.saved = s
                shortcut = s
                stop()
            }
            return nil
        }
    }

    private func stop() {
        if let monitor { NSEvent.removeMonitor(monitor) }
        monitor = nil
        if recording {
            recording = false
            model.registerQuickAccessShortcut()
        }
    }
}

/// 界面语言（写入本应用的 AppleLanguages，重新打开后生效）。
enum AppLanguage: String, CaseIterable, Identifiable {
    case system, zhHans = "zh-Hans", en
    var id: String { rawValue }

    var title: String {
        switch self {
        case .system: tr("跟随系统")
        case .zhHans: tr("简体中文")
        case .en: "English"
        }
    }

    static var current: AppLanguage {
        get {
            guard let list = UserDefaults.standard.persistentDomain(forName: Bundle.main.bundleIdentifier ?? "")?["AppleLanguages"] as? [String],
                  let first = list.first
            else { return .system }
            return first.hasPrefix("en") ? .en : (first.hasPrefix("zh") ? .zhHans : .system)
        }
        set {
            if newValue == .system {
                UserDefaults.standard.removeObject(forKey: "AppleLanguages")
            } else {
                UserDefaults.standard.set([newValue.rawValue], forKey: "AppleLanguages")
            }
        }
    }
}

struct GeneralSettings: View {
    @Environment(AppModel.self) private var model
    @ViewState private var language = AppLanguage.current
    @ViewState private var practice = PracticeSchedule.enabled

    var body: some View {
        @Bindable var model = model
        VStack(alignment: .leading, spacing: KV.Space.s5) {
            SettingsSection(title: tr("快速访问与菜单栏")) {
                SettingsRow(
                    title: tr("快速访问的快捷键"),
                    detail: model.quickAccessShortcutTaken
                        ? tr("这个组合键已被其他应用占用，请换一个。")
                        : tr("在任何应用中按下，搜索并复制密码。点一下后按新的组合键即可修改。")
                ) {
                    ShortcutRecorder()
                }
                CardRowDivider()
                SettingsRow(title: tr("在菜单栏显示 Keevo"), detail: tr("显示锁定状态，提供快速访问、生成密码与立即锁定。关闭窗口后 Keevo 继续在菜单栏中运行。")) {
                    Toggle(tr("在菜单栏显示 Keevo"), isOn: $model.menuBarEnabled).kvSwitch(tr("在菜单栏显示 Keevo"))
                }
            }
            SettingsSection(title: tr("语言"), footer: tr("可选：跟随系统、简体中文、English。")) {
                SettingsRow(title: tr("界面语言"), detail: tr("更改后重新打开 Keevo 生效。")) {
                    Picker(tr("界面语言"), selection: $language) {
                        ForEach(AppLanguage.allCases) { Text($0.title).tag($0) }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .fixedSize()
                    .onChange(of: language) { AppLanguage.current = language }
                }
            }
            SettingsSection(title: tr("提醒")) {
                SettingsRow(title: tr("提醒我练习主密码"), detail: tr("第 3 天、第 7 天，之后每月一次。只在开启了 Touch ID 时提醒。")) {
                    Toggle(tr("提醒我练习主密码"), isOn: $practice)
                        .kvSwitch(tr("提醒我练习主密码"))
                        .onChange(of: practice) { PracticeSchedule.enabled = practice }
                }
            }
        }
    }
}

#if DEBUG
/// 截图用：带初始搜索词的快速访问面板。
struct QuickAccessPreview: View {
    let model: AppModel
    let query: String

    var body: some View {
        QuickAccessView(initialQuery: query).environment(model)
    }
}
#endif
