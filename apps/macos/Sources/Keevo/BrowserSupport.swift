// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 浏览器扩展支持（spec/ipc.md）：Vault Service 的原生确认界面、"设置 → 浏览器"、Chrome 的 host 清单。

import AppKit
import KeevoKit
import SwiftUI

/// 一次待确认的配对（spec/ipc.md §4.2 第 5 步）。
struct PairingRequest: Identifiable {
    let id = UUID()
    let sas: String
    let name: String
    let browser: String
    let deadline: Date
    let answer: (Bool) -> Void
}

/// Rust 服务调用的原生确认界面。这些方法在服务的工作线程中调用，阻塞到用户回答或超时为止；
/// 界面只出现在 Keevo.app 中，扩展与网页无法伪造（spec/ipc.md §5.2 第 4 条）。
final class BrowserPromptBridge: BrowserPrompt, @unchecked Sendable {
    private weak var model: AppModel?

    init(model: AppModel) {
        self.model = model
    }

    func pairingStarted(browser: String) {
        DispatchQueue.main.async { [weak self] in
            self?.model?.pairingNotice = browser
            NSApp.requestUserAttention(.informationalRequest)
        }
    }

    func confirmPairing(sas: String, name: String, browser: String, timeoutMs: UInt64) -> Bool {
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var result = false
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000)
        let request = PairingRequest(sas: sas, name: name, browser: browser, deadline: deadline) { accepted in
            lock.withLock { result = accepted }
            semaphore.signal()
        }
        DispatchQueue.main.async { [weak self] in
            self?.model?.pairingNotice = nil
            self?.model?.pairingRequest = request
            NSApp.activate()
        }
        let answered = semaphore.wait(timeout: .now() + .milliseconds(Int(min(timeoutMs, 60_000)))) == .success
        if !answered {
            // 截止时间到：关闭界面并按拒绝处理（spec/ipc.md §4.2 第 7 步）
            DispatchQueue.main.async { [weak self] in
                if self?.model?.pairingRequest?.id == request.id { self?.model?.pairingRequest = nil }
            }
            return false
        }
        return lock.withLock { result }
    }
}

/// 配对确认：比对两边显示的短认证串（spec/ipc.md §4.2）。
struct PairingConfirmSheet: View {
    @Environment(AppModel.self) private var model
    let request: PairingRequest

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let left = max(0, Int(request.deadline.timeIntervalSince(context.date).rounded(.up)))
            VStack(alignment: .leading, spacing: 16) {
                Label("浏览器请求配对", systemImage: "puzzlepiece.extension")
                    .font(.title3.weight(.semibold))
                Text("「\(request.name)」（\(browserName(request.browser))）请求连接 Keevo。请确认扩展弹窗中显示的验证码与下面完全一致。")
                    .fixedSize(horizontal: false, vertical: true)
                classifiedText(request.sas.uppercased(), font: KV.Typography.largeType)
                    .frame(maxWidth: .infinity)
                    .padding(KV.Space.s4)
                    .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: KV.Radius.md))
                    .accessibilityLabel("验证码 \(request.sas)")
                Text("如果不一致，或者你没有在扩展中发起配对，请选择「不一致」。配对后，这个扩展可以在你授权的网站上取用密码。")
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Text("\(left) 秒后自动拒绝").font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgTertiary)
                    Spacer()
                    Button("不一致") { answer(false) }
                        .keyboardShortcut(.cancelAction)
                    Button("一致，确认配对") { answer(true) }
                }
            }
            .padding(24)
            .frame(width: 480)
            .onChange(of: left) { if left == 0 { model.pairingRequest = nil } }
        }
    }

    private func answer(_ accepted: Bool) {
        // 截止时间之后的确认一律按拒绝处理（Rust 端也会再检查一次）
        request.answer(accepted && Date() < request.deadline)
        model.pairingRequest = nil
    }
}

func browserName(_ id: String) -> String {
    switch id {
    case "com.google.Chrome": "Google Chrome"
    case "com.microsoft.edgemac": "Microsoft Edge"
    case "com.brave.Browser": "Brave"
    default: id
    }
}

/// Chrome 的 native messaging host 清单（spec/ipc.md §3.2）：host 位于应用包内，只允许 Keevo 扩展连接。
enum NativeHostManifest {
    static var directory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Google/Chrome/NativeMessagingHosts", isDirectory: true)
    }

    static var file: URL { directory.appendingPathComponent(browserHostName() + ".json") }

    /// 应用包内的 host。不是从打包的 Keevo.app 运行时为 `nil`。
    static var hostBinary: URL? {
        let url = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/keevo-native-host")
        return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
    }

    /// 已安装，且指向这个应用包里的 host。
    static var installed: Bool {
        guard let data = try? Data(contentsOf: file),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let path = json["path"] as? String
        else { return false }
        return path == hostBinary?.path
    }

    enum InstallError: Error {
        case notBundled
        case noExtensionId
    }

    static func install() throws {
        guard let host = hostBinary else { throw InstallError.notBundled }
        guard let extensionId = browserExtensionId() else { throw InstallError.noExtensionId }
        let manifest: [String: Any] = [
            "name": browserHostName(),
            "description": "Keevo",
            "path": host.path,
            "type": "stdio",
            "allowed_origins": ["chrome-extension://\(extensionId)/"],
        ]
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        try data.write(to: file, options: .atomic)
    }

    static func uninstall() throws {
        if FileManager.default.fileExists(atPath: file.path) {
            try FileManager.default.removeItem(at: file)
        }
    }
}

/// "设置 → 浏览器"：已配对的扩展、解除配对、Chrome 支持。
struct BrowserSettings: View {
    @Environment(AppModel.self) private var model
    @ViewState private var revoking: BrowserPairing?
    @ViewState private var installMessage: String?
    @ViewState private var installed = NativeHostManifest.installed

    var body: some View {
        Form {
            Section("Chrome") {
                LabeledContent("连接 Keevo 扩展") {
                    if installed {
                        HStack {
                            Label("已安装", systemImage: "checkmark.circle.fill").foregroundStyle(KV.Colors.statusSuccessFg)
                            Button("卸载") { run { try NativeHostManifest.uninstall() } }
                        }
                    } else {
                        Button("安装") { run { try NativeHostManifest.install() } }
                    }
                }
                if let installMessage {
                    Text(installMessage).font(.callout).foregroundStyle(KV.Colors.statusDangerFg)
                }
                if let error = model.browserServiceError {
                    Text("浏览器服务没有启动：\(error)").font(.callout).foregroundStyle(KV.Colors.statusWarningFg)
                }
                Text("安装后，Chrome 中的 Keevo 扩展可以通过本机的安全通道连接 Keevo。扩展第一次连接时需要在这里确认配对。")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Section("已配对的扩展") {
                if model.phase != .unlocked {
                    Text("解锁 Keevo 之后才能查看。").foregroundStyle(.secondary)
                } else if model.browserPairings.isEmpty {
                    Text("还没有配对的扩展。").foregroundStyle(.secondary)
                } else {
                    ForEach(model.browserPairings, id: \.id) { p in
                        HStack {
                            VStack(alignment: .leading) {
                                Text(p.name.isEmpty ? "（未命名）" : p.name)
                                Text("\(browserName(p.browser)) · 配对于 \(Date(timeIntervalSince1970: TimeInterval(p.pairedAtMs) / 1000).formatted(date: .abbreviated, time: .shortened))")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("解除配对…") { revoking = p }
                        }
                    }
                }
                if model.pendingRevocationWarning {
                    Banner(kind: .warning, message: "有撤销没能写入数据库，重启 Keevo 后可能失效。下次解锁时会自动重试。")
                }
            }
        }
        .formStyle(.grouped)
        .padding()
        .onAppear { model.refreshBrowserPairings() }
        .sheet(item: Binding(get: { revoking.map(RevokeItem.init) }, set: { if $0 == nil { revoking = nil } })) { item in
            ReverifySheet(
                title: "解除「\(item.pairing.name)」的配对",
                message: "解除后，这个扩展立即断开，不能再取用任何密码。请先确认是你本人。"
            ) { password in
                await model.revokeBrowserPairing(id: item.pairing.id, password: password)
            }
        }
    }

    private func run(_ body: () throws -> Void) {
        do {
            try body()
            installMessage = nil
        } catch NativeHostManifest.InstallError.notBundled {
            installMessage = "请从打包的 Keevo.app 运行（scripts/package-macos.sh），host 位于应用包内。"
        } catch NativeHostManifest.InstallError.noExtensionId {
            installMessage = "这个构建没有编译进扩展 ID。"
        } catch {
            installMessage = "写入 host 清单失败：\(error.localizedDescription)"
        }
        installed = NativeHostManifest.installed
    }
}

private struct RevokeItem: Identifiable {
    let pairing: BrowserPairing
    var id: String { pairing.id }
}

/// 敏感操作之前重新验证：Touch ID 或主密码（docs/ux.md §5"重新验证"）。`action` 收到 `nil` 表示用 Touch ID。
struct ReverifySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let title: String
    let message: String
    let action: (String?) async -> Bool
    @ViewState private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(title).font(.title3.weight(.semibold))
            Text(message).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if model.touchIDUsable {
                Button {
                    Task { if await action(nil) { dismiss() } }
                } label: {
                    Label("用 Touch ID 确认", systemImage: "touchid")
                }
                .disabled(model.busy)
                Text("或者输入主密码：").font(.callout).foregroundStyle(.secondary)
            }
            SecureField("主密码", text: $password).frame(width: 320)
            ErrorText()
            HStack {
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("确认") {
                    Task { if await action(password) { dismiss() } }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty || model.busy)
            }
        }
        .padding(24)
        .frame(width: 460)
    }
}
