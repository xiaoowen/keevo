// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 界面截图（只在 debug 构建中编译）：在临时目录新建账户并填入示例数据，把各个页面离屏渲染为 PNG，
// 浅色与深色各一张，用于对照设计稿检查界面。不显示任何窗口，不读写用户的数据。
// 入口：`keevo-snapshots`（scripts/snapshots.sh）。

#if DEBUG
import AppKit
import CryptoKit
import KeevoKit
import SwiftUI

/// 只用于截图的软件"Secure Enclave"：密钥以原始字节作为 blob，没有任何保护。
private final class SnapshotEnclave: SecureEnclaveProvider, @unchecked Sendable {
    func createKey(purpose: UInt8) throws -> EnclaveKeyData {
        let key = P256.KeyAgreement.PrivateKey()
        return EnclaveKeyData(blob: key.rawRepresentation, publicKey: key.publicKey.x963Representation)
    }

    func agreeEphemeral(publicKey: Data) throws -> EphemeralAgreementData {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
        let eph = P256.KeyAgreement.PrivateKey()
        let shared = try eph.sharedSecretFromKeyAgreement(with: peer)
        return EphemeralAgreementData(ephemeralPublic: eph.publicKey.x963Representation, shared: shared.withUnsafeBytes { Data($0) })
    }

    func agree(purpose: UInt8, keyBlob: Data, ephemeralPublic: Data) throws -> Data {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic)
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: keyBlob)
        return try key.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
    }
}

public enum Snapshots {
    /// 运行全部截图后退出。参数：输出目录（默认 `./snapshots`）；其余参数为只截的页面名称（包含匹配）。
    @MainActor
    public static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        Task { @MainActor in
            let code = await run()
            exit(code)
        }
        app.run()
    }

    @MainActor
    private static func run() async -> Int32 {
        let args = CommandLine.arguments
        let out = URL(fileURLWithPath: args.count > 1 ? args[1] : "snapshots", isDirectory: true)
        let filters = Array(args.dropFirst(2))
        try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent("keevo-snapshots-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: temp) }

        let model = AppModel(dataDirectory: temp, enclave: SnapshotEnclave(), background: false)
        var shooter = Shooter(out: out, model: model, filters: filters)

        await shooter.shoot("onboarding", size: CGSize(width: 1100, height: 720)) { RootView() }
        await model.createAccount(password: "截图用的主密码 correct horse")
        guard let vault = model.vault, let secretKey = model.pendingSecretKey else {
            print("✗ 创建账户失败：\(model.errorMessage ?? "未知错误")")
            return 1
        }
        await shooter.shoot("secret-key-sheet", sheet: true) { SecretKeySheet(secretKey: secretKey) }
        model.pendingSecretKey = nil

        let ids: SampleItems
        do {
            ids = try SampleData.populate(vault)
        } catch {
            print("✗ 示例数据：\(error)")
            return 1
        }
        model.reloadAfterBrowserWrite()

        let main = CGSize(width: 1200, height: 760)
        await shooter.shoot("main-login", size: main) { MainView(initialItem: ids.login) }
        await shooter.shoot("main-ssh", size: main) { MainView(initialSidebar: .type("ssh_key"), initialItem: ids.ssh) }
        await shooter.shoot("main-api", size: main) { MainView(initialItem: ids.api) }
        await shooter.shoot("main-database", size: main) { MainView(initialItem: ids.database) }
        await shooter.shoot("main-environment", size: main) { MainView(initialItem: ids.environment) }
        await shooter.shoot("main-note", size: main) { MainView(initialItem: ids.note) }
        await shooter.shoot("main-email", size: main) { MainView(initialItem: ids.email) }
        await shooter.shoot("main-two-factor", size: main) { MainView(initialItem: ids.twoFactor) }
        await shooter.shoot("main-no-selection", size: main) { MainView() }
        await shooter.shoot("main-empty-trash", size: main) { MainView(initialSidebar: .trash) }
        await model.runSecurityCheck()
        await shooter.shoot("security-center", size: main) { MainView(initialSidebar: .security) }
        await shooter.shoot("main-weak", size: main) { MainView(initialItem: ids.weak) }

        await shooter.shoot("editor-login", size: main) { MainView(initialItem: ids.login, initialEditing: true) }
        await shooter.shoot("editor-environment", size: main) { MainView(initialItem: ids.environment, initialEditing: true) }
        await shooter.shoot("history", sheet: true) { HistorySheet(itemId: ids.login) }
        await shooter.shoot("generator", sheet: true) { GeneratorView() }
        if let choice = NewItemChoice.all.first {
            await shooter.shoot("new-item", sheet: true) {
                NewItemSheet(choice: choice, defaultVault: model.vaults.first?.id) { _ in }
            }
        }
        await shooter.shoot("new-login", sheet: true) {
            NewLoginSheet(defaultVault: model.vaults.first?.id) { _ in }
        }
        await shooter.shoot("dialog-reverify", sheet: true) {
            ReverifySheet(title: "解除「Chrome · 个人」的配对", message: "解除后，这个扩展立即断开，不能再取用任何密码。请先确认是你本人。", confirmTitle: "解除配对", destructive: true) { _ in false }
        }
        // 导入 SSH 私钥（设计稿"macOS · 导入 SSH 私钥"）：有口令保护、口令错误、不支持的算法
        let encryptedKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA9aYwopX
        …
        -----END OPENSSH PRIVATE KEY-----
        """
        let rsaKey = encryptedKey.replacingOccurrences(of: "AAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA9aYwopX", with: "AAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcnNh")
        await shooter.shoot("ssh-import-passphrase", sheet: true) {
            ImportSshKeySheet(itemId: ids.ssh, text: encryptedKey, passphrase: "correct horse", needsPassphrase: true)
        }
        await shooter.shoot("ssh-import-wrong", sheet: true) {
            ImportSshKeySheet(itemId: ids.ssh, text: encryptedKey, needsPassphrase: true, problem: (.danger, AppModel.sshKeyProblem(code: "wrong_passphrase")))
        }
        await shooter.shoot("ssh-import-unsupported", sheet: true) {
            ImportSshKeySheet(itemId: ids.ssh, text: rsaKey, needsPassphrase: false, problem: (.warning, AppModel.sshKeyProblem(code: "unsupported", detail: "ssh-rsa")))
        }
        await shooter.shoot("kdf-confirm", sheet: true) {
            KdfConfirmSheet(info: KdfInfo(memoryKib: 4 * 1024 * 1024, iterations: 12, parallelism: 4)) {}
        }
        await shooter.shoot("settings-security", sheet: true) { SettingsView(initialTab: 0) }
        await shooter.shoot("settings-browser", sheet: true) { SettingsView(initialTab: 1) }
        model.refreshDeveloper()
        await shooter.shoot("settings-developer", sheet: true) { SettingsView(initialTab: 2) }

        let words = zip(["秋千", "珍珠", "薄荷", "稻米", "企鹅", "胡同"], ["swing", "pearl", "mint", "rice", "penguin", "alley"])
            .map { SasWord(zh: $0, en: $1) }
        let deadline = Date().addingTimeInterval(42)
        await shooter.shoot("dialog-pairing", sheet: true) {
            PairingConfirmSheet(request: PairingRequest(words: words, name: "Chrome · 个人", browser: "com.google.Chrome", deadline: deadline) { _ in })
        }
        let fill = BrowserFillRequest(pairingId: "", pairingName: "Chrome · 个人", browser: "com.google.Chrome", itemId: ids.login, title: "GitHub", username: "octocat", site: "https://github.com")
        await shooter.shoot("dialog-fill", sheet: true) {
            FillAuthorizationSheet(request: FillAuthorizationRequest(request: fill, deadline: deadline) { _ in })
        }
        let update = BrowserUpdateRequest(pairingId: "", pairingName: "Chrome · 个人", browser: "com.google.Chrome", itemId: ids.login, title: "GitHub", username: "octocat", site: "https://github.com")
        await shooter.shoot("dialog-update", sheet: true) {
            UpdateConfirmationSheet(request: UpdateConfirmationRequest(request: update, changed: true, deadline: deadline) { _ in })
        }

        let terminal = RequestOrigin(
            app: "iTerm", command: "keevo run --env-file .env.keevo -- npm run dev", parentName: "zsh",
            parentCommand: nil, inTerminal: true
        )
        await shooter.shoot("dialog-cli", sheet: true) {
            CliAuthorizationSheet(request: CliAuthorizationRequest(origin: terminal, deadline: deadline) { _ in })
        }
        let sshOrigin = RequestOrigin(
            app: "iTerm", command: "ssh git@github.com git-receive-pack me/keevo.git",
            parentName: "git", parentCommand: "git push", inTerminal: true
        )
        let sign = SshSignRequest(
            origin: sshOrigin, itemId: ids.ssh, keyTitle: "GitHub SSH 密钥",
            fingerprint: "SHA256:7c8GBuOAt2qcDj3Pik3RNArB+fLS3hcl/jaWXEu0Xq0",
            hostFingerprint: "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU", hostVerified: true,
            forwarded: false, policy: "session"
        )
        await shooter.shoot("dialog-ssh", sheet: true) {
            SshSignSheet(request: SshAuthorizationRequest(request: sign, deadline: deadline) { _ in })
        }
        var forwardedSign = sign
        forwardedSign.forwarded = true
        await shooter.shoot("dialog-ssh-forwarded", sheet: true) {
            SshSignSheet(request: SshAuthorizationRequest(request: forwardedSign, deadline: deadline) { _ in })
        }

        model.lock()
        model.unlockWaiter = .cli
        await shooter.shoot("lock-waiting", size: CGSize(width: 960, height: 640)) { RootView() }
        model.unlockWaiter = nil
        await shooter.shoot("lock", size: CGSize(width: 960, height: 640)) { RootView() }
        await shooter.shoot("enclave-unavailable", size: CGSize(width: 960, height: 640)) { EnclaveUnavailableView() }
        print("截图完成：\(shooter.count) 张，保存在 \(out.path)")
        return 0
    }
}

@MainActor
private struct Shooter {
    let out: URL
    let model: AppModel
    let filters: [String]
    var count = 0

    /// 浅色与深色各渲染一张：`<名称>-light.png`、`<名称>-dark.png`。
    /// `size` 为 `nil` 时按内容的自然大小截取；`sheet` 为真时不带窗口外框（面板、设置）。
    mutating func shoot<V: View>(_ name: String, size: CGSize? = nil, sheet: Bool = false, @ViewBuilder _ view: () -> V) async {
        guard filters.isEmpty || filters.contains(where: { name.contains($0) }) else { return }
        for dark in [false, true] {
            let base = view().tinted.environment(model)
            let host: NSHostingView<AnyView>
            if let size {
                host = NSHostingView(rootView: AnyView(base.frame(width: size.width, height: size.height)))
                host.frame = CGRect(origin: .zero, size: size)
            } else {
                host = NSHostingView(rootView: AnyView(base.fixedSize().background(KV.Colors.bgRaised)))
                host.frame = CGRect(origin: .zero, size: host.fittingSize)
            }
            let window = NSWindow(
                contentRect: host.frame,
                styleMask: sheet ? [.borderless] : [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                backing: .buffered,
                defer: false
            )
            // 由 ARC 管理；默认关闭时自行释放，会与 ARC 重复释放
            window.isReleasedWhenClosed = false
            // 与应用的窗口一致：隐藏标题栏（KeevoApp 的 .hiddenTitleBar）
            window.titlebarAppearsTransparent = true
            window.titleVisibility = .hidden
            window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            window.contentView = host
            window.layoutIfNeeded()
            // 让 SwiftUI 完成首次布局与 onAppear / task 中的加载
            for _ in 0..<6 {
                try? await Task.sleep(for: .milliseconds(80))
                host.layoutSubtreeIfNeeded()
            }
            if size == nil {
                // 加载之后内容可能变高
                window.setContentSize(host.fittingSize)
                host.layoutSubtreeIfNeeded()
            }
            // 连同标题栏与工具栏一起截（窗口的框架视图）；面板只截内容
            let frameView = sheet ? host : (window.contentView?.superview ?? host)
            guard let rep = frameView.bitmapImageRepForCachingDisplay(in: frameView.bounds) else { continue }
            frameView.cacheDisplay(in: frameView.bounds, to: rep)
            let file = out.appendingPathComponent("\(name)-\(dark ? "dark" : "light").png")
            try? rep.representation(using: .png, properties: [:])?.write(to: file)
            window.contentView = nil
            window.close()
            count += 1
        }
    }
}

struct SampleItems {
    var login = ""
    var ssh = ""
    var api = ""
    var database = ""
    var environment = ""
    var note = ""
    var email = ""
    var twoFactor = ""
    /// 安全中心的示例：弱密码、与其他条目重复、http 网址。
    var weak = ""
}

/// 截图用的示例数据：覆盖每种条目类型。值都是虚构的。
enum SampleData {
    static func populate(_ vault: KeevoVault) throws -> SampleItems {
        let vaultId = try vault.vaults()[0].id
        var ids = SampleItems()

        func make(_ type: String, _ title: String, preset: String? = nil, values: [String: String], tags: [String] = [], favorite: Bool = false) throws -> String {
            let id = try vault.createItem(vaultId: vaultId, itemType: type, preset: preset, title: title)
            let detail = try vault.item(itemId: id)
            var edits: [ItemEdit] = detail.fields.compactMap { f in
                values[f.label].map { ItemEdit.setFieldValue(fieldId: f.id, value: $0) }
            }
            edits += tags.map { ItemEdit.addTag(tag: $0) }
            if favorite { edits.append(.setFavorite(favorite: true)) }
            if !edits.isEmpty { try vault.updateItem(itemId: id, edits: edits) }
            return id
        }

        ids.login = try make("login", "GitHub", values: [
            "用户名": "octocat",
            "密码": "Tr0ub4dor&3-horse-battery",
            "网站": "https://github.com",
            "一次性密码": "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        ], tags: ["工作", "开源"], favorite: true)
        _ = try make("login", "Apple ID", values: ["用户名": "me@icloud.com", "密码": "correct-horse-staple-42", "网站": "https://appleid.apple.com"])
        _ = try make("login", "Figma", values: ["用户名": "design@studio.example", "密码": "Fg!8kd92-ab", "网站": "https://figma.com"], tags: ["工作"])
        _ = try make("login", "阿里云", values: ["用户名": "admin", "密码": "Fg!8kd92-ab", "网站": "https://aliyun.com"])
        ids.weak = try make("login", "论坛", values: ["用户名": "me@example.com", "密码": "p@ssw0rd", "网站": "http://forum.example.com"])
        ids.email = try make("email_account", "Outlook 邮箱", values: [
            "邮箱地址": "me@outlook.com", "密码": "outlook-pass-77", "提供商": "Microsoft",
            "IMAP 服务器": "outlook.office365.com", "IMAP 端口": "993", "SMTP 服务器": "smtp.office365.com", "SMTP 端口": "587",
        ])
        ids.note = try make("secure_note", "家里的 Wi-Fi", values: ["正文": "网络名称：Keevo-Home\n密码：purple-elephant-42\n路由器管理地址：192.168.1.1"])
        // 真实生成的 Ed25519 密钥：私钥、公钥、指纹由 Keevo 写入，Agent 策略为"每个会话确认一次"
        ids.ssh = try make("ssh_key", "GitHub SSH 密钥", values: ["主机": "github.com"], tags: ["开发"])
        _ = try vault.generateSshKey(itemId: ids.ssh)
        try vault.setSshAgentPolicy(itemId: ids.ssh, policy: "session")
        ids.api = try make("api_credential", "OpenAI API 密钥", values: [
            "提供商": "OpenAI", "Key ID": "proj_8f3a9", "Secret": "sk-proj-Xa7Hq2Lm9Pz4Rt6Vb1Nc8Dw3Ek5Fy0Gs", "作用域": "chat, embeddings",
            "端点": "https://api.openai.com/v1", "过期时间": "2026-12-21",
        ], tags: ["开发"])
        ids.database = try make("database", "生产数据库", values: [
            "引擎": "PostgreSQL", "主机": "app-db.internal", "端口": "5432", "数据库": "app", "用户名": "app", "密码": "pg-Prod-9xQ2-mZ7",
            "SSL 模式": "require", "跳板机": "bastion.example.com",
        ], tags: ["开发"])
        ids.environment = try make("environment", "my-app 环境变量", values: ["项目": "my-app"], tags: ["开发"])
        if let detail = try? vault.item(itemId: ids.environment), let dev = detail.fields.first(where: { $0.kind == "kv_list" }) {
            try vault.updateItem(itemId: ids.environment, edits: [.setFieldKv(fieldId: dev.id, entries: [
                KvInput(key: "DATABASE_URL", value: "postgres://localhost:5432/app", concealed: false),
                KvInput(key: "REDIS_URL", value: "redis://localhost:6379/0", concealed: false),
                KvInput(key: "OPENAI_API_KEY", value: "sk-dev-Q8wE2rT6yU1iO9pA", concealed: true),
            ])])
        }
        ids.twoFactor = try make("two_factor", "Cloudflare 双因素", values: [
            "发行方": "Cloudflare", "账户名": "ops@example.com",
            "一次性密码": "otpauth://totp/Cloudflare:ops?secret=GEZDGNBVGY3TQOJQ&issuer=Cloudflare",
        ])
        if let detail = try? vault.item(itemId: ids.twoFactor), let codes = detail.fields.first(where: { $0.kind == "recovery_codes" }) {
            try vault.updateItem(itemId: ids.twoFactor, edits: [.setFieldCodes(fieldId: codes.id, codes: [
                CodeInput(code: "4f2k-9xq1", used: true), CodeInput(code: "8m3n-2wpz", used: false), CodeInput(code: "c7vb-5tyr", used: false),
            ])])
        }
        return ids
    }
}
#endif
