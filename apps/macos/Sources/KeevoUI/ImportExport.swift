// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 导入与导出（docs/product.md §5.7，设计稿"macOS · 导入与导出"，spec/export.md）。
// 「文件 → 导入…」：选择来源与文件 →（有密码保护时输入密码）→ 预览 → 完成，导入前自动备份，完成后可以撤销。
// 「文件 → 导出…」：默认为 Keevo 加密文件；明文导出先重新验证并提示风险。
// 文件由 Rust 直接读写（keevo-ffi 的 import 模块），明文不经过 Swift。

import AppKit
import KeevoKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - 文字

enum ImportText {
    static func sourceName(_ source: String) -> String {
        switch source {
        case "keevo": "Keevo"
        case "1password": "1Password"
        case "bitwarden": "Bitwarden"
        case "chrome": "Chrome"
        case "safari": "Safari"
        case "firefox": "Firefox"
        case "lastpass": "LastPass"
        default: source
        }
    }

    static func sourceDetail(_ source: String) -> String {
        switch source {
        case "keevo": tr("Keevo 导出文件（.keevo-export 或 .json）")
        case "1password": tr("导出为 1PUX（.1pux）")
        case "bitwarden": tr("导出为 JSON（.json），可以有密码保护")
        case "chrome": tr("导出密码（.csv）")
        case "safari": tr("导出密码（.csv）")
        case "firefox": tr("导出登录信息（.csv）")
        case "lastpass": tr("导出（.csv）")
        default: ""
        }
    }

    static func fileTypes(_ source: String) -> [UTType] {
        let ext: [String] = switch source {
        case "keevo": ["keevo-export", "json"]
        case "1password": ["1pux"]
        case "bitwarden": ["json"]
        default: ["csv"]
        }
        return ext.compactMap { UTType(filenameExtension: $0) }
    }

    /// 作为安全笔记导入的原类别。
    static func original(_ code: String) -> String {
        switch code {
        case "credit_card": tr("银行卡")
        case "identity": tr("身份")
        case "document": tr("文档")
        case "software_license": tr("软件许可证")
        case "bank_account": tr("银行账户")
        case "driver_license": tr("驾照")
        case "membership": tr("会员")
        case "passport": tr("护照")
        case "wireless_router": tr("无线路由器")
        case "server": tr("服务器")
        case "crypto_wallet": tr("加密钱包")
        default: tr("其他类别")
        }
    }

    @MainActor static func problem(_ error: Error) -> String {
        guard case KeevoError.Import(let code) = error else { return AppModel.describe(error) }
        switch code {
        case "not_recognized": return tr("这个文件不是所选来源的导出文件。请确认来源，或重新导出。")
        case "wrong_password": return tr("密码不正确。")
        case "account_restricted":
            return tr("这是 Bitwarden 的「账户限制」加密导出，只能由原来的 Bitwarden 账户解密。请在 Bitwarden 中改为「受密码保护」的导出。")
        case "too_large": return tr("文件过大，或者解密参数异常地高。")
        case "empty": return tr("文件中没有可以导入的条目。")
        default: return tr("文件损坏或不完整，无法导入。")
        }
    }
}

// MARK: - 单选行

/// 单选的一行（设计稿）：圆点、名称与说明，选中时浅色底。
struct ChoiceRow: View {
    let title: String
    let detail: String
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Circle()
                    .strokeBorder(selected ? KV.Colors.accentFill : KV.Colors.borderControl, lineWidth: selected ? 5 : 1)
                    .frame(width: 16, height: 16)
                VStack(alignment: .leading, spacing: 1) {
                    Text(title)
                        .font(selected ? KV.Typography.bodyStrong : KV.Typography.body)
                        .foregroundStyle(KV.Colors.fgPrimary)
                    Text(detail)
                        .font(KV.Typography.caption)
                        .foregroundStyle(KV.Colors.fgSecondary)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .background(selected ? KV.Colors.accentSubtle : .clear)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? [.isSelected] : [])
    }
}

// MARK: - 导入

struct ImportSheet: View {
    enum Step { case source, password, preview, done }

    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @ViewState private var step: Step = .source
    @ViewState private var source = "bitwarden"
    @ViewState private var file: URL?
    @ViewState private var password = ""
    @ViewState private var preview: ImportPreview?
    @ViewState private var vaultId = ""
    @ViewState private var addTag = true
    @ViewState private var result: ImportResult?
    @ViewState private var backup: BackupInfo?
    @ViewState private var problem: String?
    @ViewState private var working = false

    /// 截图程序用：直接从某一步开始。
    init(step: Step = .source, source: String = "bitwarden", file: URL? = nil, preview: ImportPreview? = nil,
         result: ImportResult? = nil, backup: BackupInfo? = nil) {
        _step = ViewState(initialValue: step)
        _source = ViewState(initialValue: source)
        _file = ViewState(initialValue: file)
        _preview = ViewState(initialValue: preview)
        _result = ViewState(initialValue: result)
        _backup = ViewState(initialValue: backup)
    }

    private var tag: String { tr("导入 · {}", "\(ImportText.sourceName(source))") }

    var body: some View {
        Group {
            switch step {
            case .source: sourceStep
            case .password: passwordStep
            case .preview: previewStep
            case .done: doneStep
            }
        }
        .onAppear { if vaultId.isEmpty { vaultId = model.vaults.first?.id ?? "" } }
        .onDisappear { if step != .done { model.vault?.cancelImport() } }
    }

    // ① 选择来源与文件
    private var sourceStep: some View {
        SheetScaffold(title: tr("导入"), subtitle: tr("从其他密码管理器导出的文件导入。"), systemImage: "square.and.arrow.down", width: 560) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                KVCard {
                    ForEach(Array(importSources().enumerated()), id: \.element) { index, s in
                        if index > 0 { CardRowDivider() }
                        ChoiceRow(title: ImportText.sourceName(s), detail: ImportText.sourceDetail(s), selected: source == s) {
                            source = s
                            file = nil
                            problem = nil
                        }
                    }
                }
                HStack(spacing: KV.Space.s2) {
                    Button(tr("选择文件…")) { chooseFile() }.buttonStyle(.kvBordered)
                    if let file {
                        Text(file.lastPathComponent)
                            .font(KV.Typography.footnote)
                            .foregroundStyle(KV.Colors.fgSecondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                if let problem { Banner(kind: .danger, message: problem) }
                Text(tr("导出文件含有明文密码，导入后请删除。KeePass（.kdbx）稍后支持。"))
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
            }
        } footer: {
            Button(tr("取消")) { dismiss() }.buttonStyle(.kvSecondary).keyboardShortcut(.cancelAction)
            Button(tr("继续")) { prepare(password: nil) }
                .buttonStyle(.kvPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(file == nil || working)
        }
    }

    // ② 有密码保护
    private var passwordStep: some View {
        SheetScaffold(
            title: tr("导入"),
            subtitle: tr("这个 {} 导出文件有密码保护。", "\(ImportText.sourceName(source))"),
            systemImage: "square.and.arrow.down",
            width: 560
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                LabeledInput(label: tr("导出时设置的密码"), focused: true) {
                    SecureField("", text: $password).onSubmit { prepare(password: password) }
                }
                if let problem { Banner(kind: .danger, message: problem) }
                Text(tr("密码只用于这一次解密，不会保存。"))
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
            }
        } footer: {
            Button(tr("返回")) {
                step = .source
                problem = nil
            }
            .buttonStyle(.kvSecondary)
            if working { ProgressView().controlSize(.small) }
            Button(tr("继续")) { prepare(password: password) }
                .buttonStyle(.kvPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty || working)
        }
    }

    // ③ 预览
    private var previewStep: some View {
        let p = preview
        return SheetScaffold(
            title: tr("导入预览"),
            subtitle: "\(file?.lastPathComponent ?? "") · \(ImportText.sourceName(source))",
            systemImage: "square.and.arrow.down",
            width: 560
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                KVCard {
                    ForEach(Array((p?.groups ?? []).enumerated()), id: \.offset) { index, g in
                        if index > 0 { CardRowDivider() }
                        CardRow(label: g.original.map(ImportText.original) ?? ItemTypeInfo.name(g.itemType)) {
                            HStack(spacing: 4) {
                                Text("\(g.count)").font(KV.Typography.body)
                                if g.original != nil {
                                    Text(tr("· 作为安全笔记导入，字段保留"))
                                        .font(KV.Typography.footnote)
                                        .foregroundStyle(KV.Colors.fgSecondary)
                                }
                            }
                        } actions: {}
                    }
                    if let p, p.duplicates > 0 {
                        CardRowDivider()
                        CardRow(label: tr("跳过")) {
                            HStack(spacing: 4) {
                                Text("\(p.duplicates)").font(KV.Typography.body)
                                Text(tr("· 与保险库中已有的登录完全相同"))
                                    .font(KV.Typography.footnote)
                                    .foregroundStyle(KV.Colors.fgSecondary)
                            }
                        } actions: {}
                    }
                }
                HStack(spacing: 10) {
                    Text(tr("导入到")).font(KV.Typography.body)
                    Picker(tr("导入到"), selection: $vaultId) {
                        ForEach(model.vaults, id: \.id) { v in Text(v.name).tag(v.id) }
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                    .fixedSize()
                    Spacer()
                    Toggle(tr("加上标签「{}」", "\(tag)"), isOn: $addTag).toggleStyle(.checkbox)
                }
                Banner(kind: .info, message: tr("导入前会自动备份保险库；导入后可以一键撤销。文件夹会变成标签，收藏与一次性密码会保留。"))
                if let problem { Banner(kind: .danger, message: problem) }
            }
        } footer: {
            Button(tr("取消")) { dismiss() }.buttonStyle(.kvSecondary).keyboardShortcut(.cancelAction)
            if working { ProgressView().controlSize(.small) }
            Button(p.map { $0.total > 0 ? tr("导入 {} 个条目", "\($0.total)") : tr("没有新条目") } ?? tr("导入")) { commit() }
                .buttonStyle(.kvPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(working || (p?.total ?? 0) == 0 || vaultId.isEmpty)
        }
    }

    // ④ 完成
    private var doneStep: some View {
        let r = result
        let added = r?.itemIds.count ?? 0
        let plaintext = source != "keevo" || !(file.map { isKeevoExport(path: $0.path) } ?? false)
        return SheetScaffold(
            title: tr("已导入 {} 个条目", "\(added)"),
            subtitle: (r?.skipped ?? 0) > 0 ? tr("跳过了 {} 个与已有条目完全相同的登录。", "\(r?.skipped ?? 0)") : nil,
            systemImage: "checkmark",
            tint: KV.Colors.statusSuccessFg,
            width: 560
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                KVCard {
                    CardRow(label: tr("新增")) {
                        Text(addTag ? tr("{} 个条目，标签「{}」", "\(added)", "\(tag)") : tr("{} 个条目", "\(added)")).font(KV.Typography.body)
                    } actions: {}
                    if let r, r.withAttachments > 0 {
                        CardRowDivider()
                        CardRow(label: tr("附件")) {
                            Text(tr("{} 个条目带有附件，Keevo 暂不支持导入附件，已在备注中说明", "\(r.withAttachments)"))
                                .font(KV.Typography.body)
                                .fixedSize(horizontal: false, vertical: true)
                        } actions: {}
                    }
                    if let backup {
                        CardRowDivider()
                        CardRow(label: tr("备份")) {
                            Text(tr("导入前的备份 · {}", "\(BackupText.full(backup.createdMs))")).font(KV.Typography.body)
                        } actions: {}
                    }
                }
                if plaintext, let file {
                    Banner(
                        kind: .warning,
                        message: tr("导出文件中的密码是明文。确认导入无误后，请删除 {}（并清空废纸篓）。", "\(file.lastPathComponent)")
                    )
                }
                HStack(spacing: KV.Space.s4) {
                    if let file {
                        Button { NSWorkspace.shared.activateFileViewerSelecting([file]) } label: {
                            Label(tr("在访达中显示导出文件"), systemImage: "folder")
                        }
                        .buttonStyle(.kvLink)
                    }
                    if addTag {
                        Button(tr("查看导入的条目")) {
                            model.mainRequest = .showTag(tag)
                            dismiss()
                        }
                        .buttonStyle(.kvLink)
                    }
                }
            }
        } footer: {
            Button { undo() } label: { Label(tr("撤销这次导入"), systemImage: "arrow.uturn.backward") }
                .buttonStyle(.kvSecondary)
                .disabled(working)
            Button(tr("完成")) { dismiss() }
                .buttonStyle(.kvPrimary)
                .keyboardShortcut(.defaultAction)
        }
    }

    // MARK: 操作

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = ImportText.fileTypes(source)
        panel.prompt = tr("选择")
        panel.message = tr("选择从 {} 导出的文件。", "\(ImportText.sourceName(source))")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        file = url
        problem = nil
    }

    private func prepare(password: String?) {
        guard let vault = model.vault, let file else { return }
        let (path, source) = (file.path, source)
        working = true
        problem = nil
        Task {
            defer { working = false }
            do {
                preview = try await Task.detached {
                    try vault.prepareImport(path: path, source: source, password: password)
                }.value
                self.password = ""
                step = .preview
            } catch KeevoError.Import(let code) where code == "password_required" {
                step = .password
            } catch {
                problem = ImportText.problem(error)
            }
        }
    }

    private func commit() {
        guard let vault = model.vault else { return }
        working = true
        problem = nil
        let (vaultId, tag) = (vaultId, addTag ? tag : nil)
        Task {
            defer { working = false }
            // 导入前备份；备份失败时不导入
            guard let backup = await model.backupNow(kind: "import") else {
                problem = tr("无法备份保险库，所以没有导入。请在「设置 → 备份」中检查备份位置。")
                model.errorMessage = nil
                return
            }
            self.backup = backup
            do {
                result = try await Task.detached { try vault.commitImport(vaultId: vaultId, tag: tag) }.value
                model.reloadAfterBrowserWrite()
                model.scheduleSecurityCheck(after: .seconds(1))
                step = .done
            } catch {
                problem = ImportText.problem(error)
            }
        }
    }

    private func undo() {
        guard let vault = model.vault, let ids = result?.itemIds else { return }
        working = true
        Task {
            defer { working = false }
            do {
                let moved = try await Task.detached { try vault.undoImport(itemIds: ids) }.value
                model.reloadAfterBrowserWrite()
                model.scheduleSecurityCheck(after: .seconds(1))
                model.showToast(tr("已撤销导入：{} 个条目移到了最近删除", "\(moved)"))
                dismiss()
            } catch {
                problem = AppModel.describe(error)
            }
        }
    }
}

// MARK: - 导出

struct ExportSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @ViewState private var format = "keevo"
    @ViewState private var vaultId = ""
    @ViewState private var password = ""
    @ViewState private var confirm = ""
    /// 选好的保存位置；确认身份之后写入。
    @ViewState private var target: URL?
    @ViewState private var verifying = false
    @ViewState private var working = false
    @ViewState private var problem: String?

    private var passwordProblem: String? {
        guard format == "keevo" else { return nil }
        // 规则在 Rust 中（spec/export.md §3）：至少 10 个字符、不全是空白、强度「很强」
        if !exportPasswordOk(password: password) { return "" }
        if confirm != password { return confirm.isEmpty ? "" : tr("两次输入不一致") }
        return nil
    }

    var body: some View {
        SheetScaffold(title: tr("导出"), subtitle: tr("导出全部保险库，或只导出一个保险库。"), systemImage: "square.and.arrow.up", width: 560) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                KVCard {
                    ChoiceRow(title: tr("Keevo 加密文件（推荐）"), detail: tr("用你设置的导出密码加密，可以在另一台 Mac 或另一个账户中导入"), selected: format == "keevo") { format = "keevo" }
                    CardRowDivider()
                    ChoiceRow(title: tr("CSV（明文）"), detail: tr("通用格式，大多数密码管理器都能导入；只包含登录"), selected: format == "csv") { format = "csv" }
                    CardRowDivider()
                    ChoiceRow(title: tr("JSON（明文）"), detail: tr("包含全部条目与字段"), selected: format == "json") { format = "json" }
                }
                HStack(spacing: 10) {
                    Text(tr("导出")).font(KV.Typography.body)
                    Picker(tr("导出"), selection: $vaultId) {
                        Text(tr("全部保险库")).tag("")
                        ForEach(model.vaults, id: \.id) { v in Text(v.name).tag(v.id) }
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                    .fixedSize()
                }
                if format == "keevo" {
                    LabeledInput(label: tr("导出密码"), focused: true) {
                        SecureField("", text: $password)
                    }
                    ExportStrengthMeter(password: password)
                    LabeledInput(label: tr("再输入一次"), hint: passwordProblem.flatMap { $0.isEmpty ? nil : $0 }) {
                        SecureField("", text: $confirm).onSubmit(start)
                    }
                    Text(tr("导出文件只受这个密码保护（没有账户密钥这一层），所以强度必须达到「很强」。它与主密码无关；忘记后文件无法打开。"))
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let problem { Banner(kind: .danger, message: problem) }
            }
        } footer: {
            Button(tr("取消")) { dismiss() }.buttonStyle(.kvSecondary).keyboardShortcut(.cancelAction)
            if working { ProgressView().controlSize(.small) }
            Button(tr("导出…"), action: start)
                .buttonStyle(.kvPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(passwordProblem != nil || working)
        }
        .sheet(isPresented: $verifying) {
            ExportConfirmSheet(kind: format == "keevo" ? .encrypted : .plain(csv: format == "csv")) { proof in
                await verified(proof: proof)
            }
        }
    }

    private var defaultName: String {
        let date = Date().formatted(.iso8601.year().month().day())
        let ext = format == "keevo" ? "keevo-export" : format
        return tr("Keevo 导出 {}.{}", "\(date)", "\(ext)")
    }

    /// 先选位置，再确认身份（每次导出都要，第五轮预审 K15），确认后立即写入。
    private func start() {
        guard passwordProblem == nil, let url = savePanel() else { return }
        target = url
        verifying = true
    }

    private func savePanel() -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = defaultName
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        guard panel.runModal() == .OK else { return nil }
        return panel.url
    }

    /// 为导出重新验证；通过后导出到选好的位置。
    private func verified(proof: String?) async -> Bool {
        guard let vault = model.vault, let url = target else { return false }
        do {
            try await Task.detached { try vault.reverifyForExport(password: proof) }.value
        } catch KeevoError.Cancelled {
            return false
        } catch {
            model.errorMessage = AppModel.describe(error)
            return false
        }
        model.errorMessage = nil
        run(url: url, password: format == "keevo" ? password : nil)
        return true
    }

    private func run(url: URL, password: String?) {
        guard let vault = model.vault else { return }
        let (format, only) = (format, vaultId.isEmpty ? nil : vaultId)
        working = true
        problem = nil
        Task {
            defer { working = false }
            do {
                let n = try await Task.detached {
                    try vault.exportVault(path: url.path, format: format, vaultId: only, exportPassword: password)
                }.value
                model.showToast(tr("已导出 {} 个条目", "\(n)"))
                dismiss()
            } catch {
                problem = tr("无法导出：{}", "\(AppModel.describe(error))")
            }
        }
    }
}

/// 导出密码的强度（设计稿"预审修复 · 导出"）：四段条与文字，下面一行说明还差什么。
struct ExportStrengthMeter: View {
    let password: String

    var body: some View {
        // 按进入 KDF 的形式（NFKD）评估，与能否导出的判定一致
        let strength = password.isEmpty ? nil : exportPasswordStrength(password: password)
        VStack(alignment: .leading, spacing: 4) {
            MasterStrengthMeter(strength: strength)
            Text(reason(strength))
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func reason(_ s: PasswordStrengthInfo?) -> String {
        guard let s else { return tr("需要达到「很强」：建议用几个随机的词组成一句话") }
        if password.unicodeScalars.count < 10 { return tr("至少 10 个字符") }
        if password.allSatisfy(\.isWhitespace) { return tr("不能全是空格") }
        if s.score < 4 { return tr("需要达到「很强」：加长，或用几个随机的词组成一句话") }
        return tr("约 {} 比特熵", "\(Int(s.bits.rounded()))")
    }
}

/// 导出前确认身份：加密导出（设计稿"每次导出前确认身份"）与明文导出（设计稿"导出明文：重新验证"，
/// CSV 另加公式的风险）。
struct ExportConfirmSheet: View {
    enum Kind: Equatable {
        case encrypted
        case plain(csv: Bool)
    }

    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let kind: Kind
    let action: (String?) async -> Bool
    @ViewState private var password = ""
    @ViewState private var working = false

    var body: some View {
        if kind == .encrypted {
            SheetScaffold(
                title: tr("导出前确认是你本人"),
                subtitle: tr("导出文件包含所选保险库中的全部条目。"),
                systemImage: "person.crop.circle",
                width: 460
            ) {
                VStack(alignment: .leading, spacing: KV.Space.s3) {
                    proof
                    Text(tr("每次导出都要确认，加密导出也一样：拿到文件和导出密码的人就能读出全部条目。"))
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                    ErrorText()
                }
            } footer: {
                Button(tr("取消")) { dismiss() }.buttonStyle(.kvSecondary).keyboardShortcut(.cancelAction)
                Button(tr("继续")) { confirm(password) }
                    .buttonStyle(.kvPrimary)
                    .keyboardShortcut(.defaultAction)
                    .disabled(password.isEmpty || working)
            }
            .onDisappear { model.errorMessage = nil }
        } else {
            SheetScaffold(
                title: tr("导出明文文件？"),
                subtitle: tr("明文文件中的密码，任何拿到文件的人都能读取。"),
                systemImage: "exclamationmark.triangle",
                tint: KV.Colors.statusDangerFg,
                width: 560
            ) {
                VStack(alignment: .leading, spacing: KV.Space.s3) {
                    Banner(kind: .danger, message: tr("明文文件不受 Keevo 保护：同步盘、备份与邮件附件都可能把它复制到别处。导入完成后请立即删除。"))
                    if kind == .plain(csv: true) {
                        Banner(kind: .warning, message: tr("不要用电子表格软件（Numbers、Excel）打开 CSV：网站保存的用户名或标题中可能藏有公式，打开时会把同一行的密码发出去。"))
                    }
                    proof
                    ErrorText()
                }
            } footer: {
                Button(tr("取消")) { dismiss() }.buttonStyle(.kvSecondary).keyboardShortcut(.cancelAction)
                Button(tr("导出明文…")) { confirm(password) }
                    .buttonStyle(KVButtonStyle(kind: .danger))
                    .keyboardShortcut(.defaultAction)
                    .disabled(password.isEmpty || working)
            }
            .onDisappear { model.errorMessage = nil }
        }
    }

    @ViewBuilder private var proof: some View {
        if model.touchIDUsable {
            Button { confirm(nil) } label: { Label(tr("用 Touch ID 确认"), systemImage: "touchid") }
                .buttonStyle(KVButtonStyle(kind: .secondary, fullWidth: true))
                .disabled(working)
            TextDivider(text: tr("或输入主密码"))
        }
        LabeledInput(label: tr("主密码")) {
            SecureField("", text: $password).onSubmit { confirm(password) }
        }
    }

    private func confirm(_ proof: String?) {
        guard !working else { return }
        if proof?.isEmpty == true { return }
        working = true
        Task {
            if await action(proof) { dismiss() }
            working = false
        }
    }
}
