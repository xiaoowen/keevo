// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 备份与恢复（docs/product.md §5.7，设计稿"macOS · 备份与恢复"）：每天自动备份、导入与恢复之前额外备份，
// 默认保留 30 份；"设置 → 备份"列出备份、立即备份、更改位置，从备份恢复前再备份一次当前的保险库。
// 备份是数据库的副本，与保险库同等加密（keevo-core::backup）。

import AppKit
import KeevoKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - 模型

extension AppModel {
    static let backupKeepChoices = [10, 30, 100]

    var backupFolder: String { customBackupFolder ?? defaultBackupFolder }

    func refreshBackups() {
        backups = listBackups(dir: backupFolder)
    }

    /// 打开数据库后开始：立即检查一次，之后每小时检查是否该做每天的备份。
    func startAutoBackup() {
        backupTimer?.cancel()
        backupTimer = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                await self?.autoBackupIfDue()
                try? await Task.sleep(for: .seconds(3600))
            }
        }
    }

    /// 每天一次。锁定时也可以进行：备份中只有密文。
    func autoBackupIfDue() async {
        guard autoBackupEnabled, let vault else { return }
        let (dir, keep) = (backupFolder, UInt32(clamping: backupKeep))
        do {
            try await Task.detached {
                guard autoBackupDue(dir: dir) else { return }
                _ = try vault.createBackup(dir: dir, kind: "auto")
                _ = try pruneBackups(dir: dir, keep: keep)
            }.value
            backupError = nil
        } catch {
            backupError = "上次自动备份失败：无法写入备份文件夹。外部硬盘没有连接时，连接后会自动重试。"
        }
        refreshBackups()
    }

    /// 立即备份，或重大操作之前的备份（`kind`：`manual`、`import`、`delete`）。成功时返回这份备份。
    @discardableResult
    func backupNow(kind: String = "manual") async -> BackupInfo? {
        guard let vault else { return nil }
        let (dir, keep) = (backupFolder, UInt32(clamping: backupKeep))
        defer { refreshBackups() }
        do {
            let info = try await Task.detached {
                let info = try vault.createBackup(dir: dir, kind: kind)
                _ = try pruneBackups(dir: dir, keep: keep)
                return info
            }.value
            backupError = nil
            return info
        } catch {
            errorMessage = "无法备份：备份文件夹不可写。请在「设置 → 备份」中检查位置。"
            return nil
        }
    }

    func setBackupKeep(_ keep: Int) {
        backupKeep = keep
        _ = try? pruneBackups(dir: backupFolder, keep: UInt32(clamping: keep))
        refreshBackups()
    }

    func chooseBackupFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "选择"
        panel.message = "选择存放 Keevo 备份的文件夹，例如外部硬盘或同步盘中的文件夹。"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        customBackupFolder = url.path == defaultBackupFolder ? nil : url.path
        refreshBackups()
        Task { await autoBackupIfDue() }
    }

    func revealBackups() {
        try? FileManager.default.createDirectory(
            atPath: backupFolder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
        )
        NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: backupFolder)
    }

    /// 检查文件能否用来恢复。不能时返回原因。
    func backupProblem(_ path: String) -> String? {
        guard let vault else { return "保险库没有打开。" }
        do {
            try vault.checkBackup(path: path)
            return nil
        } catch {
            return Self.describe(error)
        }
    }

    /// 从备份恢复。恢复前再备份一次当前的保险库；之后回到锁屏，用备份时的主密码解锁。
    func restore(from backup: BackupInfo) async -> Bool {
        guard let vault else { return false }
        let dir = backupFolder
        do {
            _ = try await Task.detached { try vault.restoreBackup(path: backup.path, dir: dir) }.value
        } catch {
            report(error)
            return false
        }
        lock()
        lockNotice = "已恢复到 \(BackupText.when(backup.createdMs)) 的备份。请用备份时的主密码解锁；恢复前的保险库已另存一份备份。"
        refreshBackups()
        return true
    }
}

// MARK: - 文字

enum BackupText {
    static func kind(_ kind: String) -> String {
        switch kind {
        case "auto": "自动"
        case "manual": "手动"
        case "import": "导入之前"
        case "delete": "删除之前"
        case "restore": "恢复之前"
        default: kind
        }
    }

    /// "今天 14:32"、"昨天 09:00"、"11月17日 09:00"、"2025年11月17日 09:00"。
    static func when(_ ms: UInt64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        let calendar = Calendar.current
        let time = date.formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits))
        if calendar.isDateInToday(date) { return "今天 \(time)" }
        if calendar.isDateInYesterday(date) { return "昨天 \(time)" }
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        let sameYear = c.year == calendar.component(.year, from: Date())
        return (sameYear ? "" : "\(c.year ?? 0)年") + "\(c.month ?? 0)月\(c.day ?? 0)日 \(time)"
    }

    static func full(_ ms: UInt64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        let c = Calendar.current.dateComponents([.year, .month, .day], from: date)
        let time = date.formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits))
        return "\(c.year ?? 0)年\(c.month ?? 0)月\(c.day ?? 0)日 \(time)"
    }

    static func size(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: bytes), countStyle: .file)
    }

    /// 显示用的位置：家目录写作 ~。
    static func folder(_ path: String) -> String {
        let home = NSHomeDirectory()
        return path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path
    }
}

/// 一行备份：图标、时间、原因与大小。
struct BackupRow: View {
    let backup: BackupInfo
    var selected = false

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "archivebox")
                .font(.system(size: 14))
                .foregroundStyle(KV.Colors.fgSecondary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(BackupText.when(backup.createdMs))
                    .font(selected ? KV.Typography.bodyStrong : KV.Typography.body)
                    .foregroundStyle(KV.Colors.fgPrimary)
                Text(BackupText.kind(backup.kind))
                    .font(KV.Typography.caption)
                    .foregroundStyle(KV.Colors.fgSecondary)
            }
            Spacer(minLength: KV.Space.s2)
            Text(BackupText.size(backup.size))
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .background(selected ? KV.Colors.bgSelected : .clear)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

// MARK: - 设置 → 备份

struct BackupSettings: View {
    @Environment(AppModel.self) private var model
    @ViewState private var choosing = false
    @ViewState private var confirming: BackupInfo?
    @ViewState private var working = false

    var body: some View {
        @Bindable var model = model
        VStack(alignment: .leading, spacing: KV.Space.s5) {
            SettingsSection(
                title: "自动备份",
                footer: "备份与保险库同等加密：需要主密码与账户密钥才能打开。可以选一个外部硬盘或同步盘中的文件夹。"
            ) {
                SettingsRow(title: "每天自动备份", detail: "Keevo 运行时每天一次；导入与恢复之前也会备份。") {
                    Toggle("每天自动备份", isOn: $model.autoBackupEnabled)
                        .kvSwitch("每天自动备份")
                }
                CardRowDivider()
                SettingsRow(title: "位置", detail: BackupText.folder(model.backupFolder)) {
                    HStack(spacing: KV.Space.s2) {
                        if model.customBackupFolder != nil {
                            Button("恢复默认") {
                                model.customBackupFolder = nil
                                model.refreshBackups()
                            }
                            .buttonStyle(.kvLink)
                        }
                        Button("更改…") { model.chooseBackupFolder() }
                            .buttonStyle(.kvBordered)
                    }
                }
                CardRowDivider()
                SettingsRow(title: "保留") {
                    Picker("保留", selection: Binding(get: { model.backupKeep }, set: { model.setBackupKeep($0) })) {
                        ForEach(AppModel.backupKeepChoices, id: \.self) { n in
                            Text("最近 \(n) 份").tag(n)
                        }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .fixedSize()
                }
            }
            if let error = model.backupError {
                Banner(kind: .warning, message: error)
            }
            VStack(alignment: .leading, spacing: KV.Space.s2) {
                GroupTitle(text: "备份（\(model.backups.count)）")
                if model.backups.isEmpty {
                    Text("还没有备份。")
                        .font(KV.Typography.body)
                        .foregroundStyle(KV.Colors.fgSecondary)
                } else {
                    KVCard {
                        ForEach(Array(model.backups.prefix(6).enumerated()), id: \.element.path) { index, b in
                            if index > 0 { CardRowDivider() }
                            BackupRow(backup: b)
                        }
                    }
                }
                HStack(spacing: KV.Space.s2) {
                    Button("立即备份") {
                        working = true
                        Task {
                            if await model.backupNow() != nil { model.showToast("已备份") }
                            working = false
                        }
                    }
                    .buttonStyle(.kvBordered)
                    .disabled(working)
                    Button("从备份恢复…") { choosing = true }
                        .buttonStyle(.kvBordered)
                        .disabled(model.phase != .unlocked)
                    Spacer()
                    Button { model.revealBackups() } label: { Label("在访达中显示", systemImage: "folder") }
                        .buttonStyle(.kvLink)
                }
            }
        }
        .onAppear { model.refreshBackups() }
        .sheet(isPresented: $choosing) {
            RestorePickerSheet { confirming = $0 }
        }
        .sheet(item: $confirming) { backup in
            RestoreConfirmSheet(backup: backup)
        }
    }
}

extension BackupInfo: Identifiable {
    public var id: String { path }
}

// MARK: - 选择备份

struct RestorePickerSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let next: (BackupInfo) -> Void
    @ViewState private var selected: String?
    /// 从其他位置选择的文件。
    @ViewState private var other: BackupInfo?
    @ViewState private var problem: String?

    private var candidates: [BackupInfo] { (other.map { [$0] } ?? []) + model.backups }

    var body: some View {
        SheetScaffold(
            title: "选择要恢复的备份",
            subtitle: "也可以从其他位置选择一个 Keevo 备份文件（.keevo-backup）。",
            systemImage: "archivebox",
            width: 520
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                if candidates.isEmpty {
                    Text("备份文件夹中还没有备份。")
                        .font(KV.Typography.body)
                        .foregroundStyle(KV.Colors.fgSecondary)
                } else {
                    KVCard {
                        ScrollView {
                            VStack(spacing: 0) {
                                ForEach(Array(candidates.enumerated()), id: \.element.path) { index, b in
                                    if index > 0 { CardRowDivider() }
                                    Button {
                                        selected = b.path
                                        problem = nil
                                    } label: {
                                        BackupRow(backup: b, selected: current == b.path)
                                    }
                                    .buttonStyle(.plain)
                                }
                            }
                        }
                        .frame(maxHeight: 260)
                    }
                }
                if let problem {
                    Banner(kind: .danger, message: problem)
                }
                Button { pickFile() } label: { Label("从其他位置选择…", systemImage: "folder") }
                    .buttonStyle(.kvLink)
            }
        } footer: {
            Button("取消") { dismiss() }
                .buttonStyle(.kvSecondary)
                .keyboardShortcut(.cancelAction)
            Button("继续") { proceed() }
                .buttonStyle(.kvPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(current == nil)
        }
        .onAppear { model.refreshBackups() }
    }

    private var current: String? { selected ?? candidates.first?.path }

    private func pickFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if let type = UTType(filenameExtension: "keevo-backup") { panel.allowedContentTypes = [type] }
        panel.prompt = "选择"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? UInt64) ?? 0
        let modified = (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? Date()
        // 文件名不是 Keevo 的格式时（例如被改过名），时间取文件的修改时间
        let listed = listBackups(dir: url.deletingLastPathComponent().path).first { $0.path == url.path }
        other = listed ?? BackupInfo(
            path: url.path, createdMs: UInt64(max(0, modified.timeIntervalSince1970 * 1000)), kind: "manual", size: size
        )
        selected = url.path
        problem = nil
    }

    private func proceed() {
        guard let path = current, let backup = candidates.first(where: { $0.path == path }) else { return }
        if let problem = model.backupProblem(path) {
            self.problem = problem
            return
        }
        dismiss()
        // 等这个表单关闭后再打开确认
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { next(backup) }
    }
}

// MARK: - 恢复前确认

struct RestoreConfirmSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let backup: BackupInfo
    @ViewState private var working = false

    var body: some View {
        SheetScaffold(
            title: "从备份恢复？",
            subtitle: "恢复到「\(BackupText.when(backup.createdMs)) · \(BackupText.kind(backup.kind))」的备份。",
            systemImage: "arrow.uturn.backward",
            tint: KV.Colors.statusWarningFg,
            width: 520
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                KVCard {
                    CardRow(label: "备份时间") { Text(BackupText.full(backup.createdMs)).font(KV.Typography.body) } actions: {}
                    CardRowDivider()
                    CardRow(label: "内容") { Text("保险库数据库（加密）").font(KV.Typography.body) } actions: {}
                    CardRowDivider()
                    CardRow(label: "当前保险库") { Text("恢复前会再备份一份").font(KV.Typography.body) } actions: {}
                }
                Banner(
                    kind: .warning,
                    message: "备份之后的修改会被替换掉（可以从恢复前自动生成的备份找回）。恢复后需要用备份时的主密码解锁；这台 Mac 上的浏览器配对、命令行授权与解锁设置保持现在的状态。"
                )
                ErrorText()
            }
        } footer: {
            Button("取消") { dismiss() }
                .buttonStyle(.kvSecondary)
                .keyboardShortcut(.cancelAction)
            Button("恢复") {
                working = true
                Task {
                    if await model.restore(from: backup) { dismiss() }
                    working = false
                }
            }
            .buttonStyle(.kvPrimary)
            .disabled(working)
        }
    }
}
