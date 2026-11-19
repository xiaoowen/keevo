// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 附件（设计稿"macOS · 附件"，spec/crypto.md §8.9）：条目详情中的附件列表、添加（选择文件或拖放）、
// 用"快速查看"预览、保存、删除。文件由 Rust 直接读写；预览写到 Keevo 数据目录中的私有文件夹，
// 预览结束、锁定与下次启动时删除。

import AppKit
import KeevoKit
import QuickLook
import SwiftUI
import UniformTypeIdentifiers

// MARK: - 模型

extension AppModel {
    /// 预览用的私有文件夹（数据目录下的 preview，0700）。
    var previewFolder: String {
        ((defaultBackupFolder as NSString).deletingLastPathComponent as NSString).appendingPathComponent("preview")
    }

    func clearPreviews() {
        try? FileManager.default.removeItem(atPath: previewFolder)
    }

    /// 添加附件。超过 50 MB 时返回文件名与大小，由界面说明；其他错误显示在错误提示中。
    func addAttachments(itemId: String, urls: [URL]) async -> (name: String, size: Int64)? {
        guard let vault else { return nil }
        var tooBig: (String, Int64)?
        for url in urls {
            let path = url.path
            do {
                _ = try await Task.detached { try vault.addAttachment(itemId: itemId, path: path) }.value
            } catch KeevoError.Attachment(let code) where code == "too_large" {
                let size = (try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int64) ?? 0
                tooBig = (url.lastPathComponent, size)
            } catch KeevoError.Attachment {
                errorMessage = "无法读取「\(url.lastPathComponent)」。文件夹不能作为附件。"
            } catch {
                report(error)
            }
        }
        reloadAfterBrowserWrite()
        return tooBig
    }

    func removeAttachment(itemId: String, fieldId: String) {
        guard let vault else { return }
        do {
            try vault.updateItem(itemId: itemId, edits: [.removeField(fieldId: fieldId)])
            reloadAfterBrowserWrite()
            showToast("已删除附件")
        } catch {
            report(error)
        }
    }

    func saveAttachment(itemId: String, attachment: AttachmentEntry) {
        guard let vault else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = attachment.name
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try vault.saveAttachment(itemId: itemId, attachmentId: attachment.id, path: url.path)
            showToast("已保存「\(attachment.name)」")
        } catch {
            report(error)
        }
    }

    /// 写出到预览文件夹，返回文件 URL。
    func previewURL(itemId: String, attachment: AttachmentEntry) -> URL? {
        guard let vault else { return nil }
        let dir = (previewFolder as NSString).appendingPathComponent(UUID().uuidString)
        do {
            let path = try vault.previewAttachment(itemId: itemId, attachmentId: attachment.id, dir: dir, name: attachment.name)
            return URL(fileURLWithPath: path)
        } catch {
            report(error)
            return nil
        }
    }
}

enum AttachmentText {
    static func symbol(_ name: String) -> String {
        let ext = (name as NSString).pathExtension.lowercased()
        guard let type = UTType(filenameExtension: ext) else { return "doc" }
        if type.conforms(to: .image) { return "photo" }
        if type.conforms(to: .pdf) { return "doc.richtext" }
        if type.conforms(to: .archive) { return "archivebox" }
        if type.conforms(to: .text) || ["pem", "crt", "key", "pub", "env"].contains(ext) { return "doc.text" }
        return "doc"
    }

    static func detail(_ a: AttachmentEntry) -> String {
        let size = ByteCountFormatter.string(fromByteCount: Int64(clamping: a.size), countStyle: .file)
        guard a.addedMs > 0 else { return size }
        let date = Date(timeIntervalSince1970: TimeInterval(a.addedMs) / 1000)
        let c = Calendar.current.dateComponents([.year, .month, .day], from: date)
        let sameYear = c.year == Calendar.current.component(.year, from: Date())
        return "\(size) · " + (sameYear ? "" : "\(c.year ?? 0)年") + "\(c.month ?? 0)月\(c.day ?? 0)日添加"
    }
}

// MARK: - 条目详情中的附件

extension FieldEntry: Identifiable {}

struct AttachmentsSection: View {
    @Environment(AppModel.self) private var model
    let itemId: String
    let title: String
    let fields: [FieldEntry]
    @Binding var tooBig: TooBigAttachment?
    @ViewState private var deleting: FieldEntry?
    @ViewState private var preview: URL?

    var body: some View {
        VStack(alignment: .leading, spacing: KV.Space.s2) {
            HStack {
                GroupTitle(text: fields.isEmpty ? "附件" : "附件（\(fields.count)）")
                Spacer()
                Button { choose() } label: { Label("添加附件…", systemImage: "plus") }
                    .buttonStyle(.kvLink)
            }
            if !fields.isEmpty {
                KVCard {
                    ForEach(Array(fields.enumerated()), id: \.element.id) { index, f in
                        if index > 0 { CardRowDivider() }
                        if let a = f.attachment { row(f, a) }
                    }
                }
            }
            Text("附件与条目一起加密保存在这台 Mac 上；单个文件最大 50 MB。也可以把文件拖到这里。")
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .quickLookPreview($preview)
        .onChange(of: preview) { if preview == nil { model.clearPreviews() } }
        .sheet(item: $deleting) { f in
            DeleteAttachmentSheet(name: f.attachment?.name ?? f.label) {
                model.removeAttachment(itemId: itemId, fieldId: f.id)
            }
        }
    }

    private func row(_ f: FieldEntry, _ a: AttachmentEntry) -> some View {
        HStack(spacing: 10) {
            Image(systemName: AttachmentText.symbol(a.name))
                .font(.system(size: 14))
                .foregroundStyle(KV.Colors.fgSecondary)
                .frame(width: 30, height: 30)
                .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(f.label).font(KV.Typography.bodyStrong).lineLimit(1).truncationMode(.middle)
                Text(AttachmentText.detail(a)).font(KV.Typography.caption).foregroundStyle(KV.Colors.fgSecondary)
            }
            Spacer(minLength: KV.Space.s2)
            Button("预览") { preview = model.previewURL(itemId: itemId, attachment: a) }
                .buttonStyle(.kvLink)
            Button("保存…") { model.saveAttachment(itemId: itemId, attachment: a) }
                .buttonStyle(.kvLink)
            Menu {
                Button("删除附件…", role: .destructive) { deleting = f }
            } label: {
                Image(systemName: "ellipsis").foregroundStyle(KV.Colors.fgSecondary)
            }
            .menuStyle(.button)
            .buttonStyle(.plain)
            .menuIndicator(.hidden)
            .fixedSize()
            .accessibilityLabel("更多操作")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.prompt = "添加"
        panel.message = "选择要添加到「\(title)」的文件。"
        guard panel.runModal() == .OK else { return }
        let urls = panel.urls
        Task {
            if let big = await model.addAttachments(itemId: itemId, urls: urls) {
                tooBig = TooBigAttachment(name: big.name, size: big.size)
            }
        }
    }
}

/// 拖放到条目详情时的提示（设计稿）。
struct AttachmentDropOverlay: View {
    let title: String

    var body: some View {
        VStack(spacing: 6) {
            Image(systemName: "paperclip").font(.system(size: 22)).foregroundStyle(KV.Colors.accentFg)
            Text("松开即可添加到「\(title)」").font(KV.Typography.bodyStrong).foregroundStyle(KV.Colors.accentFg)
            Text("可以一次添加多个文件").font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(KV.Colors.accentSubtle.opacity(0.92), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(KV.Colors.focusRing, style: StrokeStyle(lineWidth: 2, dash: [6, 4]))
        )
        .padding(KV.Space.s4)
        .allowsHitTesting(false)
    }
}

struct TooBigAttachment: Identifiable {
    let name: String
    let size: Int64
    var id: String { name }
}

struct TooBigAttachmentSheet: View {
    @Environment(\.dismiss) private var dismiss
    let file: TooBigAttachment

    var body: some View {
        SheetScaffold(
            title: "无法添加「\(file.name)」",
            subtitle: "这个文件有 \(ByteCountFormatter.string(fromByteCount: file.size, countStyle: .file))，超过了单个附件 50 MB 的上限。",
            systemImage: "exclamationmark.triangle",
            tint: KV.Colors.statusWarningFg,
            width: 460
        ) {
            Text("大文件请放在加密磁盘或其他位置；在条目中记录它的位置即可。")
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
                .fixedSize(horizontal: false, vertical: true)
        } footer: {
            Button("好") { dismiss() }
                .buttonStyle(.kvPrimary)
                .keyboardShortcut(.defaultAction)
        }
    }
}

struct DeleteAttachmentSheet: View {
    @Environment(\.dismiss) private var dismiss
    let name: String
    let confirm: () -> Void

    var body: some View {
        SheetScaffold(
            title: "删除附件「\(name)」？",
            subtitle: "删除后不再出现在条目中。",
            systemImage: "trash",
            tint: KV.Colors.statusDangerFg,
            width: 460
        ) {
            Text("附件保留在条目的历史版本中，可以通过「恢复到此版本」找回；清理历史后彻底删除。")
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
                .fixedSize(horizontal: false, vertical: true)
        } footer: {
            Button("取消") { dismiss() }.buttonStyle(.kvSecondary).keyboardShortcut(.cancelAction)
            Button("删除") {
                confirm()
                dismiss()
            }
            .buttonStyle(KVButtonStyle(kind: .danger))
        }
    }
}
