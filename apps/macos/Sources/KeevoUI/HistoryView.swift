// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 历史版本（spec/revisions.md §7.2）：列出每次写入，查看旧版本的字段，"恢复到此版本"作为一次新的编辑写入。

import KeevoKit
import SwiftUI

struct HistorySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let itemId: String

    @ViewState private var history: [HistoryItem] = []
    @ViewState private var selected: String?
    @ViewState private var fields: [FieldEntry]?
    @ViewState private var revealed: Set<String> = []
    @ViewState private var confirmRestore = false

    private static let dateFormat: Date.FormatStyle = .dateTime.year().month().day().hour().minute()

    private var selectedEntry: HistoryItem? { history.first { $0.revId == selected } }
    private var isLatest: Bool { selected != nil && selected == history.first?.revId }

    var body: some View {
        SheetScaffold(
            title: "历史版本",
            subtitle: "最近 20 个版本，以及 90 天内（按 Keevo 的运行时间计）的全部版本会保留内容；更早的只保留修订记录。",
            systemImage: "clock.arrow.circlepath",
            width: 760
        ) {
            HStack(alignment: .top, spacing: KV.Space.s4) {
                ScrollView {
                    LazyVStack(spacing: 2) {
                        ForEach(history, id: \.revId) { entry in
                            row(entry)
                                .onTapGesture { selected = entry.revId }
                        }
                    }
                    .padding(KV.Space.s1_5)
                }
                .frame(width: 250)
                .background(KV.Colors.bgSurface, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                ScrollView {
                    preview
                        .frame(maxWidth: .infinity, alignment: .topLeading)
                }
            }
            .frame(height: 340)
        } footer: {
            Button("关闭") { dismiss() }
                .buttonStyle(.kvSecondary)
                .keyboardShortcut(.cancelAction)
            Button("恢复到此版本…") { confirmRestore = true }
                .buttonStyle(.kvPrimary)
                .disabled(fields == nil || isLatest)
        }
        .onAppear {
            history = model.history(of: itemId)
            selected = history.first?.revId
        }
        .onChange(of: selected) {
            revealed = []
            guard let entry = selectedEntry, !entry.deleted, !entry.pruned else {
                fields = nil
                return
            }
            fields = model.revisionFields(itemId: itemId, revId: entry.revId)
        }
        .onDisappear { fields = nil; revealed = [] }
        .confirmationDialog("恢复到这个版本？", isPresented: $confirmRestore) {
            Button("恢复") {
                if let id = selected { model.restoreVersion(itemId: itemId, revId: id) }
                dismiss()
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("这个版本的内容会作为一次新的修改保存；当前的内容仍然留在历史中，可以再恢复回来。")
        }
    }

    private func row(_ entry: HistoryItem) -> some View {
        let isSelected = entry.revId == selected
        return VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: KV.Space.s1_5) {
                Text(entry.title ?? (entry.deleted ? "（永久删除）" : "（内容已清理）"))
                    .font(isSelected ? KV.Typography.bodyStrong : KV.Typography.body)
                    .foregroundStyle(entry.title == nil ? KV.Colors.fgSecondary : KV.Colors.fgPrimary)
                    .lineLimit(1)
                if entry.revId == history.first?.revId {
                    Text("当前")
                        .font(KV.Typography.caption.weight(.semibold))
                        .foregroundStyle(KV.Colors.accentFg)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(KV.Colors.accentSubtle, in: Capsule())
                }
            }
            HStack(spacing: KV.Space.s1) {
                if let ms = entry.updatedMs {
                    Text(Date(timeIntervalSince1970: TimeInterval(ms) / 1000), format: Self.dateFormat)
                }
                if entry.merge {
                    Text("· 合并了多台设备的修改")
                }
            }
            .font(KV.Typography.caption)
            .foregroundStyle(KV.Colors.fgSecondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, KV.Space.s2)
        .padding(.vertical, 7)
        .background(isSelected ? KV.Colors.bgSelected : .clear, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(isSelected ? [.isButton, .isSelected] : .isButton)
    }

    @ViewBuilder
    private var preview: some View {
        if let entry = selectedEntry, entry.deleted || entry.pruned {
            EmptyState(
                symbol: "clock.badge.xmark",
                title: entry.deleted ? "永久删除" : "内容已清理",
                message: entry.deleted ? "这是永久删除留下的记录，没有内容。" : "这个版本已超出保留期，只保留了修订记录。"
            )
            .frame(maxWidth: .infinity, minHeight: 300)
        } else if let fields {
            let shown = fields.filter(FieldDisplay.hasContent)
            if shown.isEmpty {
                EmptyState(symbol: "doc", title: "没有字段", message: "这个版本只有标题。")
                    .frame(maxWidth: .infinity, minHeight: 300)
            } else {
                KVCard {
                    ForEach(Array(shown.enumerated()), id: \.element.id) { index, field in
                        if index > 0 { CardRowDivider() }
                        CardRow(label: field.label, multiline: true) {
                            if field.concealed || field.kind == "totp" {
                                SecretText(secret: field.value, revealed: revealed.contains(field.id))
                            } else {
                                Text(field.value.expose())
                                    .font(KV.Typography.body)
                                    .foregroundStyle(KV.Colors.fgPrimary)
                                    .textSelection(.enabled)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        } actions: {
                            if field.concealed || field.kind == "totp" {
                                Button(revealed.contains(field.id) ? "隐藏" : "显示") {
                                    if revealed.contains(field.id) { revealed.remove(field.id) } else { revealed.insert(field.id) }
                                }
                                .buttonStyle(.kvLink)
                            }
                        }
                    }
                }
            }
        } else {
            EmptyState(symbol: "clock.arrow.circlepath", title: "选择一个版本", message: "在左侧选择一个版本查看内容。")
                .frame(maxWidth: .infinity, minHeight: 300)
        }
    }
}
