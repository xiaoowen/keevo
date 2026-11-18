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
        VStack(alignment: .leading, spacing: KV.Space.s3) {
            Text("历史版本").font(.title3.weight(.semibold))
            Text("最近 20 个版本，以及 90 天内（按 Keevo 的运行时间计）的全部版本会保留内容；更早的只保留修订记录。")
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
            HSplitView {
                List(history, id: \.revId, selection: $selected) { entry in
                    row(entry)
                }
                .frame(minWidth: 220, idealWidth: 240)
                preview
                    .frame(minWidth: 300, maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
            HStack {
                Spacer()
                Button("关闭") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("恢复到此版本…") { confirmRestore = true }
                    .disabled(fields == nil || isLatest)
            }
        }
        .padding(24)
        .frame(width: 720, height: 500)
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
        VStack(alignment: .leading, spacing: KV.Space.s0_5) {
            HStack(spacing: KV.Space.s1) {
                if entry.revId == history.first?.revId {
                    Text("最新").font(KV.Typography.caption).foregroundStyle(KV.Colors.accentFg)
                }
                Text(entry.title ?? (entry.deleted ? "（永久删除）" : "（内容已清理）"))
                    .font(KV.Typography.body)
                    .lineLimit(1)
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
    }

    @ViewBuilder
    private var preview: some View {
        if let entry = selectedEntry, entry.deleted || entry.pruned {
            ContentUnavailableView(
                entry.deleted ? "永久删除" : "内容已清理",
                systemImage: "clock.badge.xmark",
                description: Text(entry.deleted ? "这是永久删除留下的记录，没有内容。" : "这个版本已超出保留期，只保留了修订记录。")
            )
        } else if let fields {
            Form {
                ForEach(fields, id: \.id) { field in
                    LabeledContent(field.label) {
                        if field.concealed {
                            HStack {
                                SecretText(secret: field.value, revealed: revealed.contains(field.id))
                                Button(revealed.contains(field.id) ? "隐藏" : "显示") {
                                    if revealed.contains(field.id) { revealed.remove(field.id) } else { revealed.insert(field.id) }
                                }
                                .buttonStyle(.borderless)
                            }
                        } else {
                            Text(field.value.expose()).textSelection(.enabled)
                        }
                    }
                }
            }
            .formStyle(.grouped)
        } else {
            ContentUnavailableView("选择一个版本", systemImage: "clock.arrow.circlepath")
        }
    }
}
