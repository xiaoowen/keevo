// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 条目详情（docs/ux.md §2）：头部、提示、字段行、标签；编辑、历史与冲突在单独的面板中。

import AppKit
import KeevoKit
import SwiftUI

struct ItemDetailView: View {
    @Environment(AppModel.self) private var model
    let itemId: String
    @Binding var selectedItem: String?
    /// 新建条目后直接打开编辑器。
    var editOnAppear = false

    @ViewState private var detail: ItemDetail?
    @ViewState private var revealed: Set<String> = []
    /// 每次显示时的标记：30 秒后只隐藏仍是那一次显示的字段，避免更早的计时提前隐藏。
    @ViewState private var revealTokens: [String: UUID] = [:]
    @ViewState private var largeType: LargeTypeItem?
    @ViewState private var editing = false
    @ViewState private var showingHistory = false
    @ViewState private var showingConflicts = false
    @ViewState private var confirmPurge = false

    /// 秘密字段显示 30 秒后自动隐藏（docs/ux.md §5）。
    private static let revealDuration: Duration = .seconds(30)

    var body: some View {
        Group {
            if let detail {
                content(detail)
            } else {
                ContentUnavailableView("这个条目已不存在", systemImage: "questionmark.square.dashed")
            }
        }
        .onAppear {
            load()
            if editOnAppear, detail != nil { editing = true }
        }
        .onChange(of: model.dataVersion) { load() }
        // 切换条目、离开视图或窗口失去焦点时丢弃已解密的内容，隐藏显示中的秘密
        .onDisappear { detail = nil; revealed = []; largeType = nil }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didResignKeyNotification)) { _ in
            revealed = []
        }
        .sheet(item: $largeType) { item in LargeTypeView(value: item.value) }
        .sheet(isPresented: $editing) {
            if let detail { ItemEditorSheet(detail: detail, selectedItem: $selectedItem) }
        }
        .sheet(isPresented: $showingHistory) {
            HistorySheet(itemId: itemId)
        }
        .sheet(isPresented: $showingConflicts) {
            if let detail { ConflictSheet(detail: detail) }
        }
        .confirmationDialog("永久删除这个条目？", isPresented: $confirmPurge) {
            Button("永久删除", role: .destructive) {
                model.purge(itemId: itemId)
                selectedItem = nil
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("删除后无法从回收站恢复。")
        }
    }

    private func load() {
        detail = model.detail(of: itemId)
    }

    // MARK: - 内容

    private func content(_ d: ItemDetail) -> some View {
        Form {
            Section { header(d) }
            if hasNotice(d) {
                Section { notice(d) }
            }
            // 默认分区在前，然后是各个分区；不显示没有内容的字段
            let groups = fieldGroups(d)
            if groups.isEmpty {
                Section { Text("还没有填写任何字段").foregroundStyle(KV.Colors.fgSecondary) }
            }
            ForEach(groups, id: \.id) { group in
                Section {
                    ForEach(group.fields, id: \.id) { field in
                        FieldDisplay(
                            itemId: d.id,
                            field: field,
                            revealed: revealed,
                            toggle: toggle,
                            largeType: { largeType = LargeTypeItem(value: $0) }
                        )
                    }
                } header: {
                    if let label = group.label { Text(label) }
                }
            }
            if !d.tags.isEmpty {
                Section("标签") {
                    TagList(tags: d.tags)
                }
            }
        }
        .formStyle(.grouped)
        .toolbar {
            ToolbarItemGroup {
                if !d.trashed {
                    Button { editing = true } label: { Label("编辑", systemImage: "pencil") }
                        .keyboardShortcut("e")
                        .help("编辑（⌘E）")
                }
                Menu {
                    Button("历史版本…") { showingHistory = true }
                        .keyboardShortcut("y")
                    Divider()
                    if d.trashed {
                        Button("恢复") { model.restore(itemId: d.id) }
                        Button("永久删除…", role: .destructive) { confirmPurge = true }
                    } else {
                        Button("移入回收站") { model.trash(itemId: d.id) }
                            .keyboardShortcut(.delete)
                    }
                } label: {
                    Label("更多", systemImage: "ellipsis.circle")
                }
            }
        }
    }

    private func header(_ d: ItemDetail) -> some View {
        HStack(spacing: KV.Space.s3) {
            SiteIcon(title: d.title, url: d.fields.first { $0.kind == "url" }?.value.expose(), size: 40)
            VStack(alignment: .leading, spacing: KV.Space.s0_5) {
                Text(d.title.isEmpty ? "（无标题）" : d.title)
                    .font(KV.Typography.title)
                    .textSelection(.enabled)
                Label(ItemTypeInfo.name(d.itemType), systemImage: ItemTypeInfo.symbol(d.itemType))
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
            }
            Spacer()
            if !d.trashed {
                Button {
                    model.setFavorite(itemId: d.id, !d.favorite)
                } label: {
                    Image(systemName: d.favorite ? "star.fill" : "star")
                        .font(.title3)
                        .foregroundStyle(d.favorite ? KV.Colors.statusWarningFg : KV.Colors.fgTertiary)
                }
                .buttonStyle(.borderless)
                .help(d.favorite ? "取消收藏" : "收藏")
                .accessibilityLabel(d.favorite ? "取消收藏" : "收藏")
            }
        }
    }

    /// 需要用户注意的状态：回收站、冲突、撤销删除、完整性问题、并发头异常多（spec/revisions.md §5.4–§5.6、§7.1）。
    private struct FieldGroup {
        let id: String
        let label: String?
        let fields: [FieldEntry]
    }

    private func fieldGroups(_ d: ItemDetail) -> [FieldGroup] {
        let visible = d.fields.filter(FieldDisplay.hasContent)
        var groups = [FieldGroup(id: "", label: nil, fields: visible.filter { $0.sectionId == nil })]
        groups += d.sections.map { s in
            FieldGroup(id: s.id, label: s.label, fields: visible.filter { $0.sectionId == s.id })
        }
        return groups.filter { !$0.fields.isEmpty }
    }

    private func hasNotice(_ d: ItemDetail) -> Bool {
        d.trashed || !d.conflicts.isEmpty || d.resurrected || d.integrityIssues > 0 || d.headCount > 64
    }

    @ViewBuilder
    private func notice(_ d: ItemDetail) -> some View {
        if d.trashed {
            HStack {
                Banner(kind: .info, message: "这个条目在回收站中。")
                Button("恢复") { model.restore(itemId: d.id) }
                Button("永久删除…", role: .destructive) { confirmPurge = true }
            }
        } else if !d.conflicts.isEmpty || d.resurrected || d.integrityIssues > 0 {
            HStack {
                Banner(kind: .warning, message: conflictSummary(d))
                Button("处理…") { showingConflicts = true }
            }
        } else if d.headCount > 64 {
            Banner(kind: .info, message: "这个条目的并发修订异常多。编辑并保存一次即可合并。")
        }
    }

    private func conflictSummary(_ d: ItemDetail) -> String {
        var parts: [String] = []
        if d.resurrected { parts.append("另一台设备删除了这个条目，但这里有新的修改，已为你保留") }
        if !d.conflicts.isEmpty { parts.append("\(d.conflicts.count) 处修改与其他设备冲突") }
        if d.integrityIssues > 0 { parts.append("合并时发现 \(d.integrityIssues) 处来源不一致的内容") }
        return parts.joined(separator: "；") + "。"
    }

    private func toggle(_ id: String) {
        if revealed.contains(id) {
            revealed.remove(id)
            return
        }
        revealed.insert(id)
        let token = UUID()
        revealTokens[id] = token
        Task {
            try? await Task.sleep(for: Self.revealDuration)
            if revealTokens[id] == token { revealed.remove(id) }
        }
    }
}

struct LargeTypeItem: Identifiable {
    let value: String
    var id: String { "large-type" }
}

struct TagList: View {
    let tags: [String]

    var body: some View {
        HStack(spacing: KV.Space.s1_5) {
            ForEach(tags, id: \.self) { tag in
                Text(tag)
                    .font(KV.Typography.footnote)
                    .padding(.horizontal, KV.Space.s2)
                    .padding(.vertical, KV.Space.s0_5)
                    .background(KV.Colors.bgSunken, in: Capsule())
            }
        }
    }
}
