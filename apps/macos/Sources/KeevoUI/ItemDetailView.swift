// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 条目详情（docs/ux.md §2，设计稿“macOS · 主窗口”）：顶部操作、头部、提示、字段卡片、标签与修改时间；
// 编辑在详情栏中直接进行（ItemEditor）；历史与冲突在单独的面板中。

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
        VStack(spacing: 0) {
            if editing, let detail {
                ItemEditor(detail: detail, selectedItem: $selectedItem) {
                    editing = false
                    load()
                }
            } else if let detail {
                DetailTopBar { actions(detail) }
                ScrollView { content(detail) }
            } else {
                DetailTopBar { EmptyView() }
                EmptyState(symbol: "questionmark.square.dashed", title: "这个条目已不存在", message: "它可能已被永久删除。")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
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

    // MARK: - 顶部操作

    @ViewBuilder
    private func actions(_ d: ItemDetail) -> some View {
        if !d.trashed {
            Button {
                model.setFavorite(itemId: d.id, !d.favorite)
            } label: {
                Image(systemName: d.favorite ? "star.fill" : "star")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(d.favorite ? KV.Colors.statusWarningFg : KV.Colors.fgPrimary)
                    .frame(width: 14)
            }
            .buttonStyle(.kvBordered)
            .help(d.favorite ? "取消收藏" : "收藏")
            .accessibilityLabel(d.favorite ? "取消收藏" : "收藏")
            Button("编辑") { editing = true }
                .buttonStyle(.kvBordered)
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
            Image(systemName: "ellipsis").font(.system(size: 12, weight: .semibold)).frame(width: 14, height: 18)
        }
        .menuStyle(.button)
        .buttonStyle(.kvBordered)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("更多")
        .accessibilityLabel("更多操作")
    }

    // MARK: - 内容

    private func content(_ d: ItemDetail) -> some View {
        VStack(alignment: .leading, spacing: 18) {
            header(d)
            if hasNotice(d) { notice(d) }
            let groups = fieldGroups(d)
            if groups.isEmpty {
                Text("还没有填写任何字段。点「编辑」添加。")
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
            } else if d.itemType == "environment" {
                EnvironmentView(itemId: d.id, groups: groups, revealed: revealed, toggle: toggle)
            } else {
                ForEach(groups, id: \.id) { group in
                    VStack(alignment: .leading, spacing: KV.Space.s2) {
                        if let label = group.label { GroupTitle(text: label) }
                        FieldCard(itemId: d.id, fields: group.fields, revealed: revealed, toggle: toggle) {
                            largeType = LargeTypeItem(value: $0)
                        }
                    }
                }
            }
            if d.itemType == "ssh_key", !d.trashed {
                SshKeyAgentCard(itemId: d.id)
            }
            footer(d)
        }
        .padding(.horizontal, 28)
        .padding(.vertical, KV.Space.s6)
        .frame(maxWidth: 760, alignment: .leading)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func header(_ d: ItemDetail) -> some View {
        HStack(spacing: 14) {
            SiteIcon(title: d.title, url: d.fields.first { $0.kind == "url" }?.value.expose(), size: 48)
            VStack(alignment: .leading, spacing: 2) {
                Text(d.title.isEmpty ? "（无标题）" : d.title)
                    .font(KV.Typography.title)
                    .foregroundStyle(KV.Colors.fgPrimary)
                    .textSelection(.enabled)
                Text("\(ItemTypeInfo.name(d.itemType)) · \(vaultName(d.vaultId))")
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func vaultName(_ id: String) -> String {
        Self.vaultLabel(model.vaults.first { $0.id == id }?.name ?? "")
    }

    /// "个人" → "个人保险库"，"dev" → "dev 保险库"。
    static func vaultLabel(_ name: String) -> String {
        if name.isEmpty { return "保险库" }
        if name.hasSuffix("保险库") { return name }
        return name.unicodeScalars.last.map(\.isASCII) == true ? "\(name) 保险库" : "\(name)保险库"
    }

    private func footer(_ d: ItemDetail) -> some View {
        HStack(spacing: KV.Space.s2) {
            ForEach(d.tags, id: \.self) { Pill(text: $0) }
            Spacer(minLength: KV.Space.s3)
            Text(Self.relative(d.updatedMs) + "修改 ·")
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
            Button("\(d.revisionCount) 个历史版本") { showingHistory = true }
                .buttonStyle(.plain)
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.accentFg)
                .help("查看与恢复历史版本（⌘Y）")
        }
        .padding(.top, KV.Space.s1)
    }

    /// "刚刚"、"5 分钟前"、"3 天前"，更早的显示日期。
    static func relative(_ ms: UInt64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        let seconds = Date().timeIntervalSince(date)
        switch seconds {
        case ..<60: return "刚刚"
        case ..<3600: return "\(Int(seconds / 60)) 分钟前"
        case ..<86_400: return "\(Int(seconds / 3600)) 小时前"
        case ..<(86_400 * 30): return "\(Int(seconds / 86_400)) 天前"
        default: return date.formatted(.dateTime.year().month().day().locale(Locale(identifier: "zh_Hans"))) + " "
        }
    }

    struct FieldGroup {
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

    /// 需要用户注意的状态：回收站、冲突、撤销删除、完整性问题、并发头异常多（spec/revisions.md §5.4–§5.6、§7.1）。
    private func hasNotice(_ d: ItemDetail) -> Bool {
        d.trashed || !d.conflicts.isEmpty || d.resurrected || d.integrityIssues > 0 || d.headCount > 64
    }

    @ViewBuilder
    private func notice(_ d: ItemDetail) -> some View {
        if d.trashed {
            HStack(spacing: KV.Space.s2) {
                Banner(kind: .info, message: "这个条目在回收站中。")
                Button("恢复") { model.restore(itemId: d.id) }.buttonStyle(.kvBordered)
                Button("永久删除…") { confirmPurge = true }.buttonStyle(.kvBordered)
            }
        } else if !d.conflicts.isEmpty || d.resurrected || d.integrityIssues > 0 {
            HStack(spacing: KV.Space.s2) {
                Banner(kind: .warning, message: conflictSummary(d))
                Button("处理…") { showingConflicts = true }.buttonStyle(.kvBordered)
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
