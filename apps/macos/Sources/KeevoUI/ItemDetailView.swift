// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 条目详情（docs/ux.md §2，设计稿"条目的展示、编辑与新建"）：顶部的无边框操作、大图标与标题、提示、字段卡片，
// 卡片下方是网站、备注、各分区、安全问题、标签、附件与"最后编辑"；编辑在详情栏中直接进行（ItemEditor）；
// 历史与冲突在单独的面板中。

import AppKit
import KeevoKit
import SwiftUI
import UniformTypeIdentifiers

struct ItemDetailView: View {
    @Environment(AppModel.self) private var model
    let itemId: String
    @Binding var selectedItem: String?
    /// 新建条目后直接打开编辑器。
    var editOnAppear = false

    @ViewState private var detail: ItemDetail?
    /// 安全中心对这个条目的检查结果（"安全"区）。
    @ViewState private var security: ItemSecurity?
    @ViewState private var revealed: Set<String> = []
    /// 每次显示时的标记：30 秒后只隐藏仍是那一次显示的字段，避免更早的计时提前隐藏。
    @ViewState private var revealTokens: [String: UUID] = [:]
    @ViewState private var largeType: LargeTypeItem?
    @ViewState private var editing = false
    @ViewState private var showingHistory = false
    @ViewState private var showingConflicts = false
    @ViewState private var confirmPurge = false
    /// "最后编辑"展开后显示历史版本的入口。
    @ViewState private var showingEdited = false
    /// 附件：拖放提示与超过上限的说明。
    @ViewState private var dropTargeted = false
    @ViewState private var tooBig: TooBigAttachment?

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
                    // 把文件拖到详情上即添加为附件（设计稿"macOS · 附件"）
                    .onDrop(of: [.fileURL], isTargeted: $dropTargeted) { providers in
                        guard !detail.trashed else { return false }
                        dropFiles(providers, itemId: detail.id)
                        return true
                    }
                    .overlay { if dropTargeted, !detail.trashed { AttachmentDropOverlay(title: detail.title) } }
            } else {
                DetailTopBar { EmptyView() }
                EmptyState(symbol: "questionmark.square.dashed", title: tr("这个条目已不存在"), message: tr("它可能已被永久删除。"))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .onAppear {
            load()
            if editOnAppear, detail != nil { editing = true }
        }
        .onChange(of: model.dataVersion) { load() }
        .onChange(of: model.securityVersion) { security = model.itemSecurity(itemId) }
        // 切换条目、离开视图或窗口失去焦点时丢弃已解密的内容，隐藏显示中的秘密
        .onDisappear { detail = nil; revealed = []; largeType = nil }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didResignKeyNotification)) { _ in
            revealed = []
        }
        .sheet(item: $largeType) { item in LargeTypeView(value: item.value) }
        .sheet(item: $tooBig) { TooBigAttachmentSheet(file: $0) }
        .sheet(isPresented: $showingHistory) {
            HistorySheet(itemId: itemId)
        }
        .sheet(isPresented: $showingConflicts) {
            if let detail { ConflictSheet(detail: detail) }
        }
        .confirmationDialog(tr("永久删除这个条目？"), isPresented: $confirmPurge) {
            Button(tr("永久删除"), role: .destructive) {
                model.purge(itemId: itemId)
                selectedItem = nil
            }
            Button(tr("取消"), role: .cancel) {}
        } message: {
            Text(tr("删除后无法从回收站恢复。"))
        }
    }

    private func load() {
        detail = model.detail(of: itemId)
        security = model.itemSecurity(itemId)
    }

    // MARK: - 顶部操作

    @ViewBuilder
    private func actions(_ d: ItemDetail) -> some View {
        if !d.trashed {
            Button {
                model.setFavorite(itemId: d.id, !d.favorite)
            } label: {
                Image(systemName: d.favorite ? "star.fill" : "star")
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(d.favorite ? KV.Colors.statusWarningFg : KV.Colors.fgPrimary)
            }
            .buttonStyle(.kvToolbar)
            .help(d.favorite ? tr("取消收藏") : tr("收藏"))
            .accessibilityLabel(d.favorite ? tr("取消收藏") : tr("收藏"))
            Button(tr("编辑")) { editing = true }
                .buttonStyle(.kvToolbarAccent)
                .keyboardShortcut("e")
                .help(tr("编辑（⌘E）"))
        }
        Menu {
            Button(tr("历史版本…")) { showingHistory = true }
                .keyboardShortcut("y")
            Divider()
            if d.trashed {
                Button(tr("恢复")) { model.restore(itemId: d.id) }
                Button(tr("永久删除…"), role: .destructive) { confirmPurge = true }
            } else {
                Button(tr("移入回收站")) { model.trash(itemId: d.id) }
                    .keyboardShortcut(.delete)
            }
        } label: {
            Image(systemName: "ellipsis").font(.system(size: 14, weight: .medium)).frame(height: 18)
        }
        .menuStyle(.button)
        .buttonStyle(.kvToolbar)
        .menuIndicator(.hidden)
        .fixedSize()
        .help(tr("更多"))
        .accessibilityLabel(tr("更多操作"))
    }

    // MARK: - 内容

    private func content(_ d: ItemDetail) -> some View {
        VStack(alignment: .leading, spacing: 20) {
            header(d)
            if hasNotice(d) { notice(d) }
            let groups = fieldGroups(d)
            if groups.isEmpty {
                Text(tr("还没有填写任何字段"))
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
            } else if d.itemType == "environment" {
                EnvironmentView(itemId: d.id, groups: groups, revealed: revealed, toggle: toggle) {
                    largeType = LargeTypeItem(value: $0)
                }
            } else {
                ForEach(groups, id: \.id) { group in
                    if group.label == nil {
                        defaultGroup(d, group.fields)
                    } else {
                        VStack(alignment: .leading, spacing: KV.Space.s2) {
                            if let label = group.label { GroupTitle(text: label) }
                            FieldCard(itemId: d.id, fields: group.fields, revealed: revealed, toggle: toggle) {
                                largeType = LargeTypeItem(value: $0)
                            }
                        }
                    }
                }
            }
            if d.itemType == "ssh_key", !d.trashed {
                SshKeyAgentCard(itemId: d.id)
            }
            if !d.trashed {
                ItemSecuritySection(itemId: d.id, info: security) { editing = true }
            }
            if !d.tags.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    FieldLabel(text: tr("标签"))
                    FlowLayout { ForEach(d.tags, id: \.self) { Pill(text: $0) } }
                }
                .padding(.horizontal, 14)
            }
            if !d.trashed {
                AttachmentsSection(
                    itemId: d.id,
                    title: d.title,
                    fields: d.fields.filter { $0.kind == "attachment" },
                    tooBig: $tooBig
                )
            }
            footer(d)
        }
        .padding(.horizontal, 28)
        .padding(.vertical, KV.Space.s6)
        .frame(maxWidth: 760, alignment: .leading)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// 默认分区（设计稿）：常用字段在卡片里，网站与备注在卡片下方。
    @ViewBuilder
    private func defaultGroup(_ d: ItemDetail, _ fields: [FieldEntry]) -> some View {
        let card = fields.filter { $0.kind != "url" && $0.purpose != "notes" }
        let urls = fields.filter { $0.kind == "url" }
        if !card.isEmpty {
            FieldCard(itemId: d.id, fields: card, revealed: revealed, toggle: toggle, strength: security?.strength) {
                largeType = LargeTypeItem(value: $0)
            }
        }
        if !urls.isEmpty { WebsitesBlock(itemId: d.id, fields: urls) }
        ForEach(fields.filter { $0.purpose == "notes" }, id: \.id) { NotesBlock(field: $0) }
    }

    private func header(_ d: ItemDetail) -> some View {
        HStack(spacing: KV.Space.s4) {
            SiteIcon(title: d.title, url: d.fields.first { $0.kind == "url" }?.value.expose(), size: 60)
            Text(d.title.isEmpty ? tr("（无标题）") : d.title)
                .font(.system(size: 22, weight: .bold))
                .foregroundStyle(KV.Colors.fgPrimary)
                .textSelection(.enabled)
        }
        .help("\(ItemTypeInfo.name(d.itemType)) · \(Self.vaultLabel(model.vaults.first { $0.id == d.vaultId }?.name ?? ""))")
        .accessibilityElement(children: .combine)
    }

    /// "个人" → "个人保险库"，"dev" → "dev 保险库"。
    static func vaultLabel(_ name: String) -> String {
        // 默认保险库名是数据（"个人"）：按界面语言显示
        let name = tr(name)
        if name.isEmpty { return tr("保险库") }
        if name.hasSuffix(tr("保险库")) { return name }
        return name.unicodeScalars.last.map(\.isASCII) == true ? tr("{} 保险库", "\(name)") : tr("{}保险库", "\(name)")
    }

    /// "› 最后编辑 2026年11月24日星期二 14:52:39"，点开后显示历史版本的入口（设计稿）。
    private func footer(_ d: ItemDetail) -> some View {
        VStack(alignment: .leading, spacing: KV.Space.s2) {
            Button { withAnimation(.easeOut(duration: 0.15)) { showingEdited.toggle() } } label: {
                HStack(spacing: KV.Space.s1_5) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .rotationEffect(.degrees(showingEdited ? 90 : 0))
                    Text(tr("最后编辑 {}", Self.fullDate(d.updatedMs)))
                }
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if showingEdited {
                Button(tr("{} 个历史版本", "\(d.revisionCount)")) { showingHistory = true }
                    .buttonStyle(.kvLink)
                    .help(tr("查看与恢复历史版本（⌘Y）"))
                    .padding(.leading, 18)
            }
        }
        .padding(.horizontal, 14)
        .padding(.top, KV.Space.s1)
    }

    /// 完整的日期与时间，精确到秒，按界面语言显示（"2026年11月24日星期二 14:52:39"）。
    static func fullDate(_ ms: UInt64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        let locale = Locale(identifier: UILanguage.current == .zh ? "zh_Hans" : "en_US")
        return date.formatted(.dateTime.year().month(.wide).day().weekday(.wide).hour().minute().second().locale(locale))
    }

    /// "刚刚"、"5 分钟前"、"3 天前"，更早的显示日期。
    static func relative(_ ms: UInt64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        let seconds = Date().timeIntervalSince(date)
        switch seconds {
        case ..<60: return tr("刚刚")
        case ..<3600: return tr("{} 分钟前", "\(Int(seconds / 60))")
        case ..<86_400: return tr("{} 小时前", "\(Int(seconds / 3600))")
        case ..<(86_400 * 30): return tr("{} 天前", "\(Int(seconds / 86_400))")
        default: return date.formatted(.dateTime.year().month().day().locale(Locale(identifier: "zh_Hans"))) + " "
        }
    }

    private func dropFiles(_ providers: [NSItemProvider], itemId: String) {
        Task {
            var urls: [URL] = []
            for p in providers {
                if let url = try? await p.loadItem(forTypeIdentifier: UTType.fileURL.identifier) as? Data,
                   let u = URL(dataRepresentation: url, relativeTo: nil) {
                    urls.append(u)
                }
            }
            guard !urls.isEmpty else { return }
            if let big = await model.addAttachments(itemId: itemId, urls: urls) {
                tooBig = TooBigAttachment(name: big.name, size: big.size)
            }
        }
    }

    struct FieldGroup {
        let id: String
        let label: String?
        let fields: [FieldEntry]
    }

    private func fieldGroups(_ d: ItemDetail) -> [FieldGroup] {
        // 附件在单独的"附件"区中
        let visible = d.fields.filter { FieldDisplay.hasContent($0) && $0.kind != "attachment" }
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
                Banner(kind: .info, message: tr("这个条目在回收站中。"))
                Button(tr("恢复")) { model.restore(itemId: d.id) }.buttonStyle(.kvBordered)
                Button(tr("永久删除…")) { confirmPurge = true }.buttonStyle(.kvBordered)
            }
        } else if !d.conflicts.isEmpty || d.resurrected || d.integrityIssues > 0 {
            HStack(spacing: KV.Space.s2) {
                Banner(kind: .warning, message: conflictSummary(d))
                Button(tr("处理…")) { showingConflicts = true }.buttonStyle(.kvBordered)
            }
        } else if d.headCount > 64 {
            Banner(kind: .info, message: tr("这个条目的并发修订异常多。编辑并保存一次即可合并。"))
        }
    }

    private func conflictSummary(_ d: ItemDetail) -> String {
        var parts: [String] = []
        if d.resurrected { parts.append(tr("另一台设备删除了这个条目，但这里有新的修改，已为你保留")) }
        if !d.conflicts.isEmpty { parts.append(tr("{} 处修改与其他设备冲突", "\(d.conflicts.count)")) }
        if d.integrityIssues > 0 { parts.append(tr("合并时发现 {} 处来源不一致的内容", "\(d.integrityIssues)")) }
        return parts.joined(separator: tr("；")) + tr("。")
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
