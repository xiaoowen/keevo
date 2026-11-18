// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 三栏主界面：侧边栏 → 条目列表 → 条目详情（docs/ux.md §2）。

import KeevoKit
import SwiftUI

/// 侧边栏的选择。
enum SidebarItem: Hashable {
    case all
    case favorites
    case type(String)
    case vault(String)
    case tag(String)
    case trash

    var title: String {
        switch self {
        case .all: "全部条目"
        case .favorites: "收藏"
        case .type(let t): ItemTypeInfo.name(t)
        case .vault: "保险库"
        case .tag(let t): t
        case .trash: "最近删除"
        }
    }
}

struct MainView: View {
    @Environment(AppModel.self) private var model
    @ViewState private var sidebar: SidebarItem? = .all
    @ViewState private var selectedItem: String?
    @ViewState private var search = ""
    @ViewState private var showingNewLogin = false

    private var selection: SidebarItem { sidebar ?? .all }

    private func matches(_ item: ItemEntry, _ s: SidebarItem) -> Bool {
        switch s {
        case .trash: return item.trashed
        case _ where item.trashed: return false
        case .all: return true
        case .favorites: return item.favorite
        case .type(let t): return item.itemType == t
        case .vault(let v): return item.vaultId == v
        case .tag(let t): return item.tags.contains(t)
        }
    }

    private var visibleItems: [ItemEntry] {
        let query = search.trimmingCharacters(in: .whitespaces)
        return model.items
            .filter { matches($0, selection) }
            .filter { item in
                query.isEmpty
                    || item.title.localizedCaseInsensitiveContains(query)
                    || item.subtitle.localizedCaseInsensitiveContains(query)
                    || item.urls.contains { $0.localizedCaseInsensitiveContains(query) }
                    || item.tags.contains { $0.localizedCaseInsensitiveContains(query) }
            }
            .sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
    }

    private func count(_ s: SidebarItem) -> Int {
        model.items.reduce(0) { $0 + (matches($1, s) ? 1 : 0) }
    }

    var body: some View {
        NavigationSplitView {
            sidebarList
                .navigationSplitViewColumnWidth(min: 190, ideal: 210)
        } content: {
            itemList
                .navigationSplitViewColumnWidth(min: 250, ideal: 290)
        } detail: {
            if let id = selectedItem, model.items.contains(where: { $0.id == id }) {
                ItemDetailView(itemId: id, selectedItem: $selectedItem).id(id)
            } else {
                ContentUnavailableView("选择一个条目", systemImage: "sidebar.right")
            }
        }
        .toolbar {
            ToolbarItem {
                Button { showingNewLogin = true } label: { Label("新建登录", systemImage: "plus") }
                    .keyboardShortcut("n")
                    .disabled(model.vaults.isEmpty)
            }
            ToolbarItem {
                Button { model.lock() } label: { Label("锁定", systemImage: "lock") }
                    .help("立即锁定（⇧⌘L）")
            }
        }
        .sheet(isPresented: $showingNewLogin) {
            NewLoginSheet(defaultVault: defaultVault) { id in selectedItem = id }
        }
        .sheet(item: Binding(
            get: { model.pendingSecretKey.map(SecretKeyItem.init) },
            set: { if $0 == nil { model.pendingSecretKey = nil } }
        )) { key in
            SecretKeySheet(secretKey: key.value).interactiveDismissDisabled()
        }
        .onChange(of: sidebar) { selectedItem = nil }
    }

    private var defaultVault: String? {
        if case .vault(let v) = selection { return v }
        return model.vaults.first?.id
    }

    // MARK: - 侧边栏

    private var presentTypes: [String] {
        let types = Set(model.items.filter { !$0.trashed }.map(\.itemType))
        return ItemTypeInfo.order.filter(types.contains)
    }

    private var allTags: [String] {
        Set(model.items.filter { !$0.trashed }.flatMap(\.tags))
            .sorted { $0.localizedStandardCompare($1) == .orderedAscending }
    }

    private var sidebarList: some View {
        List(selection: $sidebar) {
            sidebarRow(.all, "全部条目", "square.grid.2x2")
            sidebarRow(.favorites, "收藏", "star")
            if !presentTypes.isEmpty {
                Section("分类") {
                    ForEach(presentTypes, id: \.self) { t in
                        sidebarRow(.type(t), ItemTypeInfo.name(t), ItemTypeInfo.symbol(t))
                    }
                }
            }
            Section("保险库") {
                ForEach(model.vaults, id: \.id) { v in
                    sidebarRow(.vault(v.id), v.name, "lock.rectangle.stack")
                }
            }
            if !allTags.isEmpty {
                Section("标签") {
                    ForEach(allTags, id: \.self) { t in
                        sidebarRow(.tag(t), t, "tag")
                    }
                }
            }
            Section {
                sidebarRow(.trash, "最近删除", "trash")
            }
        }
    }

    private func sidebarRow(_ item: SidebarItem, _ title: String, _ symbol: String) -> some View {
        let n = count(item)
        return Label(title, systemImage: symbol)
            .badge(n > 0 ? n : 0)
            .tag(item)
    }

    // MARK: - 条目列表

    private var itemList: some View {
        List(visibleItems, id: \.id, selection: $selectedItem) { item in
            ItemRow(item: item)
                .contextMenu { rowMenu(item) }
        }
        .searchable(text: $search, prompt: "搜索标题、用户名、网址、标签")
        .navigationTitle(navigationTitle)
        .overlay {
            if visibleItems.isEmpty {
                emptyState
            }
        }
    }

    private var navigationTitle: String {
        if case .vault(let v) = selection {
            return model.vaults.first { $0.id == v }?.name ?? "保险库"
        }
        return selection.title
    }

    @ViewBuilder
    private var emptyState: some View {
        if !search.isEmpty {
            ContentUnavailableView.search(text: search)
        } else if selection == .trash {
            ContentUnavailableView("回收站是空的", systemImage: "trash", description: Text("移入回收站的条目会出现在这里，可以恢复。"))
        } else if selection == .favorites {
            ContentUnavailableView("还没有收藏", systemImage: "star", description: Text("在条目详情中点星标即可收藏。"))
        } else {
            ContentUnavailableView("还没有条目", systemImage: "key", description: Text("点击 + 添加第一个登录。"))
        }
    }

    @ViewBuilder
    private func rowMenu(_ item: ItemEntry) -> some View {
        if item.trashed {
            Button("恢复") { model.restore(itemId: item.id) }
        } else {
            Button(item.favorite ? "取消收藏" : "收藏") { model.setFavorite(itemId: item.id, !item.favorite) }
            Divider()
            Button("移入回收站") { model.trash(itemId: item.id) }
        }
    }
}

/// 列表中的一行：图标、标题、副标题；收藏与冲突以图标标出，不只靠颜色（docs/ux.md §8）。
struct ItemRow: View {
    let item: ItemEntry

    var body: some View {
        HStack(spacing: KV.Space.s2) {
            SiteIcon(title: item.title, url: item.urls.first)
            VStack(alignment: .leading, spacing: KV.Space.s0_5) {
                Text(item.title.isEmpty ? "（无标题）" : item.title)
                    .font(KV.Typography.bodyStrong)
                    .lineLimit(1)
                if !item.subtitle.isEmpty {
                    Text(item.subtitle)
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 0)
            if item.hasConflicts {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(KV.Colors.statusWarningFg)
                    .help("有待处理的冲突")
                    .accessibilityLabel("有待处理的冲突")
            }
            if item.favorite {
                Image(systemName: "star.fill")
                    .font(.caption)
                    .foregroundStyle(KV.Colors.fgTertiary)
                    .accessibilityLabel("已收藏")
            }
        }
        .padding(.vertical, KV.Space.s0_5)
    }
}

private struct SecretKeyItem: Identifiable {
    let value: String
    var id: String { "secret-key" }
}

struct NewLoginSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let defaultVault: String?
    let created: (String) -> Void
    @ViewState private var title = ""
    @ViewState private var username = ""
    @ViewState private var password = ""
    @ViewState private var url = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("新建登录").font(.title2.weight(.semibold))
            Form {
                TextField("标题", text: $title)
                TextField("用户名", text: $username)
                SecureField("密码", text: $password)
                TextField("网址", text: $url)
            }
            .formStyle(.grouped)
            HStack {
                Spacer()
                Button("取消", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("保存") {
                    if let vault = defaultVault,
                       let id = model.createLogin(vaultId: vault, title: title, username: username, password: password, url: url) {
                        created(id)
                    }
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(title.isEmpty || defaultVault == nil)
            }
        }
        .padding(24)
        .frame(width: 460)
    }
}
