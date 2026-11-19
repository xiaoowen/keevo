// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 主窗口（docs/ux.md §2，设计稿"macOS · 主窗口"）：侧边栏 → 条目列表 → 条目详情。
// 不使用系统工具栏：搜索与新建在列表顶部，编辑与锁定在详情顶部；新建、生成密码、搜索也在菜单栏中（⌘N、⇧⌘G、⌘F）。

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

/// 菜单栏命令对主窗口的请求（KeevoApp 的 commands）。
enum MainRequest: Equatable {
    case newItem(NewItemChoice)
    case generator
    case focusSearch
}

struct MainView: View {
    @Environment(AppModel.self) private var model
    @ViewState private var sidebar: SidebarItem
    @ViewState private var selectedItem: String?
    @ViewState private var search = ""
    @FocusState private var searchFocused: Bool
    @FocusState private var listFocused: Bool
    @ViewState private var showingNewLogin = false
    @ViewState private var newItem: NewItemChoice?
    @ViewState private var showingGenerator = false
    /// 刚新建的条目：显示时直接打开编辑器。
    @ViewState private var editRequest: String?

    init(initialSidebar: SidebarItem = .all, initialItem: String? = nil, initialEditing: Bool = false) {
        _sidebar = ViewState(initialValue: initialSidebar)
        _selectedItem = ViewState(initialValue: initialItem)
        _editRequest = ViewState(initialValue: initialEditing ? initialItem : nil)
    }

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

    /// 没有搜索词时按标题排序（汉字按拼音与拉丁字母混排，见 AppModel.sortKeys）；有搜索词时由 Rust 按相关度排序。
    private var visibleItems: [ItemEntry] {
        let query = search.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty else {
            let keys = model.sortKeys
            return model.items
                .filter { matches($0, sidebar) }
                .sorted {
                    let a = keys[$0.title] ?? $0.title.lowercased()
                    let b = keys[$1.title] ?? $1.title.lowercased()
                    return a.localizedStandardCompare(b) == .orderedAscending
                }
        }
        let byId = Dictionary(uniqueKeysWithValues: model.items.map { ($0.id, $0) })
        return model.search(query).compactMap { byId[$0] }.filter { matches($0, sidebar) }
    }

    private func count(_ s: SidebarItem) -> Int {
        model.items.reduce(0) { $0 + (matches($1, s) ? 1 : 0) }
    }

    var body: some View {
        HStack(spacing: 0) {
            Sidebar(selection: $sidebar, count: count)
                .frame(width: 220)
                .overlay { EditingShield() }
            ColumnDivider()
            itemColumn
                .frame(width: 300)
                .overlay { EditingShield() }
            ColumnDivider()
            detailColumn
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(KV.Colors.bgCanvas)
        .ignoresSafeArea(.container, edges: .top)
        .sheet(isPresented: $showingNewLogin) {
            NewLoginSheet(defaultVault: defaultVault) { id in selectedItem = id }
        }
        .sheet(item: $newItem) { choice in
            NewItemSheet(choice: choice, defaultVault: defaultVault) { id in
                editRequest = id
                selectedItem = id
            }
        }
        .sheet(isPresented: $showingGenerator) {
            GeneratorView()
        }
        .sheet(item: Binding(
            get: { model.pendingSecretKey.map(SecretKeyItem.init) },
            set: { if $0 == nil { model.pendingSecretKey = nil } }
        )) { key in
            SecretKeySheet(secretKey: key.value).interactiveDismissDisabled()
        }
        .onChange(of: sidebar) { selectedItem = nil }
        .onChange(of: model.mainRequest) { handle(model.mainRequest) }
    }

    private func handle(_ request: MainRequest?) {
        guard let request else { return }
        model.mainRequest = nil
        guard model.editingItem == nil else {
            model.showToast("先保存或取消正在编辑的条目")
            return
        }
        switch request {
        case .newItem(let choice): create(choice)
        case .generator: showingGenerator = true
        case .focusSearch: searchFocused = true
        }
    }

    private func create(_ choice: NewItemChoice) {
        if choice.itemType == "login" { showingNewLogin = true } else { newItem = choice }
    }

    private var defaultVault: String? {
        if case .vault(let v) = sidebar { return v }
        return model.vaults.first?.id
    }

    // MARK: - 条目列表

    private var itemColumn: some View {
        VStack(spacing: 0) {
            HStack(spacing: KV.Space.s2) {
                KVSearchField(text: $search, prompt: "搜索，或输入 type:ssh", focus: $searchFocused)
                    .help("过滤：type: tag: vault: url: is:fav is:conflict，前加 - 表示排除")
                    .onKeyPress(.downArrow) {
                        guard model.editingItem == nil else { return .ignored }
                        listFocused = true
                        if selectedItem == nil { selectedItem = visibleItems.first?.id }
                        return .handled
                    }
                NewItemMenu(disabled: model.vaults.isEmpty, create: create, generator: { showingGenerator = true })
            }
            .padding(.horizontal, KV.Space.s3)
            .frame(height: 54)
            .padding(.top, 0)
            ColumnRule()
            let items = visibleItems
            if items.isEmpty {
                emptyState
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(spacing: 2) {
                            ForEach(items, id: \.id) { item in
                                ItemRow(item: item, selected: item.id == selectedItem)
                                    .id(item.id)
                                    .onTapGesture {
                                        selectedItem = item.id
                                        listFocused = true
                                    }
                                    .contextMenu { rowMenu(item) }
                            }
                        }
                        .padding(KV.Space.s2)
                    }
                    .focusable()
                    .focused($listFocused)
                    .focusEffectDisabled()
                    .onKeyPress(.downArrow) { move(1, in: items, proxy); return .handled }
                    .onKeyPress(.upArrow) { move(-1, in: items, proxy); return .handled }
                }
            }
        }
        .background(KV.Colors.bgCanvas)
    }

    private func move(_ delta: Int, in items: [ItemEntry], _ proxy: ScrollViewProxy) {
        // 编辑期间不切换条目（切换会丢弃未保存的修改）
        guard !items.isEmpty, model.editingItem == nil else { return }
        let index = items.firstIndex { $0.id == selectedItem }.map { $0 + delta } ?? 0
        let next = items[max(0, min(items.count - 1, index))].id
        selectedItem = next
        proxy.scrollTo(next)
    }

    @ViewBuilder
    private var emptyState: some View {
        if !search.isEmpty {
            EmptyState(symbol: "magnifyingglass", title: "没有符合的条目", message: "换个关键词，或用 type: tag: vault: url: 过滤。")
        } else if sidebar == .trash {
            EmptyState(symbol: "trash", title: "回收站是空的", message: "移入回收站的条目会出现在这里，可以恢复。")
        } else if sidebar == .favorites {
            EmptyState(symbol: "star", title: "还没有收藏", message: "在条目详情中点星标即可收藏。")
        } else {
            EmptyState(symbol: "key", title: "还没有条目", message: "点击 + 添加第一个登录，或从其他密码管理器导入。")
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

    // MARK: - 详情

    @ViewBuilder
    private var detailColumn: some View {
        if let id = selectedItem, model.items.contains(where: { $0.id == id }) {
            ItemDetailView(itemId: id, selectedItem: $selectedItem, editOnAppear: editRequest == id)
                .id(id)
                .onAppear { if editRequest == id { editRequest = nil } }
        } else {
            VStack(spacing: 0) {
                DetailTopBar { EmptyView() }
                EmptyState(symbol: "rectangle.on.rectangle", title: "选择一个条目", message: "在左侧选择条目查看详情，或按 ⌘N 新建。")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }
}

// MARK: - 侧边栏

/// 侧边栏（设计稿）：全部与收藏；"分类"与"开发者"两组类型；有多个保险库时列出保险库；标签；最近删除。
private struct Sidebar: View {
    @Environment(AppModel.self) private var model
    @Binding var selection: SidebarItem
    let count: (SidebarItem) -> Int

    private static let personal = ["login", "email_account", "secure_note", "two_factor"]
    private static let developer = ["ssh_key", "api_credential", "database", "environment"]

    private var presentTypes: Set<String> {
        Set(model.items.filter { !$0.trashed }.map(\.itemType))
    }

    private var tags: [String] {
        let zh = Locale(identifier: "zh_Hans")
        return Set(model.items.filter { !$0.trashed }.flatMap(\.tags))
            .sorted { $0.compare($1, options: [.caseInsensitive], range: nil, locale: zh) == .orderedAscending }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // 红绿灯按钮的位置（窗口隐藏了标题栏）
            Color.clear.frame(height: 40)
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    VStack(spacing: 2) {
                        row(.all, "全部条目", symbol: "square.grid.2x2", prominent: true)
                        row(.favorites, "收藏", symbol: "star", prominent: true)
                    }
                    section("分类", Self.personal)
                    section("开发者", Self.developer)
                    if model.vaults.count > 1 {
                        group("保险库") {
                            ForEach(model.vaults, id: \.id) { v in row(.vault(v.id), v.name) }
                        }
                    }
                    if !tags.isEmpty {
                        group("标签") {
                            ForEach(tags, id: \.self) { t in row(.tag(t), t) }
                        }
                    }
                    VStack(spacing: 2) {
                        row(.trash, "最近删除", symbol: "trash", prominent: true)
                    }
                }
                .padding(.horizontal, 10)
                .padding(.bottom, KV.Space.s3)
            }
            .scrollIndicators(.never)
            HStack(spacing: 6) {
                Circle().fill(KV.Colors.fgTertiary).frame(width: 7, height: 7)
                Text("仅在这台 Mac 上 · 未开启同步")
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
            }
            .padding(.horizontal, 18)
            .padding(.vertical, 14)
            .accessibilityElement(children: .combine)
        }
        .background(KV.Colors.bgSurface)
    }

    @ViewBuilder
    private func section(_ title: String, _ types: [String]) -> some View {
        let shown = types.filter(presentTypes.contains)
        if !shown.isEmpty {
            group(title) {
                ForEach(shown, id: \.self) { t in row(.type(t), ItemTypeInfo.name(t)) }
            }
        }
    }

    private func group<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(KV.Typography.caption.weight(.semibold))
                .foregroundStyle(KV.Colors.fgSecondary)
                .padding(.horizontal, KV.Space.s2)
                .padding(.bottom, KV.Space.s1)
                .accessibilityAddTraits(.isHeader)
            content()
        }
    }

    private func row(_ item: SidebarItem, _ title: String, symbol: String? = nil, prominent: Bool = false) -> some View {
        SidebarRow(
            title: title,
            symbol: symbol,
            count: count(item),
            selected: selection == item,
            verticalPadding: prominent ? 6 : 5
        ) { selection = item }
    }
}

struct SidebarRow: View {
    let title: String
    let symbol: String?
    let count: Int
    let selected: Bool
    let verticalPadding: CGFloat
    let action: () -> Void
    @ViewState private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: KV.Space.s2) {
                if let symbol {
                    Image(systemName: symbol)
                        .font(.system(size: 13))
                        .foregroundStyle(selected ? KV.Colors.accentFg : KV.Colors.fgSecondary)
                        .frame(width: 16)
                }
                Text(title)
                    .font(selected ? KV.Typography.bodyStrong : KV.Typography.body)
                    .foregroundStyle(KV.Colors.fgPrimary)
                    .lineLimit(1)
                Spacer(minLength: KV.Space.s1)
                if count > 0 {
                    CountBadge(count: count)
                }
            }
            .padding(.horizontal, KV.Space.s2)
            .padding(.vertical, verticalPadding)
            .background(
                selected ? KV.Colors.bgSelected : (hovering ? KV.Colors.bgHover : .clear),
                in: RoundedRectangle(cornerRadius: 6, style: .continuous)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityValue(count > 0 ? "\(count) 个" : "")
    }
}

// MARK: - 新建

/// 列表顶部的"+"：点击新建登录，箭头菜单选择其他类型或打开密码生成器。
private struct NewItemMenu: View {
    let disabled: Bool
    let create: (NewItemChoice) -> Void
    let generator: () -> Void

    var body: some View {
        Menu {
            ForEach(NewItemChoice.all) { choice in
                Button { create(choice) } label: { Label(choice.name, systemImage: choice.symbol) }
            }
            Divider()
            Button { generator() } label: { Label("生成密码…", systemImage: "wand.and.stars") }
        } label: {
            Image(systemName: "plus")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(KV.Colors.fgOnAccent)
                .frame(width: 30, height: 30)
                .background(KV.Colors.accentFill, in: RoundedRectangle(cornerRadius: KV.Radius.md, style: .continuous))
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .fixedSize()
        .disabled(disabled)
        .help("新建条目（⌘N 新建登录）")
        .accessibilityLabel("新建条目")
    }
}

// MARK: - 布局零件

/// 栏与栏之间的竖线。
struct ColumnDivider: View {
    var body: some View {
        Rectangle().fill(KV.Colors.borderSubtle).frame(width: 1).ignoresSafeArea()
    }
}

/// 栏顶部区域下的横线。
struct ColumnRule: View {
    var body: some View {
        Rectangle().fill(KV.Colors.borderSubtle).frame(height: 1)
    }
}

/// 详情栏顶部：高 54，右侧放操作按钮（设计稿："编辑"与锁定）。
struct DetailTopBar<Actions: View>: View {
    @Environment(AppModel.self) private var model
    @ViewBuilder let actions: Actions

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: KV.Space.s2) {
                Spacer()
                actions
                Button { model.lock() } label: {
                    Image(systemName: "lock").font(.system(size: 12, weight: .semibold)).frame(width: 14)
                }
                .buttonStyle(.kvBordered)
                .help("立即锁定（⇧⌘L）")
                .accessibilityLabel("锁定")
            }
            .padding(.horizontal, KV.Space.s4)
            .frame(height: 54)
            ColumnRule()
        }
    }
}

/// 编辑条目期间盖住侧边栏与列表（参考 1Password 的编辑模式）：避免切换条目时丢失未保存的修改。
private struct EditingShield: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if model.editingItem != nil {
            KV.Colors.bgCanvas.opacity(0.6)
                .contentShape(Rectangle())
                .onTapGesture { model.showToast("先保存或取消正在编辑的条目") }
                .accessibilityHidden(true)
        }
    }
}

/// 空状态：图标、标题、说明。
struct EmptyState: View {
    let symbol: String
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: KV.Space.s2) {
            Image(systemName: symbol)
                .font(.system(size: 28, weight: .light))
                .foregroundStyle(KV.Colors.fgTertiary)
                .padding(.bottom, KV.Space.s1)
            Text(title).font(KV.Typography.headline).foregroundStyle(KV.Colors.fgPrimary)
            Text(message)
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 260)
        }
        .padding(KV.Space.s6)
    }
}

/// 列表中的一行（设计稿）：图标、标题、副标题；选中为品牌色浅底；收藏与冲突以图标标出，不只靠颜色（docs/ux.md §8）。
/// 没有副标题时显示类型名。
struct ItemRow: View {
    let item: ItemEntry
    var selected = false
    @ViewState private var hovering = false

    var body: some View {
        HStack(spacing: 10) {
            SiteIcon(title: item.title, url: item.urls.first)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.title.isEmpty ? "（无标题）" : item.title)
                    .font(KV.Typography.bodyStrong)
                    .foregroundStyle(KV.Colors.fgPrimary)
                    .lineLimit(1)
                Text(item.subtitle.isEmpty ? ItemTypeInfo.name(item.itemType) : item.subtitle)
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            if item.hasConflicts {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 11))
                    .foregroundStyle(KV.Colors.statusWarningFg)
                    .help("有待处理的冲突")
                    .accessibilityLabel("有待处理的冲突")
            }
            if item.favorite {
                Image(systemName: "star.fill")
                    .font(.system(size: 11))
                    .foregroundStyle(KV.Colors.statusWarningFg)
                    .accessibilityLabel("已收藏")
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(
            selected ? KV.Colors.bgSelected : (hovering ? KV.Colors.bgHover : .clear),
            in: RoundedRectangle(cornerRadius: KV.Radius.md, style: .continuous)
        )
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
    }
}

private struct SecretKeyItem: Identifiable {
    let value: SecretValue
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
    @ViewState private var generating = false
    @FocusState private var titleFocused: Bool

    private var canSave: Bool { !title.trimmingCharacters(in: .whitespaces).isEmpty && defaultVault != nil }

    var body: some View {
        SheetScaffold(title: "新建登录", systemImage: "person.badge.key", width: 460) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                LabeledInput(label: "标题") {
                    TextField("", text: $title, prompt: DraftFieldRow.prompt("例如 GitHub")).focused($titleFocused)
                }
                LabeledInput(label: "用户名") {
                    TextField("", text: $username, prompt: DraftFieldRow.prompt("用户名或邮箱"))
                }
                VStack(alignment: .trailing, spacing: KV.Space.s1) {
                    LabeledInput(label: "密码") {
                        SecureField("", text: $password)
                    }
                    Button { generating = true } label: { Label("生成强密码", systemImage: "wand.and.stars") }
                        .buttonStyle(.kvLink)
                        .popover(isPresented: $generating) {
                            GeneratorView { password = $0 }
                        }
                }
                LabeledInput(label: "网站") {
                    TextField("", text: $url, prompt: DraftFieldRow.prompt("https://…"))
                }
            }
        } footer: {
            Button("取消") { dismiss() }
                .buttonStyle(.kvSecondary)
                .keyboardShortcut(.cancelAction)
            Button("保存", action: save)
                .buttonStyle(.kvPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(!canSave)
        }
        .onAppear { titleFocused = true }
    }

    private func save() {
        guard canSave, let vault = defaultVault else { return }
        if let id = model.createLogin(vaultId: vault, title: title, username: username, password: password, url: url) {
            created(id)
        }
        dismiss()
    }
}

/// 按类型新建：先输入标题，新建后直接打开编辑器填写模板中的字段（docs/product.md §5.3）。
struct NewItemSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let choice: NewItemChoice
    let defaultVault: String?
    let created: (String) -> Void
    @ViewState private var title = ""
    @ViewState private var vault: String?
    @FocusState private var titleFocused: Bool

    private var canCreate: Bool { !title.trimmingCharacters(in: .whitespaces).isEmpty && (vault ?? defaultVault) != nil }

    var body: some View {
        SheetScaffold(
            title: "新建\(choice.name)",
            subtitle: "先起个名字，然后在详情中填写其余内容。",
            systemImage: choice.symbol,
            width: 440
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                LabeledInput(label: "标题") {
                    TextField("", text: $title).focused($titleFocused).onSubmit(create)
                }
                if model.vaults.count > 1 {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("保险库")
                            .font(KV.Typography.footnote.weight(.semibold))
                            .foregroundStyle(KV.Colors.fgSecondary)
                        Picker("保险库", selection: $vault) {
                            ForEach(model.vaults, id: \.id) { Text($0.name).tag(String?.some($0.id)) }
                        }
                        .pickerStyle(.menu)
                        .labelsHidden()
                        .fixedSize()
                    }
                }
            }
        } footer: {
            Button("取消") { dismiss() }
                .buttonStyle(.kvSecondary)
                .keyboardShortcut(.cancelAction)
            Button("继续", action: create)
                .buttonStyle(.kvPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(!canCreate)
        }
        .onAppear {
            vault = defaultVault
            titleFocused = true
        }
    }

    private func create() {
        guard canCreate, let vault = vault ?? defaultVault else { return }
        if let id = model.createItem(vaultId: vault, itemType: choice.itemType, preset: choice.preset, title: title) {
            created(id)
        }
        dismiss()
    }
}
