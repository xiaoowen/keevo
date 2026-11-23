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
    /// 安全中心（docs/product.md §5.6）：不显示条目列表，内容区为检查结果。
    case security

    var title: String {
        switch self {
        case .security: tr("安全中心")
        case .all: tr("全部条目")
        case .favorites: tr("收藏")
        case .type(let t): ItemTypeInfo.name(t)
        case .vault: tr("保险库")
        case .tag(let t): t
        case .trash: tr("最近删除")
        }
    }
}

/// 菜单栏命令对主窗口的请求（KeevoApp 的 commands）。
enum MainRequest: Equatable {
    case newItem(NewItemChoice)
    case generator
    case focusSearch
    /// 选中一个条目（浏览器扩展的"在 Keevo 中打开"，spec/ipc.md §5.6）。
    case showItem(String)
    /// 选中一个条目并打开编辑器（安全中心的"修改密码"）。
    case editItem(String)
    /// 显示某个标签下的条目（导入完成后的"查看导入的条目"）。
    case showTag(String)
}

struct MainView: View {
    @Environment(AppModel.self) private var model
    @ViewState private var sidebar: SidebarItem
    @ViewState private var selectedItem: String?
    /// 切换侧边栏后要选中的条目（"在 Keevo 中打开"）：切换会清空选中，由切换的处理代为选中。
    @ViewState private var selectAfterSidebarChange: String?
    @ViewState private var search = ""
    @FocusState private var searchFocused: Bool
    @FocusState private var listFocused: Bool
    @ViewState private var showingNewLogin = false
    /// 在新建登录的面板中返回并选了其他类型：面板关闭后打开那个类型的新建面板。
    @ViewState private var pendingChoice: NewItemChoice?
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
        case .security: return false
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
        if s == .security { return model.visibleAffectedItems }
        return model.items.reduce(0) { $0 + (matches($1, s) ? 1 : 0) }
    }

    var body: some View {
        HStack(spacing: 0) {
            Sidebar(selection: $sidebar, count: count)
                .frame(width: 220)
                .overlay { EditingShield() }
            ColumnDivider()
            if sidebar == .security {
                SecurityCenterView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                itemColumn
                    .frame(width: 300)
                    .overlay { EditingShield() }
                ColumnDivider()
                detailColumn
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .background(KV.Colors.bgCanvas)
        .ignoresSafeArea(.container, edges: .top)
        .sheet(isPresented: $showingNewLogin, onDismiss: {
            if let choice = pendingChoice {
                pendingChoice = nil
                newItem = choice
            }
        }) {
            NewLoginSheet(defaultVault: defaultVault, chooseType: { pendingChoice = $0 }) { id in selectedItem = id }
        }
        .sheet(item: $newItem) { choice in
            NewItemSheet(choice: choice, defaultVault: defaultVault) { id in
                editRequest = id
                selectedItem = id
            }
        }
        .sheet(isPresented: Binding(get: { model.showingImport }, set: { model.showingImport = $0 })) {
            ImportSheet()
        }
        .sheet(isPresented: Binding(get: { model.showingExport }, set: { model.showingExport = $0 })) {
            ExportSheet()
        }
        .sheet(isPresented: $showingGenerator) {
            GeneratorView()
        }
        .sheet(isPresented: Binding(get: { model.showingPractice }, set: { model.showingPractice = $0 })) {
            PracticeSheet()
        }
        .onChange(of: sidebar) {
            selectedItem = selectAfterSidebarChange
            selectAfterSidebarChange = nil
        }
        .onChange(of: model.mainRequest) { handle(model.mainRequest) }
    }

    private func handle(_ request: MainRequest?) {
        guard let request else { return }
        model.mainRequest = nil
        guard model.editingItem == nil else {
            model.showToast(tr("先保存或取消正在编辑的条目"))
            return
        }
        switch request {
        case .newItem(let choice): create(choice)
        case .generator: showingGenerator = true
        case .focusSearch: searchFocused = true
        case .showItem(let id), .editItem(let id):
            search = ""
            if case .editItem = request { editRequest = id }
            if sidebar == .all {
                selectedItem = id
            } else {
                selectAfterSidebarChange = id
                sidebar = .all
            }
        case .showTag(let tag):
            search = ""
            sidebar = .tag(tag)
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
                KVSearchField(text: $search, prompt: tr("搜索，或输入 type:ssh"), focus: $searchFocused)
                    .help(tr("过滤：type: tag: vault: url: is:fav is:conflict is:weak，前加 - 表示排除"))
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
            EmptyState(symbol: "magnifyingglass", title: tr("没有符合的条目"), message: tr("换个关键词试试"))
        } else if sidebar == .trash {
            EmptyState(symbol: "trash", title: tr("回收站是空的"))
        } else if sidebar == .favorites {
            EmptyState(symbol: "star", title: tr("还没有收藏"), message: tr("在条目详情中点星标即可收藏。"))
        } else {
            EmptyState(symbol: "key", title: tr("还没有条目"), message: tr("点 + 添加，或从其他密码管理器导入"))
        }
    }

    @ViewBuilder
    private func rowMenu(_ item: ItemEntry) -> some View {
        if item.trashed {
            Button(tr("恢复")) { model.restore(itemId: item.id) }
        } else {
            Button(item.favorite ? tr("取消收藏") : tr("收藏")) { model.setFavorite(itemId: item.id, !item.favorite) }
            Divider()
            Button(tr("移入回收站")) { model.trash(itemId: item.id) }
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
                EmptyState(symbol: "rectangle.on.rectangle", title: tr("选择一个条目"))
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
                        row(.all, tr("全部条目"), symbol: "square.grid.2x2", prominent: true)
                        row(.favorites, tr("收藏"), symbol: "star", prominent: true)
                        row(.security, tr("安全中心"), symbol: "checkmark.shield", prominent: true, attention: true)
                    }
                    section(tr("分类"), Self.personal)
                    section(tr("开发者"), Self.developer)
                    if model.vaults.count > 1 {
                        group(tr("保险库")) {
                            ForEach(model.vaults, id: \.id) { v in row(.vault(v.id), v.name) }
                        }
                    }
                    if !tags.isEmpty {
                        group(tr("标签")) {
                            ForEach(tags, id: \.self) { t in row(.tag(t), t) }
                        }
                    }
                    VStack(spacing: 2) {
                        row(.trash, tr("最近删除"), symbol: "trash", prominent: true)
                    }
                }
                .padding(.horizontal, 10)
                .padding(.bottom, KV.Space.s3)
            }
            .scrollIndicators(.never)
            HStack(spacing: 6) {
                Circle().fill(KV.Colors.fgTertiary).frame(width: 7, height: 7)
                Text(tr("仅在这台 Mac 上 · 未开启同步"))
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

    private func row(_ item: SidebarItem, _ title: String, symbol: String? = nil, prominent: Bool = false, attention: Bool = false) -> some View {
        SidebarRow(
            title: title,
            symbol: symbol,
            count: count(item),
            selected: selection == item,
            verticalPadding: prominent ? 6 : 5,
            attention: attention
        ) { selection = item }
    }
}

struct SidebarRow: View {
    let title: String
    let symbol: String?
    let count: Int
    let selected: Bool
    let verticalPadding: CGFloat
    /// 计数以警示色显示（安全中心的待处理数量）。
    var attention = false
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
                    CountBadge(count: count, attention: attention)
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
        // 鼠标点击按钮不会移走键盘焦点：行本身不进入 Tab 顺序，否则焦点框一直停在第一行
        .focusable(false)
        .onHover { hovering = $0 }
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityValue(count > 0 ? tr("{} 个", "\(count)") : "")
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
            Button { generator() } label: { Label(tr("生成密码…"), systemImage: "wand.and.stars") }
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
        .help(tr("新建条目（⌘N 新建登录）"))
        .accessibilityLabel(tr("新建条目"))
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
                    Image(systemName: "lock").font(.system(size: 14, weight: .medium))
                }
                .buttonStyle(.kvToolbar)
                .help(tr("立即锁定（⇧⌘L）"))
                .accessibilityLabel(tr("锁定"))
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
                .onTapGesture { model.showToast(tr("先保存或取消正在编辑的条目")) }
                .accessibilityHidden(true)
        }
    }
}

/// 空状态：图标、标题、说明。
struct EmptyState: View {
    let symbol: String
    let title: String
    var message: String?

    var body: some View {
        VStack(spacing: KV.Space.s2) {
            Image(systemName: symbol)
                .font(.system(size: 28, weight: .light))
                .foregroundStyle(KV.Colors.fgTertiary)
                .padding(.bottom, KV.Space.s1)
            Text(title).font(KV.Typography.headline).foregroundStyle(KV.Colors.fgPrimary)
            if let message {
                Text(message)
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 260)
            }
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
                Text(item.title.isEmpty ? tr("（无标题）") : item.title)
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
                    .help(tr("有待处理的冲突"))
                    .accessibilityLabel(tr("有待处理的冲突"))
            }
            if item.favorite {
                Image(systemName: "star.fill")
                    .font(.system(size: 11))
                    .foregroundStyle(KV.Colors.statusWarningFg)
                    .accessibilityLabel(tr("已收藏"))
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

/// 新建登录（设计稿"条目的展示、编辑与新建"）：与编辑同一套表单。左上角返回类型选择，右上角关闭；
/// 填了标题才能保存。保存时先按模板新建，再一次写入其余的网站、备注、新增字段与标签。
struct NewLoginSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let defaultVault: String?
    /// 返回后选了其他类型：交给按类型新建的面板。
    let chooseType: (NewItemChoice) -> Void
    let created: (String) -> Void
    @ViewState private var title = ""
    @ViewState private var username = ""
    @ViewState private var password = ""
    @ViewState private var urls: [String] = [""]
    @ViewState private var notes = ""
    @ViewState private var tags: [String] = []
    @ViewState private var newTag = ""
    @ViewState private var extra: [DraftField] = []
    @ViewState private var generating = false
    @ViewState private var choosingType = false
    @FocusState private var titleFocused: Bool

    private var canSave: Bool { !title.trimmingCharacters(in: .whitespaces).isEmpty && defaultVault != nil }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Button { choosingType.toggle() } label: {
                    Image(systemName: choosingType ? "chevron.right" : "arrow.left").font(.system(size: 14, weight: .medium))
                }
                .buttonStyle(.kvToolbar)
                .help(choosingType ? tr("返回") : tr("选择其他类型"))
                .accessibilityLabel(choosingType ? tr("返回") : tr("选择其他类型"))
                Spacer()
                Text(choosingType ? tr("新建条目") : tr("新建登录")).font(.system(size: 14, weight: .bold))
                Spacer()
                Button { dismiss() } label: {
                    Image(systemName: "xmark").font(.system(size: 13, weight: .medium))
                }
                .buttonStyle(.kvToolbar)
                .keyboardShortcut(.cancelAction)
                .help(tr("关闭（esc）"))
                .accessibilityLabel(tr("关闭"))
            }
            .padding(.horizontal, KV.Space.s3)
            .frame(height: 50)
            Rectangle().fill(KV.Colors.borderSubtle).frame(height: 1)
            if choosingType {
                typeList
            } else {
                form
                Rectangle().fill(KV.Colors.borderSubtle).frame(height: 1)
                HStack {
                    Spacer()
                    Button(tr("保存"), action: save)
                        .buttonStyle(.kvPrimary)
                        .keyboardShortcut(.defaultAction)
                        .disabled(!canSave)
                }
                .padding(.horizontal, KV.Space.s5)
                .padding(.vertical, KV.Space.s3)
            }
        }
        .frame(width: 600, height: 660)
        .background(KV.Colors.bgCanvas)
        .onAppear { titleFocused = true }
    }

    private var form: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: KV.Space.s4) {
                    Image(systemName: "person.badge.key")
                        .font(.system(size: 24))
                        .foregroundStyle(KV.Colors.accentFg)
                        .frame(width: 60, height: 60)
                        .background(KV.Colors.accentSubtle, in: RoundedRectangle(cornerRadius: 15, style: .continuous))
                    TitleField(title: $title, focused: $titleFocused)
                }
                KVCard {
                    inputRow(tr("用户名")) {
                        TextField("", text: $username, prompt: DraftFieldRow.prompt(tr("用户名或邮箱"))).kvInline()
                    }
                    CardRowDivider()
                    HStack(spacing: KV.Space.s1) {
                        inputRow(tr("密码")) {
                            SecureField("", text: $password, prompt: DraftFieldRow.prompt(tr("密码"))).kvInline()
                        }
                        IconButton(systemImage: "wand.and.stars", label: tr("生成密码")) { generating = true }
                            .padding(.trailing, KV.Space.s2)
                            .popover(isPresented: $generating) { GeneratorView { password = $0 } }
                    }
                }
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(urls.indices, id: \.self) { i in
                        HStack(spacing: KV.Space.s1) {
                            inputRow(i == 0 ? tr("网站") : "") {
                                TextField("", text: Binding(get: { urls[i] }, set: { urls[i] = $0 }), prompt: DraftFieldRow.prompt("https://example.com"))
                                    .kvInline()
                            }
                            if urls.count > 1 {
                                Button { urls.remove(at: i) } label: {
                                    Image(systemName: "minus.circle").font(.system(size: 14, weight: .medium)).foregroundStyle(KV.Colors.statusDangerFg)
                                }
                                .buttonStyle(.kvToolbar)
                                .padding(.trailing, KV.Space.s2)
                                .accessibilityLabel(tr("删除网站"))
                            }
                        }
                        Rectangle().fill(KV.Colors.borderSubtle).frame(height: 1)
                    }
                    Button { urls.append("") } label: {
                        Label(tr("添加另一个网站"), systemImage: "plus")
                            .font(KV.Typography.body.weight(.medium))
                            .foregroundStyle(KV.Colors.accentFg)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 10)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
                .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                if !extra.isEmpty {
                    KVCard {
                        ForEach(Array(extra.enumerated()), id: \.element.id) { index, field in
                            if index > 0 { CardRowDivider() }
                            DraftFieldRow(
                                field: Binding(
                                    get: { extra.first { $0.id == field.id } ?? field },
                                    set: { v in if let i = extra.firstIndex(where: { $0.id == field.id }) { extra[i] = v } }
                                ),
                                sections: [],
                                canMoveUp: false,
                                canMoveDown: false,
                                move: { _ in },
                                moveTo: { _ in },
                                remove: { extra.removeAll { $0.id == field.id } }
                            )
                        }
                    }
                }
                AddMoreMenu(add: { kind in
                    if kind == "url" { urls.append("") } else { extra.append(DraftField(newKind: kind, section: nil)) }
                }, addSection: {})
                VStack(alignment: .leading, spacing: 4) {
                    FieldLabel(text: tr("备注"))
                    TextField("", text: $notes, prompt: DraftFieldRow.prompt(tr("添加备注")), axis: .vertical)
                        .lineLimit(2...10)
                        .kvInline()
                        .accessibilityLabel(tr("备注"))
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                TagEditor(tags: $tags, newTag: $newTag, add: addTag)
            }
            .padding(.horizontal, 28)
            .padding(.vertical, 22)
        }
    }

    /// 类型选择：返回之后的列表。选登录回到表单，选其他类型交给按类型新建的面板。
    private var typeList: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 2) {
                ForEach(NewItemChoice.all) { choice in
                    Button {
                        if choice.itemType == "login" {
                            choosingType = false
                        } else {
                            chooseType(choice)
                            dismiss()
                        }
                    } label: {
                        HStack(spacing: KV.Space.s3) {
                            Image(systemName: choice.symbol)
                                .font(.system(size: 15))
                                .foregroundStyle(KV.Colors.accentFg)
                                .frame(width: 34, height: 34)
                                .background(KV.Colors.accentSubtle, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                            Text(choice.name).font(KV.Typography.body)
                            Spacer()
                        }
                        .padding(.horizontal, KV.Space.s3)
                        .padding(.vertical, 6)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(KV.Space.s4)
        }
    }

    private func inputRow<Field: View>(_ label: String, @ViewBuilder field: () -> Field) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            if !label.isEmpty {
                Text(label).font(KV.Typography.footnote).foregroundStyle(KV.Colors.accentFg)
            }
            field()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func addTag() {
        let tag = newTag.trimmingCharacters(in: .whitespaces)
        if !tag.isEmpty, !tags.contains(tag) { tags.append(tag) }
        newTag = ""
    }

    private func save() {
        guard canSave, let vault = defaultVault else { return }
        addTag()
        let links = urls.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard let id = model.createLogin(vaultId: vault, title: title, username: username, password: password, url: links.first ?? "")
        else { return }
        // 模板之外的内容：一次写入（spec/revisions.md §5.4）
        var edits: [ItemEdit] = []
        if let detail = model.detail(of: id) {
            if !notes.isEmpty, let field = detail.fields.first(where: { $0.purpose == "notes" }) {
                edits.append(.setFieldValue(fieldId: field.id, value: notes))
            }
            for link in links.dropFirst() {
                edits.append(.addFieldToSection(
                    sectionId: nil, kind: "url", label: DraftField.defaultLabel("url"), purpose: nil, value: link, kv: [], codes: []
                ))
            }
            for f in extra {
                let empty = f.value.isEmpty && f.kv.isEmpty && f.codes.isEmpty
                if empty { continue }
                // 模板中已有空的一次性密码字段：填入它，不另加
                if f.kind == "totp", let otp = detail.fields.first(where: { $0.kind == "totp" && $0.value.isEmpty() }) {
                    edits.append(.setFieldValue(fieldId: otp.id, value: f.value))
                    continue
                }
                edits.append(.addFieldToSection(
                    sectionId: nil, kind: f.kind, label: f.label, purpose: f.purpose, value: f.value,
                    kv: f.kv.map { KvInput(key: $0.key, value: $0.value, concealed: $0.concealed) },
                    codes: f.codes.map { CodeInput(code: $0.code, used: $0.used) }
                ))
            }
            for tag in tags { edits.append(.addTag(tag: tag)) }
        }
        if !edits.isEmpty {
            do {
                try model.update(itemId: id, edits: edits, force: true)
            } catch {
                model.report(error)
            }
        }
        created(id)
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
    /// SSH 密钥：新建后直接生成 Ed25519 密钥（docs/ux.md §3.6 第 2 步）。
    @ViewState private var generateKey = true
    @FocusState private var titleFocused: Bool

    private var canCreate: Bool { !title.trimmingCharacters(in: .whitespaces).isEmpty && (vault ?? defaultVault) != nil }

    var body: some View {
        SheetScaffold(
            // 中文与拉丁字母之间加空格："新建 SSH 密钥"
            title: tr("新建") + (choice.name.first?.isASCII == true ? " " : "") + choice.name,
            subtitle: tr("先起个名字，然后在详情中填写其余内容。"),
            systemImage: choice.symbol,
            width: 440
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                LabeledInput(label: tr("标题")) {
                    TextField("", text: $title).focused($titleFocused).onSubmit(create)
                }
                if choice.itemType == "ssh_key" {
                    Toggle(tr("生成新的 Ed25519 密钥（也可以之后导入现有私钥）"), isOn: $generateKey)
                        .toggleStyle(.checkbox)
                        .font(KV.Typography.body)
                }
                if model.vaults.count > 1 {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(tr("保险库"))
                            .font(KV.Typography.footnote.weight(.semibold))
                            .foregroundStyle(KV.Colors.fgSecondary)
                        Picker(tr("保险库"), selection: $vault) {
                            ForEach(model.vaults, id: \.id) { Text($0.name).tag(String?.some($0.id)) }
                        }
                        .pickerStyle(.menu)
                        .labelsHidden()
                        .fixedSize()
                    }
                }
            }
        } footer: {
            Button(tr("取消")) { dismiss() }
                .buttonStyle(.kvSecondary)
                .keyboardShortcut(.cancelAction)
            Button(tr("继续"), action: create)
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
            if choice.itemType == "ssh_key", generateKey {
                model.generateSshKey(itemId: id)
            }
            created(id)
        }
        dismiss()
    }
}
