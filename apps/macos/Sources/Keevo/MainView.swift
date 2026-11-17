// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 三栏主界面：侧边栏 → 条目列表 → 条目详情（docs/ux.md §2）。

import KeevoKit
import SwiftUI

struct MainView: View {
    @Environment(AppModel.self) private var model
    @ViewState private var selectedVault: String?
    @ViewState private var selectedItem: String?
    @ViewState private var search = ""
    @ViewState private var showingNewLogin = false

    private var visibleItems: [ItemEntry] {
        model.items.filter { item in
            !item.trashed
                && (selectedVault == nil || item.vaultId == selectedVault)
                && (search.isEmpty
                    || item.title.localizedCaseInsensitiveContains(search)
                    || item.subtitle.localizedCaseInsensitiveContains(search)
                    || item.urls.contains { $0.localizedCaseInsensitiveContains(search) })
        }
    }

    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            List(selection: $selectedVault) {
                Label("全部条目", systemImage: "square.grid.2x2").tag(String?.none)
                Section("保险库") {
                    ForEach(model.vaults, id: \.id) { vault in
                        Label(vault.name, systemImage: "lock.rectangle.stack").tag(String?.some(vault.id))
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200)
        } content: {
            List(visibleItems, id: \.id, selection: $selectedItem) { item in
                HStack(spacing: KV.Space.s2) {
                    SiteIcon(title: item.title, url: item.urls.first)
                    VStack(alignment: .leading, spacing: KV.Space.s0_5) {
                        Text(item.title).font(KV.Typography.bodyStrong)
                        if !item.subtitle.isEmpty {
                            Text(item.subtitle).font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
                        }
                    }
                }
                .padding(.vertical, KV.Space.s0_5)
            }
            .searchable(text: $search, prompt: "搜索标题、用户名、网址")
            .overlay {
                if visibleItems.isEmpty {
                    ContentUnavailableView("还没有条目", systemImage: "key", description: Text("点击 + 添加第一个登录。"))
                }
            }
            .navigationSplitViewColumnWidth(min: 240, ideal: 280)
        } detail: {
            if let id = selectedItem, let item = model.items.first(where: { $0.id == id }) {
                ItemDetailView(item: item).id(item.id)
            } else {
                ContentUnavailableView("选择一个条目", systemImage: "sidebar.right")
            }
        }
        .toolbar {
            ToolbarItem {
                Button { showingNewLogin = true } label: { Label("新建登录", systemImage: "plus") }
                    .keyboardShortcut("n")
            }
            ToolbarItem {
                Button { model.lock() } label: { Label("锁定", systemImage: "lock") }
            }
        }
        .sheet(isPresented: $showingNewLogin) {
            NewLoginSheet(defaultVault: selectedVault ?? model.vaults.first?.id)
        }
        .sheet(item: Binding(
            get: { model.pendingSecretKey.map(SecretKeyItem.init) },
            set: { if $0 == nil { model.pendingSecretKey = nil } }
        )) { key in
            SecretKeySheet(secretKey: key.value).interactiveDismissDisabled()
        }
    }
}

private struct LargeTypeItem: Identifiable {
    let value: String
    var id: String { "large-type" }
}

private struct SecretKeyItem: Identifiable {
    let value: String
    var id: String { "secret-key" }
}

struct ItemDetailView: View {
    @Environment(AppModel.self) private var model
    let item: ItemEntry
    @ViewState private var fields: [FieldEntry] = []
    @ViewState private var revealed: Set<String> = []
    @ViewState private var largeType: LargeTypeItem?

    var body: some View {
        Form {
            Section {
                HStack(spacing: KV.Space.s3) {
                    SiteIcon(title: item.title, url: item.urls.first, size: 40)
                    VStack(alignment: .leading, spacing: KV.Space.s0_5) {
                        Text(item.title).font(KV.Typography.title)
                        if !item.subtitle.isEmpty {
                            Text(item.subtitle).font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
                        }
                    }
                }
            }
            Section {
                ForEach(fields, id: \.id) { field in
                    LabeledContent(field.label) {
                        HStack(spacing: 8) {
                            if field.concealed {
                                SecretText(value: field.value, revealed: revealed.contains(field.id))
                                Button(revealed.contains(field.id) ? "隐藏" : "显示") { toggle(field.id) }
                                    .buttonStyle(.borderless)
                                Button { largeType = LargeTypeItem(value: field.value) } label: {
                                    Image(systemName: "textformat.size")
                                }
                                .buttonStyle(.borderless)
                                .help("大字显示")
                            } else {
                                Text(field.value)
                                    .font(KV.Typography.body)
                                    .textSelection(.enabled)
                            }
                            Button { Clipboard.copy(field.value) } label: { Image(systemName: "doc.on.doc") }
                                .buttonStyle(.borderless)
                                .help("复制（\(Int(Clipboard.clearAfter)) 秒后自动清除）")
                        }
                    }
                }
            }
            Section {
                Button("移入回收站", role: .destructive) { model.trash(itemId: item.id) }
            }
        }
        .formStyle(.grouped)
        .onAppear { fields = model.fields(of: item.id) }
        // 切换条目或离开视图时丢弃已解密的字段
        .onDisappear { fields = []; revealed = []; largeType = nil }
        .sheet(item: $largeType) { item in LargeTypeView(value: item.value) }
    }

    private func toggle(_ id: String) {
        if revealed.contains(id) { revealed.remove(id) } else { revealed.insert(id) }
    }
}

struct NewLoginSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let defaultVault: String?
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
                Button("保存") {
                    if let vault = defaultVault {
                        model.createLogin(vaultId: vault, title: title, username: username, password: password, url: url)
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
