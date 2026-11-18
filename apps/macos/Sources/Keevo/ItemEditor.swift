// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 条目编辑器。保存时把改动算成一组编辑，一次写入（spec/revisions.md §5.4 写时收敛）。
// 存在冲突、撤销删除或来源不一致的内容时，编辑界面顶部展示冲突面板（同上，"界面要求"）。

import KeevoKit
import SwiftUI

/// 编辑中的字段。
///
/// 秘密字段在用户点"显示"之前不取出原值（docs/architecture.md §4.2）：输入框为空，提示"保持不变"；
/// 这时输入的内容整体替换原值。点"显示"后才把原值取出到输入框中，可以部分修改。
struct DraftField: Identifiable {
    /// 已有字段为字段 ID；新字段为临时 ID。
    let id: String
    var label: String
    let kind: String
    var value: String
    let concealed: Bool
    let isNew: Bool
    /// 已有字段的原值句柄。
    let original: SecretValue?
    /// 原值是否已取出到 `value`。非秘密字段一开始就取出。
    private(set) var loaded: Bool

    init(_ f: FieldEntry) {
        id = f.id
        label = f.label
        kind = f.kind
        concealed = f.concealed
        isNew = false
        original = f.value
        loaded = !f.concealed
        value = f.concealed ? "" : f.value.expose()
    }

    init(newKind kind: String) {
        id = "new-" + UUID().uuidString
        label = Self.defaultLabel(kind)
        self.kind = kind
        value = ""
        concealed = kind == "concealed"
        isNew = true
        original = nil
        loaded = true
    }

    /// 把原值取出到输入框（用户点"显示"）。已经输入了新值时保留新值。
    mutating func load() {
        guard !loaded, let original else { return }
        if value.isEmpty { value = original.expose() }
        loaded = true
    }

    /// 与原值相比是否有改动。没有取出原值时，输入了内容即为改动。
    var changed: Bool {
        guard let original else { return true }
        if !loaded { return !value.isEmpty }
        return !original.equals(other: value)
    }

    static func defaultLabel(_ kind: String) -> String {
        switch kind {
        case "concealed": "密码"
        case "url": "网站"
        case "email": "电子邮件"
        case "phone": "电话"
        case "multiline": "备注"
        default: "文本"
        }
    }
}

struct ItemEditorSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Binding var selectedItem: String?

    /// 编辑开始时（或最近一次处理冲突后）的详情，用来计算改动。
    @ViewState private var base: ItemDetail
    @ViewState private var title: String
    @ViewState private var favorite: Bool
    @ViewState private var fields: [DraftField]
    @ViewState private var removed: Set<String> = []
    @ViewState private var tags: [String]
    @ViewState private var newTag = ""
    @ViewState private var error: String?
    @ViewState private var needsRebuild = false

    init(detail: ItemDetail, selectedItem: Binding<String?>) {
        _selectedItem = selectedItem
        _base = .init(initialValue: detail)
        _title = .init(initialValue: detail.title)
        _favorite = .init(initialValue: detail.favorite)
        _fields = .init(initialValue: detail.fields.map(DraftField.init))
        _tags = .init(initialValue: detail.tags)
    }

    private var needsAttention: Bool {
        !base.conflicts.isEmpty || base.resurrected || base.integrityIssues > 0
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("编辑条目")
                .font(.title3.weight(.semibold))
                .padding([.horizontal, .top], 24)
            Form {
                if needsAttention {
                    Section("需要你处理") {
                        ConflictPanel(detail: base) { rebase() }
                    }
                }
                Section {
                    TextField("标题", text: $title)
                    Toggle("收藏", isOn: $favorite)
                }
                Section("字段") {
                    ForEach($fields) { $field in
                        if !removed.contains(field.id) {
                            DraftFieldRow(field: $field) { remove(field) }
                        }
                    }
                    Menu("添加字段") {
                        ForEach(FieldKindInfo.addable, id: \.self) { kind in
                            Button(FieldKindInfo.name(kind)) { fields.append(DraftField(newKind: kind)) }
                        }
                    }
                    .fixedSize()
                }
                Section("标签") {
                    if !tags.isEmpty {
                        HStack(spacing: KV.Space.s1_5) {
                            ForEach(tags, id: \.self) { tag in
                                HStack(spacing: KV.Space.s1) {
                                    Text(tag).font(KV.Typography.footnote)
                                    Button { tags.removeAll { $0 == tag } } label: { Image(systemName: "xmark.circle.fill") }
                                        .buttonStyle(.borderless)
                                        .accessibilityLabel("移除标签\(tag)")
                                }
                                .padding(.horizontal, KV.Space.s2)
                                .padding(.vertical, KV.Space.s0_5)
                                .background(KV.Colors.bgSunken, in: Capsule())
                            }
                        }
                    }
                    HStack {
                        TextField("添加标签", text: $newTag)
                            .onSubmit(addTag)
                        Button("添加", action: addTag)
                            .disabled(newTag.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }
            }
            .formStyle(.grouped)
            VStack(alignment: .leading, spacing: KV.Space.s2) {
                if let error {
                    Banner(kind: .danger, message: error)
                }
                HStack {
                    if needsRebuild {
                        Button("重建为新条目") { rebuild() }
                    }
                    Spacer()
                    Button("取消", role: .cancel) { dismiss() }
                        .keyboardShortcut(.cancelAction)
                    Button("保存") { save() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(needsRebuild)
                }
            }
            .padding([.horizontal, .bottom], 24)
        }
        .frame(width: 580, height: 640)
    }

    // MARK: - 操作

    private func addTag() {
        let tag = newTag.trimmingCharacters(in: .whitespaces)
        guard !tag.isEmpty else { return }
        if !tags.contains(tag) { tags.append(tag) }
        newTag = ""
    }

    private func remove(_ field: DraftField) {
        if field.isNew {
            fields.removeAll { $0.id == field.id }
        } else {
            removed.insert(field.id)
        }
    }

    /// 由当前草稿与 `base` 算出编辑列表。
    private var edits: [ItemEdit] {
        var out: [ItemEdit] = []
        if title != base.title { out.append(.setTitle(title: title)) }
        if favorite != base.favorite { out.append(.setFavorite(favorite: favorite)) }
        for tag in tags where !base.tags.contains(tag) { out.append(.addTag(tag: tag)) }
        for tag in base.tags where !tags.contains(tag) { out.append(.removeTag(tag: tag)) }
        for field in fields {
            if field.isNew {
                out.append(.addField(kind: field.kind, label: field.label, purpose: nil, value: field.value))
            } else if removed.contains(field.id) {
                out.append(.removeField(fieldId: field.id))
            } else if field.changed, FieldKindInfo.editable(field.kind) {
                out.append(.setFieldValue(fieldId: field.id, value: field.value))
            }
        }
        return out
    }

    private func save() {
        let edits = edits
        // 没有改动但有待确认的状态（撤销删除、来源不一致、多个头）时，空编辑也写一个收敛修订：保存即确认
        guard !edits.isEmpty || base.resurrected || base.integrityIssues > 0 || base.headCount > 1 else {
            dismiss()
            return
        }
        do {
            try model.update(itemId: base.id, edits: edits, force: true)
            dismiss()
        } catch KeevoError.ItemNeedsRebuild {
            needsRebuild = true
            error = AppModel.describe(KeevoError.ItemNeedsRebuild)
        } catch {
            self.error = AppModel.describe(error)
        }
    }

    private func rebuild() {
        do {
            if let id = try model.rebuild(itemId: base.id) {
                selectedItem = id
            }
            dismiss()
        } catch {
            self.error = AppModel.describe(error)
        }
    }

    /// 在编辑器中处理冲突后，详情已写入新修订：用户没有改动的部分跟随新值，已改动的保留草稿。
    private func rebase() {
        guard let new = model.detail(of: base.id) else {
            dismiss()
            return
        }
        if title == base.title { title = new.title }
        if favorite == base.favorite { favorite = new.favorite }
        if tags == base.tags { tags = new.tags }
        var updated: [DraftField] = []
        for f in new.fields {
            if let draft = fields.first(where: { $0.id == f.id }) {
                updated.append(draft.changed ? draft : DraftField(f))
            } else if !removed.contains(f.id) {
                updated.append(DraftField(f))
            }
        }
        updated.append(contentsOf: fields.filter(\.isNew))
        fields = updated
        base = new
    }
}

/// 编辑器中的一行字段：新字段可改名，秘密字段可切换显示，结构化字段暂时只读。
struct DraftFieldRow: View {
    @Binding var field: DraftField
    let remove: () -> Void
    @ViewState private var revealed = false

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: KV.Space.s2) {
            if field.isNew {
                TextField("名称", text: $field.label)
                    .frame(width: 120)
            } else {
                Text(field.label)
                    .frame(width: 120, alignment: .leading)
                    .lineLimit(1)
            }
            valueEditor
            Button(action: remove) { Image(systemName: "minus.circle") }
                .buttonStyle(.borderless)
                .help("删除这个字段")
                .accessibilityLabel("删除字段\(field.label)")
        }
    }

    @ViewBuilder
    private var valueEditor: some View {
        if !FieldKindInfo.editable(field.kind) {
            Text("\(FieldKindInfo.name(field.kind))：暂不支持在这里编辑")
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        } else if field.concealed {
            Group {
                if revealed {
                    TextField("值", text: $field.value).font(KV.Typography.mono)
                } else {
                    SecureField("值", text: $field.value, prompt: Text(field.loaded ? "" : "保持不变"))
                }
            }
            Button {
                field.load()
                revealed.toggle()
            } label: { Image(systemName: revealed ? "eye.slash" : "eye") }
                .buttonStyle(.borderless)
                .accessibilityLabel(revealed ? "隐藏" : "显示")
        } else if field.kind == "multiline" {
            TextField("值", text: $field.value, axis: .vertical)
                .lineLimit(2...8)
        } else {
            TextField("值", text: $field.value)
        }
    }
}
