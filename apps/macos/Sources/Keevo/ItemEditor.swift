// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 条目编辑器。保存时把改动算成一组编辑，一次写入（spec/revisions.md §5.4 写时收敛）。
// 存在冲突、撤销删除或来源不一致的内容时，编辑界面顶部展示冲突面板（同上，"界面要求"）。
//
// 移动字段时只改写真正移动了的字段：保持相对顺序不变的字段（最长递增子序列）不动，
// 其余字段从后往前依次放到各自的后继之前（keevo-core `Edit::MoveField`）。

import AppKit
import KeevoKit
import SwiftUI
import UniformTypeIdentifiers

struct DraftSection: Identifiable {
    let id: String
    var label: String
    let isNew: Bool
    let originalLabel: String
}

struct DraftKv: Identifiable, Equatable {
    let id = UUID()
    var key: String
    var value: String
    var concealed: Bool

    static func == (a: Self, b: Self) -> Bool {
        a.key == b.key && a.value == b.value && a.concealed == b.concealed
    }
}

struct DraftCode: Identifiable, Equatable {
    let id = UUID()
    var code: String
    var used: Bool

    static func == (a: Self, b: Self) -> Bool { a.code == b.code && a.used == b.used }
}

/// 编辑中的字段。
///
/// 秘密字段与一次性密码在用户点"显示"之前不取出原值（docs/architecture.md §4.2）：输入框为空，提示"保持不变"；
/// 这时输入的内容整体替换原值。点"显示"后才把原值取出到输入框中，可以部分修改。
/// 键值对与恢复码在编辑器打开时取出，以便逐项修改；其中的秘密值仍以密码框显示。
struct DraftField: Identifiable {
    /// 已有字段为字段 ID；新字段为临时 ID。
    let id: String
    var label: String
    let kind: String
    var value: String
    let concealed: Bool
    let isNew: Bool
    var sectionId: String?
    var purpose: String?
    var kv: [DraftKv]
    var codes: [DraftCode]
    /// 已有字段的原值句柄。
    let original: SecretValue?
    let originalLabel: String
    let originalPurpose: String?
    let originalKv: [DraftKv]
    let originalCodes: [DraftCode]
    /// 原值是否已取出到 `value`。
    private(set) var loaded: Bool

    /// 不直接显示原值的字段：秘密字段，以及含有密钥的一次性密码。
    var hidesValue: Bool { concealed || kind == "totp" }

    init(_ f: FieldEntry) {
        id = f.id
        label = f.label
        kind = f.kind
        concealed = f.concealed
        isNew = false
        sectionId = f.sectionId
        purpose = f.purpose
        original = f.value
        originalLabel = f.label
        originalPurpose = f.purpose
        let hides = f.concealed || f.kind == "totp"
        loaded = !hides
        value = hides || FieldKindInfo.structured(f.kind) ? "" : f.value.expose()
        kv = f.kv.map { DraftKv(key: $0.key, value: $0.value.expose(), concealed: $0.concealed) }
        codes = f.codes.map { DraftCode(code: $0.code.expose(), used: $0.used) }
        originalKv = kv
        originalCodes = codes
    }

    init(newKind kind: String, section: String?) {
        id = "new-" + UUID().uuidString
        label = Self.defaultLabel(kind)
        self.kind = kind
        value = ""
        concealed = ["concealed", "ssh_private_key", "recovery_codes"].contains(kind)
        isNew = true
        sectionId = section
        purpose = kind == "totp" ? "otp" : nil
        kv = []
        codes = []
        original = nil
        originalLabel = ""
        originalPurpose = nil
        originalKv = []
        originalCodes = []
        loaded = true
    }

    /// 把原值取出到输入框（用户点"显示"）。已经输入了新值时保留新值。
    mutating func load() {
        guard !loaded, let original else { return }
        if value.isEmpty { value = original.expose() }
        loaded = true
    }

    /// 输入了新值（例如用生成器填入）：视为已取出。
    mutating func replace(with newValue: String) {
        value = newValue
        loaded = true
    }

    /// 值有没有改动。
    var valueChanged: Bool {
        if FieldKindInfo.structured(kind) { return kv != originalKv || codes != originalCodes }
        guard let original else { return true }
        if !loaded { return !value.isEmpty }
        return !original.equals(other: value)
    }

    var modified: Bool {
        isNew || valueChanged || label != originalLabel || purpose != originalPurpose
    }

    static func defaultLabel(_ kind: String) -> String {
        switch kind {
        case "concealed": "密码"
        case "url": "网站"
        case "email": "电子邮件"
        case "phone": "电话"
        case "multiline": "备注"
        case "date": "日期"
        case "totp": "一次性密码"
        case "kv_list": "变量"
        case "recovery_codes": "恢复码"
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
    @ViewState private var sections: [DraftSection]
    @ViewState private var removedSections: Set<String> = []
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
        _sections = .init(initialValue: detail.sections.map { DraftSection(id: $0.id, label: $0.label, isNew: false, originalLabel: $0.label) })
        _fields = .init(initialValue: detail.fields.map(DraftField.init))
        _tags = .init(initialValue: detail.tags)
    }

    private var needsAttention: Bool {
        !base.conflicts.isEmpty || base.resurrected || base.integrityIssues > 0
    }

    private struct EditorGroup: Identifiable {
        let id: String
        let section: DraftSection?
        let fields: [DraftField]
    }

    /// 按字段 ID 绑定：增删字段时下标会移位，按下标绑定在刷新期间可能越界。
    private func binding(_ field: DraftField) -> Binding<DraftField> {
        Binding(
            get: { fields.first { $0.id == field.id } ?? field },
            set: { value in
                if let i = fields.firstIndex(where: { $0.id == field.id }) { fields[i] = value }
            }
        )
    }

    /// 显示用的分组：默认分区，然后是各个分区（未删除的）。
    private var groups: [EditorGroup] {
        let visible = sections.filter { !removedSections.contains($0.id) }
        let order: [DraftSection?] = [nil] + visible.map { Optional($0) }
        return order.map { s in
            let list = fields.filter { $0.sectionId == s?.id && !removed.contains($0.id) }
            return EditorGroup(id: s?.id ?? "", section: s, fields: list)
        }
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
                ForEach(groups) { group in
                    Section {
                        ForEach(group.fields) { field in
                            DraftFieldRow(
                                field: binding(field),
                                sections: sections.filter { !removedSections.contains($0.id) },
                                canMoveUp: canMove(field.id, by: -1),
                                canMoveDown: canMove(field.id, by: 1),
                                move: { move(field.id, by: $0) },
                                moveTo: { moveTo(field.id, section: $0) },
                                remove: { remove(field.id) }
                            )
                        }
                        Menu("添加字段") {
                            ForEach(FieldKindInfo.addable, id: \.self) { kind in
                                Button(FieldKindInfo.name(kind)) {
                                    fields.append(DraftField(newKind: kind, section: group.section?.id))
                                }
                            }
                        }
                        .fixedSize()
                    } header: {
                        if let section = group.section {
                            SectionHeaderEditor(
                                label: Binding(
                                    get: { sections.first { $0.id == section.id }?.label ?? "" },
                                    set: { v in
                                        if let i = sections.firstIndex(where: { $0.id == section.id }) { sections[i].label = v }
                                    }
                                ),
                                remove: { removeSection(section.id) }
                            )
                        }
                    }
                }
                Section {
                    Button { addSection() } label: { Label("添加分区", systemImage: "rectangle.stack.badge.plus") }
                        .buttonStyle(.borderless)
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
        .frame(width: 640, height: 720)
    }

    // MARK: - 排列

    /// 同一分区中已有字段的下标（新字段排在末尾，保存前不能移动）。
    private func siblings(of id: String) -> [Int] {
        guard let field = fields.first(where: { $0.id == id }) else { return [] }
        return fields.indices.filter {
            fields[$0].sectionId == field.sectionId && !fields[$0].isNew && !removed.contains(fields[$0].id)
        }
    }

    private func canMove(_ id: String, by delta: Int) -> Bool {
        let list = siblings(of: id)
        guard let pos = list.firstIndex(where: { fields[$0].id == id }) else { return false }
        return list.indices.contains(pos + delta)
    }

    private func move(_ id: String, by delta: Int) {
        let list = siblings(of: id)
        guard let pos = list.firstIndex(where: { fields[$0].id == id }), list.indices.contains(pos + delta) else { return }
        fields.swapAt(list[pos], list[pos + delta])
    }

    /// 移到另一个分区：排在那个分区已有字段的末尾。
    private func moveTo(_ id: String, section: String?) {
        guard let i = fields.firstIndex(where: { $0.id == id }) else { return }
        var field = fields.remove(at: i)
        field.sectionId = section
        let lastExisting = fields.lastIndex { $0.sectionId == section && !$0.isNew }
        fields.insert(field, at: lastExisting.map { $0 + 1 } ?? fields.endIndex)
    }

    private func remove(_ id: String) {
        if let i = fields.firstIndex(where: { $0.id == id }), fields[i].isNew {
            fields.remove(at: i)
        } else {
            removed.insert(id)
        }
    }

    private func addSection() {
        guard let id = try? newId() else { return }
        sections.append(DraftSection(id: id, label: "新分区", isNew: true, originalLabel: ""))
    }

    /// 删除分区：其中的字段移到默认分区末尾（与 keevo-core `Edit::RemoveSection` 一致）。
    private func removeSection(_ id: String) {
        let moving = fields.filter { $0.sectionId == id }
        fields.removeAll { $0.sectionId == id }
        for var field in moving {
            field.sectionId = nil
            let lastExisting = fields.lastIndex { $0.sectionId == nil && !$0.isNew }
            fields.insert(field, at: lastExisting.map { $0 + 1 } ?? fields.endIndex)
        }
        if sections.first(where: { $0.id == id })?.isNew == true {
            sections.removeAll { $0.id == id }
        } else {
            removedSections.insert(id)
        }
    }

    private func addTag() {
        let tag = newTag.trimmingCharacters(in: .whitespaces)
        guard !tag.isEmpty else { return }
        if !tags.contains(tag) { tags.append(tag) }
        newTag = ""
    }

    // MARK: - 保存

    /// 由当前草稿与 `base` 算出编辑列表。先改分区，再改字段内容，再移动，最后新增字段（新增的排在各分区末尾）。
    private var edits: [ItemEdit] {
        var out: [ItemEdit] = []
        if title != base.title { out.append(.setTitle(title: title)) }
        if favorite != base.favorite { out.append(.setFavorite(favorite: favorite)) }
        for tag in tags where !base.tags.contains(tag) { out.append(.addTag(tag: tag)) }
        for tag in base.tags where !tags.contains(tag) { out.append(.removeTag(tag: tag)) }
        for s in sections where s.isNew { out.append(.addSection(sectionId: s.id, label: s.label)) }
        for s in sections where !s.isNew && !removedSections.contains(s.id) && s.label != s.originalLabel {
            out.append(.renameSection(sectionId: s.id, label: s.label))
        }
        for id in removedSections { out.append(.removeSection(sectionId: id)) }
        for f in fields where !f.isNew {
            if removed.contains(f.id) {
                out.append(.removeField(fieldId: f.id))
                continue
            }
            if f.label != f.originalLabel { out.append(.setFieldLabel(fieldId: f.id, label: f.label)) }
            if f.purpose != f.originalPurpose { out.append(.setFieldPurpose(fieldId: f.id, purpose: f.purpose)) }
            guard f.valueChanged else { continue }
            switch f.kind {
            case "kv_list":
                out.append(.setFieldKv(fieldId: f.id, entries: f.kv.map { KvInput(key: $0.key, value: $0.value, concealed: $0.concealed) }))
            case "recovery_codes":
                out.append(.setFieldCodes(fieldId: f.id, codes: f.codes.map { CodeInput(code: $0.code, used: $0.used) }))
            default:
                out.append(.setFieldValue(fieldId: f.id, value: f.value))
            }
        }
        out += moves
        for f in fields where f.isNew {
            out.append(.addFieldToSection(
                sectionId: f.sectionId, kind: f.kind, label: f.label, purpose: f.purpose, value: f.value,
                kv: f.kv.map { KvInput(key: $0.key, value: $0.value, concealed: $0.concealed) },
                codes: f.codes.map { CodeInput(code: $0.code, used: $0.used) }
            ))
        }
        return out
    }

    /// 移动：与"按前面的编辑执行之后"的排列比较，只移动不在最长递增子序列中的字段。
    private var moves: [ItemEdit] {
        let live = { (id: String) in !removed.contains(id) }
        // 前面的编辑执行之后的排列：删除分区的字段依次移到默认分区末尾
        var expected: [String?: [String]] = [:]
        let baseSections = base.sections.map(\.id)
        for f in base.fields where live(f.id) {
            let s = f.sectionId.flatMap { removedSections.contains($0) ? nil : $0 }
            if f.sectionId == nil || s != nil { expected[s, default: []].append(f.id) }
        }
        for sid in baseSections where removedSections.contains(sid) {
            expected[nil, default: []] += base.fields.filter { $0.sectionId == sid && live($0.id) }.map(\.id)
        }
        var out: [ItemEdit] = []
        let finalSections: [String?] = [nil] + sections.filter { !removedSections.contains($0.id) }.map(\.id)
        for s in finalSections {
            let final = fields.filter { $0.sectionId == s && !$0.isNew && live($0.id) }.map(\.id)
            let before = expected[s] ?? []
            let positions = final.map { before.firstIndex(of: $0) ?? -1 }
            let stable = Set(Ordering.longestIncreasing(positions).map { final[$0] })
            for (i, id) in final.enumerated().reversed() where !stable.contains(id) {
                let next = i + 1 < final.count ? final[i + 1] : nil
                out.append(.moveField(fieldId: id, sectionId: s, beforeFieldId: next))
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

    /// 在编辑器中处理冲突后，详情已写入新修订：用户没有改动的字段跟随新值，已改动的字段、新增与删除保留。
    /// 字段的移动在这种情况下不保留，需要重新调整。
    private func rebase() {
        guard let new = model.detail(of: base.id) else {
            dismiss()
            return
        }
        if title == base.title { title = new.title }
        if favorite == base.favorite { favorite = new.favorite }
        if tags == base.tags { tags = new.tags }
        let kept = Dictionary(uniqueKeysWithValues: fields.filter { $0.modified && !$0.isNew }.map { ($0.id, $0) })
        fields = new.fields.map { kept[$0.id] ?? DraftField($0) } + fields.filter(\.isNew)
        let renamed = Dictionary(uniqueKeysWithValues: sections.filter { !$0.isNew }.map { ($0.id, $0.label) })
        sections = new.sections.map { s in
            DraftSection(id: s.id, label: renamed[s.id].flatMap { $0 == s.label ? nil : $0 } ?? s.label, isNew: false, originalLabel: s.label)
        } + sections.filter(\.isNew)
        base = new
    }
}

/// 分区标题：可改名、可删除。
struct SectionHeaderEditor: View {
    @Binding var label: String
    let remove: () -> Void

    var body: some View {
        HStack {
            TextField("分区名称", text: $label)
                .textFieldStyle(.plain)
                .font(KV.Typography.bodyStrong)
            Spacer()
            Button(role: .destructive, action: remove) { Label("删除分区", systemImage: "trash") }
                .buttonStyle(.borderless)
                .labelStyle(.iconOnly)
                .help("删除分区（其中的字段移到默认分区）")
        }
    }
}

/// 编辑器中的一行字段。
struct DraftFieldRow: View {
    @Binding var field: DraftField
    let sections: [DraftSection]
    let canMoveUp: Bool
    let canMoveDown: Bool
    let move: (Int) -> Void
    let moveTo: (String?) -> Void
    let remove: () -> Void
    @ViewState private var revealed = false
    @ViewState private var generating = false

    var body: some View {
        VStack(alignment: .leading, spacing: KV.Space.s1_5) {
            HStack(alignment: .firstTextBaseline, spacing: KV.Space.s2) {
                TextField("名称", text: $field.label)
                    .frame(width: 130)
                if !FieldKindInfo.structured(field.kind) {
                    valueEditor
                } else {
                    Spacer()
                }
                fieldMenu
            }
            switch field.kind {
            case "kv_list": KvEditor(entries: $field.kv)
            case "recovery_codes": CodesEditor(codes: $field.codes)
            case "totp": OtpPreview(text: field.loaded ? field.value : "", unchanged: !field.loaded && field.value.isEmpty)
            default: FormatHint(kind: field.kind, value: field.value)
            }
        }
        .popover(isPresented: $generating) {
            GeneratorView { field.replace(with: $0) }
        }
    }

    @ViewBuilder
    private var valueEditor: some View {
        if field.hidesValue {
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
            if field.kind == "concealed" {
                Button { generating = true } label: { Image(systemName: "wand.and.stars") }
                    .buttonStyle(.borderless)
                    .help("生成密码")
                    .accessibilityLabel("生成密码")
            }
            if field.kind == "totp" {
                OtpImportMenu { text in
                    field.replace(with: text)
                    revealed = true
                }
            }
        } else if field.kind == "multiline" {
            TextField("值", text: $field.value, axis: .vertical)
                .lineLimit(2...8)
        } else {
            TextField(placeholder, text: $field.value)
        }
    }

    private var placeholder: String {
        switch field.kind {
        case "date": "例如 2026-11-18"
        case "url": "https://…"
        default: "值"
        }
    }

    private var fieldMenu: some View {
        Menu {
            Button("上移") { move(-1) }.disabled(!canMoveUp)
            Button("下移") { move(1) }.disabled(!canMoveDown)
            if !field.isNew {
                Menu("移到分区") {
                    Button("默认分区") { moveTo(nil) }.disabled(field.sectionId == nil)
                    ForEach(sections) { s in
                        Button(s.label) { moveTo(s.id) }.disabled(field.sectionId == s.id)
                    }
                }
            }
            Menu("自动填充用途") {
                ForEach(FieldKindInfo.purposes, id: \.0) { purpose, name in
                    Button {
                        field.purpose = purpose
                    } label: {
                        if field.purpose == purpose { Label(name, systemImage: "checkmark") } else { Text(name) }
                    }
                }
            }
            Divider()
            Button("删除字段", role: .destructive, action: remove)
        } label: {
            Image(systemName: "ellipsis.circle")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .help(field.isNew ? "新字段保存后才能调整位置" : "字段操作")
    }
}

/// 格式提示（docs/product.md §5.2"带格式校验"）：不阻止保存。
struct FormatHint: View {
    let kind: String
    let value: String

    private var message: String? {
        let v = value.trimmingCharacters(in: .whitespaces)
        guard !v.isEmpty else { return nil }
        switch kind {
        case "email":
            return v.contains("@") && v.split(separator: "@").last?.contains(".") == true ? nil : "看起来不像电子邮件地址"
        case "url":
            guard let url = URL(string: v), let scheme = url.scheme, url.host != nil else { return "网址应以 https:// 开头" }
            return ["https", "http"].contains(scheme.lowercased()) ? nil : "网址应以 https:// 开头"
        case "phone":
            return v.allSatisfy { $0.isNumber || " +-()".contains($0) } ? nil : "电话号码只能包含数字、空格和 + - ( )"
        case "date":
            return v.range(of: #"^\d{4}-\d{2}(-\d{2})?$"#, options: .regularExpression) == nil ? "日期格式为 YYYY-MM-DD" : nil
        default:
            return nil
        }
    }

    var body: some View {
        if let message {
            Text(message).font(KV.Typography.caption).foregroundStyle(KV.Colors.statusWarningFg)
        }
    }
}

/// 一次性密码的预览：解析后显示发行方、账户与参数，不显示密钥。
struct OtpPreview: View {
    let text: String
    let unchanged: Bool

    var body: some View {
        if unchanged {
            Text("保持不变。可以粘贴 otpauth:// 链接或密钥，也可以从二维码导入。")
                .font(KV.Typography.caption).foregroundStyle(KV.Colors.fgSecondary)
        } else if !text.isEmpty {
            if let info = try? parseOtp(text: text) {
                let who = [info.issuer, info.account].compactMap { $0 }.joined(separator: " · ")
                Text("\(who.isEmpty ? "一次性密码" : who)：\(info.digits) 位，每 \(info.period) 秒，\(info.algorithm)")
                    .font(KV.Typography.caption).foregroundStyle(KV.Colors.statusSuccessFg)
            } else {
                Text("无法识别。请粘贴 otpauth://totp/ 链接或 Base32 密钥。")
                    .font(KV.Typography.caption).foregroundStyle(KV.Colors.statusDangerFg)
            }
        }
    }
}

/// 从二维码导入一次性密码：图片文件、剪贴板中的图片、屏幕（docs/product.md §5.4）。
struct OtpImportMenu: View {
    let found: (String) -> Void
    @ViewState private var message: String?

    var body: some View {
        Menu {
            Button("从图片文件读取二维码…") { openImage() }
            Button("读取剪贴板中的二维码图片") { readPasteboard() }
            Button("扫描屏幕上的二维码…") { Task { await scanScreen() } }
        } label: {
            Image(systemName: "qrcode.viewfinder")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .help(message ?? "从二维码导入")
        .alert("没有找到一次性密码的二维码", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好") { message = nil }
        } message: {
            Text(message ?? "")
        }
    }

    private func accept(_ texts: [String]) {
        if let uri = QRCodeReader.otpURI(in: texts) {
            found(uri)
        } else {
            message = texts.isEmpty ? "图片中没有可识别的二维码。" : "二维码的内容不是 otpauth://totp/ 链接。"
        }
    }

    private func openImage() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        accept(QRCodeReader.decode(contentsOf: url))
    }

    private func readPasteboard() {
        let pb = NSPasteboard.general
        guard let data = pb.data(forType: .png) ?? pb.data(forType: .tiff) else {
            message = "剪贴板中没有图片。"
            return
        }
        accept(QRCodeReader.decode(data: data))
    }

    @MainActor
    private func scanScreen() async {
        do {
            accept(try await ScreenQRScanner.shared.scan())
        } catch ScreenQRScanner.ScanError.cancelled {
            return
        } catch {
            message = "无法截取所选的内容。"
        }
    }
}

/// 键值对编辑器：键、值、值是否隐藏；可以粘贴 .env 文本批量导入。
struct KvEditor: View {
    @Binding var entries: [DraftKv]

    var body: some View {
        VStack(alignment: .leading, spacing: KV.Space.s1) {
            ForEach($entries) { $entry in
                HStack(spacing: KV.Space.s2) {
                    TextField("键", text: $entry.key).font(KV.Typography.mono).frame(width: 160)
                    if entry.concealed {
                        SecureField("值", text: $entry.value)
                    } else {
                        TextField("值", text: $entry.value).font(KV.Typography.mono)
                    }
                    Toggle("隐藏", isOn: $entry.concealed).toggleStyle(.checkbox)
                    Button { entries.removeAll { $0.id == entry.id } } label: { Image(systemName: "minus.circle") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("删除 \(entry.key)")
                }
            }
            HStack {
                Button("添加一项") { entries.append(DraftKv(key: "", value: "", concealed: true)) }
                Button("从剪贴板导入 .env") { importEnv() }
            }
            .buttonStyle(.borderless)
        }
        .padding(.leading, 138)
    }

    /// 解析 `KEY=VALUE` 行：忽略空行与 `#` 注释，去掉值两端成对的引号。
    private func importEnv() {
        guard let text = NSPasteboard.general.string(forType: .string) else { return }
        for line in text.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#"), let eq = trimmed.firstIndex(of: "=") else { continue }
            var key = String(trimmed[..<eq]).trimmingCharacters(in: .whitespaces)
            if key.hasPrefix("export ") { key = String(key.dropFirst(7)) }
            var value = String(trimmed[trimmed.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            if value.count >= 2, let q = value.first, "\"'".contains(q), value.last == q {
                value = String(value.dropFirst().dropLast())
            }
            guard !key.isEmpty else { continue }
            if let i = entries.firstIndex(where: { $0.key == key }) {
                entries[i].value = value
            } else {
                entries.append(DraftKv(key: key, value: value, concealed: true))
            }
        }
    }
}

/// 恢复码编辑器：逐个标记已使用；可以粘贴多个恢复码（每行一个）。
struct CodesEditor: View {
    @Binding var codes: [DraftCode]

    var body: some View {
        VStack(alignment: .leading, spacing: KV.Space.s1) {
            ForEach($codes) { $code in
                HStack(spacing: KV.Space.s2) {
                    SecureField("恢复码", text: $code.code).font(KV.Typography.mono)
                    Toggle("已使用", isOn: $code.used).toggleStyle(.checkbox)
                    Button { codes.removeAll { $0.id == code.id } } label: { Image(systemName: "minus.circle") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("删除恢复码")
                }
            }
            HStack {
                Button("添加一个") { codes.append(DraftCode(code: "", used: false)) }
                Button("从剪贴板导入（每行一个）") {
                    let lines = (NSPasteboard.general.string(forType: .string) ?? "")
                        .split(whereSeparator: \.isNewline)
                        .map { $0.trimmingCharacters(in: .whitespaces) }
                        .filter { !$0.isEmpty }
                    codes += lines.map { DraftCode(code: $0, used: false) }
                }
            }
            .buttonStyle(.borderless)
        }
        .padding(.leading, 138)
    }
}
