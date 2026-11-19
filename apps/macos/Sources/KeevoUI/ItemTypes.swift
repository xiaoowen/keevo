// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 条目类型、字段类型与冲突记录的显示名称（docs/ux.md §2、§6 术语表）。

import KeevoKit

enum ItemTypeInfo {
    /// 侧边栏"分类"的顺序（docs/ux.md §2）。
    static let order = [
        "login", "email_account", "secure_note", "ssh_key", "api_credential", "database", "environment", "two_factor",
    ]

    static func name(_ type: String) -> String {
        switch type {
        case "login": tr("登录")
        case "email_account": tr("电子邮件账户")
        case "secure_note": tr("安全笔记")
        case "ssh_key": tr("SSH 密钥")
        case "api_credential": tr("API 凭证")
        case "database": tr("数据库凭证")
        case "environment": tr("环境变量")
        case "two_factor": tr("双因素验证")
        default: type
        }
    }

    static func symbol(_ type: String) -> String {
        switch type {
        case "login": "key"
        case "email_account": "envelope"
        case "secure_note": "note.text"
        case "ssh_key": "terminal"
        case "api_credential": "curlybraces"
        case "database": "cylinder"
        case "environment": "list.bullet.rectangle"
        case "two_factor": "lock.rotation"
        default: "questionmark.square"
        }
    }
}

/// 新建菜单中的一项：类型与预设（docs/product.md §5.3："API 密钥"与"访问令牌"同属 api_credential）。
struct NewItemChoice: Identifiable, Hashable {
    let itemType: String
    let preset: String?
    let name: String
    let symbol: String
    var id: String { itemType + (preset ?? "") }

    static let all: [NewItemChoice] = [
        .init(itemType: "login", preset: nil, name: tr("登录"), symbol: "key"),
        .init(itemType: "email_account", preset: nil, name: tr("电子邮件账户"), symbol: "envelope"),
        .init(itemType: "secure_note", preset: nil, name: tr("安全笔记"), symbol: "note.text"),
        .init(itemType: "ssh_key", preset: nil, name: tr("SSH 密钥"), symbol: "terminal"),
        .init(itemType: "api_credential", preset: "api_key", name: tr("API 密钥"), symbol: "curlybraces"),
        .init(itemType: "api_credential", preset: "access_token", name: tr("访问令牌"), symbol: "ticket"),
        .init(itemType: "database", preset: nil, name: tr("数据库凭证"), symbol: "cylinder"),
        .init(itemType: "environment", preset: nil, name: tr("环境变量"), symbol: "list.bullet.rectangle"),
        .init(itemType: "two_factor", preset: nil, name: tr("双因素验证"), symbol: "lock.rotation"),
    ]
}

enum FieldKindInfo {
    /// 编辑器中可以新增的字段类型。
    static let addable = [
        "text", "concealed", "url", "email", "phone", "multiline", "date", "totp", "kv_list", "recovery_codes",
    ]

    static func name(_ kind: String) -> String {
        switch kind {
        case "text": tr("文本")
        case "multiline": tr("多行文本")
        case "concealed": tr("密码（隐藏）")
        case "email": tr("电子邮件")
        case "url": tr("网址")
        case "phone": tr("电话")
        case "date": tr("日期")
        case "month_year": tr("年月")
        case "select": tr("选项")
        case "totp": tr("一次性密码")
        case "ssh_private_key": tr("SSH 私钥")
        case "reference": tr("引用")
        case "recovery_codes": tr("恢复码")
        case "kv_list": tr("键值对")
        default: kind
        }
    }

    /// 是否是结构化字段（键值对、恢复码），由专门的编辑器修改。
    static func structured(_ kind: String) -> Bool {
        ["recovery_codes", "kv_list"].contains(kind)
    }

    /// 自动填充用途的显示名。
    static let purposes: [(String?, String)] = [
        (nil, tr("无")), ("username", tr("用户名")), ("password", tr("密码")), ("otp", tr("一次性密码")), ("notes", tr("备注")),
    ]
}

extension ConflictEntry {
    /// 冲突记录的显示名称：记录种类由 Rust 给出，这里本地化（keevo-ffi `ConflictEntry::kind`）。
    var displayName: String {
        switch kind {
        case "title": return tr("标题")
        case "favorite": return tr("收藏")
        case "tag": return tr("标签「{}」", "\(label ?? "")")
        case "section": return label.map { tr("分区「{}」", "\($0)") } ?? tr("分区")
        case "field": return label.map { tr("字段「{}」", "\($0)") } ?? tr("字段")
        default: return tr("其他属性")
        }
    }

    /// 某个版本的显示文字。布尔值与标签由 Rust 给出原始值，这里本地化。
    func displayValue(_ version: ConflictVersion) -> String {
        guard let value = version.value?.expose() else { return tr("（已删除）") }
        switch kind {
        case "favorite": return value == "true" ? tr("已收藏") : tr("未收藏")
        case "tag": return tr("有此标签")
        default: return value.isEmpty ? tr("（空）") : value
        }
    }
}
