// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 冲突面板（spec/revisions.md §5.2、§5.4–§5.6）：并发修改、撤销删除、来源不一致的内容。
// 编辑界面必须展示它；详情页也可以单独打开。

import KeevoKit
import SwiftUI

struct ConflictPanel: View {
    @Environment(AppModel.self) private var model
    let detail: ItemDetail
    /// 用户选定某个版本之后调用（已写入新修订）。
    var resolved: () -> Void = {}
    @ViewState private var revealed: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: KV.Space.s3) {
            if detail.resurrected {
                Banner(kind: .warning, message: "这个条目在另一台设备上被删除，但这里有新的修改，已为你保留。保存即确认恢复这个条目。")
            }
            if detail.integrityIssues > 0 {
                Banner(kind: .danger, message: "合并时发现 \(detail.integrityIssues) 处来源不一致的内容，可能来自损坏的数据或异常的设备。请在历史版本中核对；保存即表示你已知晓。")
            }
            ForEach(detail.conflicts, id: \.key) { conflict in
                VStack(alignment: .leading, spacing: KV.Space.s1_5) {
                    Text(conflict.displayName).font(KV.Typography.bodyStrong)
                    versionRow(conflict, conflict.current, current: true)
                    ForEach(conflict.others, id: \.revId) { version in
                        versionRow(conflict, version, current: false)
                    }
                }
                .padding(KV.Space.s3)
                .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: KV.Radius.md))
            }
        }
    }

    private func versionRow(_ conflict: ConflictEntry, _ version: ConflictVersion, current: Bool) -> some View {
        let revealKey = conflict.key + "/" + version.revId
        return HStack(spacing: KV.Space.s2) {
            Text(current ? "当前" : "另一版本")
                .font(KV.Typography.caption)
                .foregroundStyle(KV.Colors.fgSecondary)
                .frame(width: 52, alignment: .leading)
            if version.concealed, let secret = version.value {
                SecretText(secret: secret, revealed: revealed.contains(revealKey))
                Button(revealed.contains(revealKey) ? "隐藏" : "显示") {
                    if revealed.contains(revealKey) { revealed.remove(revealKey) } else { revealed.insert(revealKey) }
                }
                .buttonStyle(.borderless)
            } else {
                Text(conflict.displayValue(version))
                    .font(KV.Typography.body)
                    .foregroundStyle(version.value == nil ? KV.Colors.fgSecondary : KV.Colors.fgPrimary)
                    .lineLimit(3)
            }
            Spacer(minLength: KV.Space.s2)
            Button("保留这个") {
                model.resolveConflict(itemId: detail.id, key: conflict.key, revId: version.revId)
                resolved()
            }
            .disabled(version.revId.isEmpty)
        }
    }
}

/// 从详情页打开的冲突面板。
struct ConflictSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let detail: ItemDetail
    @ViewState private var current: ItemDetail?

    var body: some View {
        let shown = current ?? detail
        VStack(alignment: .leading, spacing: KV.Space.s4) {
            Text("处理冲突").font(.title3.weight(.semibold))
            Text("其他设备对这个条目做了不同的修改。为每一处选择要保留的版本；没有处理的冲突会一直保留，不会丢失。")
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
                .fixedSize(horizontal: false, vertical: true)
            ScrollView {
                ConflictPanel(detail: shown) { current = model.detail(of: detail.id) }
            }
            if shown.conflicts.isEmpty && (shown.resurrected || shown.integrityIssues > 0) {
                Text("剩下的提示会在下一次保存这个条目时确认。")
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
            }
            HStack {
                Spacer()
                Button("完成") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 560, height: 480)
    }
}
