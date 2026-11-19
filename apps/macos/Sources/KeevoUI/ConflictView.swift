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
                Banner(kind: .warning, message: tr("这个条目在另一台设备上被删除，但这里有新的修改，已为你保留。保存即确认恢复这个条目。"))
            }
            if detail.integrityIssues > 0 {
                Banner(kind: .danger, message: tr("合并时发现 {} 处来源不一致的内容，可能来自损坏的数据或异常的设备。请在历史版本中核对；保存即表示你已知晓。", "\(detail.integrityIssues)"))
            }
            ForEach(detail.conflicts, id: \.key) { conflict in
                KVCard {
                    HStack(spacing: KV.Space.s2) {
                        Image(systemName: "arrow.triangle.branch")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(KV.Colors.statusWarningFg)
                        Text(conflict.displayName)
                            .font(KV.Typography.bodyStrong)
                            .foregroundStyle(KV.Colors.fgPrimary)
                        Spacer()
                        Text(tr("{} 个版本", "\(conflict.others.count + 1)"))
                            .font(KV.Typography.caption)
                            .foregroundStyle(KV.Colors.fgSecondary)
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 9)
                    .background(KV.Colors.statusWarningBg.opacity(0.5))
                    CardRowDivider()
                    versionRow(conflict, conflict.current, current: true)
                    ForEach(conflict.others, id: \.revId) { version in
                        CardRowDivider()
                        versionRow(conflict, version, current: false)
                    }
                }
            }
        }
    }

    private func versionRow(_ conflict: ConflictEntry, _ version: ConflictVersion, current: Bool) -> some View {
        let revealKey = conflict.key + "/" + version.revId
        let shown = revealed.contains(revealKey)
        return HStack(spacing: KV.Space.s2) {
            Text(current ? tr("这台 Mac") : tr("另一版本"))
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
                .frame(width: 72, alignment: .leading)
            if version.concealed, let secret = version.value {
                SecretText(secret: secret, revealed: shown)
                Button(shown ? tr("隐藏") : tr("显示")) {
                    if shown { revealed.remove(revealKey) } else { revealed.insert(revealKey) }
                }
                .buttonStyle(.kvLink)
            } else {
                Text(conflict.displayValue(version))
                    .font(KV.Typography.body)
                    .foregroundStyle(version.value == nil ? KV.Colors.fgSecondary : KV.Colors.fgPrimary)
                    .lineLimit(3)
            }
            Spacer(minLength: KV.Space.s2)
            Button(tr("保留这个")) {
                model.resolveConflict(itemId: detail.id, key: conflict.key, revId: version.revId)
                resolved()
            }
            .buttonStyle(.kvBordered)
            .disabled(version.revId.isEmpty)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
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
        SheetScaffold(
            title: tr("处理冲突"),
            subtitle: tr("其他设备对这个条目做了不同的修改。为每一处选择要保留的版本；没有处理的冲突会一直保留，不会丢失。"),
            systemImage: "arrow.triangle.branch",
            tint: KV.Colors.statusWarningFg,
            width: 580
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                ScrollView {
                    ConflictPanel(detail: shown) { current = model.detail(of: detail.id) }
                }
                .frame(maxHeight: 360)
                if shown.conflicts.isEmpty && (shown.resurrected || shown.integrityIssues > 0) {
                    Text(tr("剩下的提示会在下一次保存这个条目时确认。"))
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                }
            }
        } footer: {
            Button(tr("完成")) { dismiss() }
                .buttonStyle(.kvPrimary)
                .keyboardShortcut(.defaultAction)
        }
    }
}
