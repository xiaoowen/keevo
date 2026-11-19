// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）

/// 编辑器计算字段移动时使用（apps/macos/Sources/KeevoUI/ItemEditor.swift）。
public enum Ordering {
    /// 最长严格递增子序列的下标，忽略取值为负的元素（来自其他分区的字段）。
    /// 这些字段的相对顺序没有变，保存时不需要移动。
    public static func longestIncreasing(_ values: [Int]) -> [Int] {
        var length = Array(repeating: 1, count: values.count)
        var previous = Array(repeating: -1, count: values.count)
        for i in values.indices where values[i] >= 0 {
            for j in 0..<i where values[j] >= 0 && values[j] < values[i] && length[j] + 1 > length[i] {
                length[i] = length[j] + 1
                previous[i] = j
            }
        }
        guard var end = values.indices.filter({ values[$0] >= 0 }).max(by: { length[$0] < length[$1] }) else {
            return []
        }
        var out: [Int] = []
        while end >= 0 {
            out.append(end)
            end = previous[end]
        }
        return out.reversed()
    }
}
