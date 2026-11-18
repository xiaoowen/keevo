// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 进程加固实测（scripts/package-macos.sh --verify 使用）：
//
//   keevo-smoke --dlopen <dylib>   尝试加载一个动态库。启用 Hardened Runtime 时，Library Validation
//                                  应拒绝没有 Team ID 的临时签名库（docs/security.md §9、ADR-0003）。
//
// 只存在于冒烟测试中，不随应用发布。

import Darwin
import Foundation

/// 处理 `--dlopen` 参数；没有时返回 `nil`。退出码：0 已加载，3 被拒绝。
func runDlopenCheckIfRequested() -> Int32? {
    let args = CommandLine.arguments
    guard args.count == 3, args[1] == "--dlopen" else { return nil }
    if dlopen(args[2], RTLD_NOW) != nil {
        print("loaded")
        return 0
    }
    print("refused: \(dlerror().map { String(cString: $0) } ?? "unknown")")
    return 3
}
