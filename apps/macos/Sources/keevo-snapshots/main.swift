// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 界面截图：用示例数据把各个页面离屏渲染为 PNG（浅色与深色），用于对照设计稿检查界面。
// 不显示任何窗口，不读写用户的数据。只在 debug 构建中可用：
//
//   scripts/snapshots.sh [输出目录]

import Foundation
import KeevoUI

#if DEBUG
// 顶层代码在主线程上运行
MainActor.assumeIsolated { Snapshots.main() }
#else
print("keevo-snapshots 只在 debug 构建中可用：scripts/snapshots.sh")
exit(1)
#endif
