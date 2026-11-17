// swift-tools-version: 6.0
// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// M0 空壳应用。先运行 scripts/build-macos.sh：它会编译 Rust 静态库、生成 UniFFI 绑定，再调用 SwiftPM。
// M1 会改为 Xcode 工程（签名、entitlements、钥匙串与 Touch ID 需要）。

import Foundation
import PackageDescription

let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let rustLibDir = ProcessInfo.processInfo.environment["KEEVO_RUST_LIB_DIR"]
    ?? packageDir.appendingPathComponent("../../target/release").standardized.path

let package = Package(
    name: "Keevo",
    platforms: [.macOS(.v15)],
    targets: [
        // UniFFI 生成的 C 头文件与模块映射；链接 Rust 静态库（传完整路径，避免链接器优先选用 dylib）
        .target(
            name: "keevo_ffiFFI",
            path: "Sources/keevo_ffiFFI",
            linkerSettings: [
                .unsafeFlags(["\(rustLibDir)/libkeevo_ffi.a"]),
                .linkedLibrary("iconv"),
            ]
        ),
        // UniFFI 生成的 Swift 绑定
        .target(
            name: "KeevoKit",
            dependencies: ["keevo_ffiFFI"],
            path: "Sources/KeevoKit",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        // 无界面的端到端冒烟测试：经 UniFFI 调用 Rust 核心
        .executableTarget(
            name: "keevo-smoke",
            dependencies: ["KeevoKit"],
            path: "Sources/keevo-smoke",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        // SwiftUI 空壳应用
        .executableTarget(
            name: "Keevo",
            dependencies: ["KeevoKit"],
            path: "Sources/Keevo",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
