// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 检查更新（设计稿"强度、双击复制、排序与检查更新"，docs/governance.md §5）：默认开启，每天一次读取 GitHub 上公开的
// 发布列表，有更新的版本时在"设置 → 通用"与侧边栏底部提示。只提示：不下载、不安装，用户按安装说明下载并核对
// （docs/alpha/install.md）。请求不带 Cookie 与缓存，发送的只有 User-Agent 中的版本号。版本比较在 Rust 中进行
// （keevo_core::update）。

import AppKit
import KeevoKit
import Observation
import SwiftUI

@MainActor
@Observable
final class UpdateChecker {
    static let shared = UpdateChecker()
    /// 发布所在的仓库。发布页的地址必须在它之下（Rust 端核对）。
    static let repository = "xiaoowen/keevo"
    private static let autoCheckKey = "update.autoCheck"
    private static let lastCheckKey = "update.lastCheck"
    private static let interval: TimeInterval = 24 * 60 * 60

    /// 完整的版本号（含预发布后缀），如 0.1.0-alpha.1。
    let version = keevoVersion()
    /// 应用包的构建号（开发构建没有）。
    let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String

    var autoCheck = UserDefaults.standard.object(forKey: UpdateChecker.autoCheckKey) as? Bool ?? true {
        didSet {
            UserDefaults.standard.set(autoCheck, forKey: Self.autoCheckKey)
            schedule()
        }
    }

    /// 上一次成功检查的时间。
    private(set) var lastCheck = UserDefaults.standard.object(forKey: UpdateChecker.lastCheckKey) as? Date
    /// 更新的版本；没有或还没有检查时为 nil。
    private(set) var available: ReleaseInfo?
    private(set) var checking = false
    /// 上一次检查失败（网络不通、响应格式不对）。
    private(set) var failed = false

    private var timer: Timer?

    /// 应用启动后调用：到期就检查一次，之后每小时看一次是否又满 24 小时（睡眠后醒来也能补上）。
    func start() {
        schedule()
        checkIfDue()
    }

    private func schedule() {
        timer?.invalidate()
        timer = nil
        guard autoCheck else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 60 * 60, repeats: true) { _ in
            Task { @MainActor in UpdateChecker.shared.checkIfDue() }
        }
    }

    private func checkIfDue() {
        guard autoCheck, lastCheck.map({ Date().timeIntervalSince($0) >= Self.interval }) ?? true else { return }
        Task { await check() }
    }

    /// 立即检查（"立即检查"、菜单中的"检查更新…"，以及到期时）。
    func check() async {
        guard !checking, let url = URL(string: "https://api.github.com/repos/\(Self.repository)/releases?per_page=30") else { return }
        checking = true
        defer { checking = false }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("Keevo/\(version)", forHTTPHeaderField: "User-Agent")
        do {
            let (data, response) = try await URLSession(configuration: .ephemeral).data(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
            available = try newestRelease(releasesJson: String(decoding: data, as: UTF8.self), repo: Self.repository)
            failed = false
            let now = Date()
            lastCheck = now
            UserDefaults.standard.set(now, forKey: Self.lastCheckKey)
        } catch {
            failed = true
        }
    }

    /// 打开新版本的发布页。
    func openRelease() {
        guard let available, let url = URL(string: available.url) else { return }
        NSWorkspace.shared.open(url)
    }

    /// "0.1.0-alpha.1（85）"
    var versionLabel: String {
        build.map { tr("{}（{}）", version, $0) } ?? version
    }

    /// "今天 21:05"：按界面语言，今天、昨天用相对说法。
    static func checkedAt(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: UILanguage.current == .zh ? "zh_Hans" : "en_US")
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        formatter.doesRelativeDateFormatting = true
        return formatter.string(from: date)
    }
}

/// "设置 → 通用"中的"更新"一节（设计稿）。
struct UpdateSettingsSection: View {
    @Bindable private var updates = UpdateChecker.shared

    var body: some View {
        SettingsSection(title: tr("更新")) {
            SettingsRow(title: tr("自动检查更新"), detail: tr("每天一次，访问 GitHub 上公开的发布列表，不发送任何个人信息")) {
                Toggle(tr("自动检查更新"), isOn: $updates.autoCheck).kvSwitch(tr("自动检查更新"))
            }
            CardRowDivider()
            if let available = updates.available {
                SettingsRow(title: updates.versionLabel, detail: tr("有新版本 {}", available.version), emphasizeDetail: true) {
                    Button(tr("查看新版本")) { updates.openRelease() }
                        .buttonStyle(.kvPrimary)
                }
            } else {
                SettingsRow(title: updates.versionLabel, detail: status) {
                    Button(tr("立即检查")) { Task { await updates.check() } }
                        .buttonStyle(.kvBordered)
                        .disabled(updates.checking)
                }
            }
        }
    }

    private var status: String {
        if updates.checking { return tr("正在检查…") }
        if updates.failed { return tr("检查失败，请稍后再试") }
        guard let last = updates.lastCheck else { return tr("还没有检查过") }
        return tr("已是最新版本 · {} 检查过", UpdateChecker.checkedAt(last))
    }
}

/// 侧边栏底部：有新版本时多一行，点击打开发布页（设计稿）。
struct UpdateNotice: View {
    private var updates = UpdateChecker.shared

    var body: some View {
        if let available = updates.available {
            Button { updates.openRelease() } label: {
                Label(tr("有新版本 {}", available.version), systemImage: "arrow.down.circle")
                    .font(KV.Typography.footnote.weight(.semibold))
                    .foregroundStyle(KV.Colors.accentFg)
            }
            .buttonStyle(.plain)
            .help(tr("打开 GitHub 上的发布页"))
        }
    }
}
