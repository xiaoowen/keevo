// SPDX-License-Identifier: MIT OR Apache-2.0
//
// iCloud 云盘「普通文件夹」技术验证（docs/sync.md §6）。不需要任何证书、权限或 App ID。
//
// 在 ~/Library/Mobile Documents/com~apple~CloudDocs/Keevo-iCloud-验证/<运行 ID>/ 下写入测试文件，
// 按 Keevo 同步设计逐项验证，结束后删除整个运行目录。测试文件全部是随机字节，不含任何真实数据。
//
// 编译与运行：
//   swiftc -O spikes/icloud-folder/main.swift -o /tmp/keevo-icloud-spike
//   /tmp/keevo-icloud-spike [报告.json]

import CryptoKit
import Foundation

// MARK: - 记录

struct Step: Encodable {
    let name: String
    var ok: Bool
    var seconds: Double
    var detail: [String: String]
}

var steps: [Step] = []
let home = FileManager.default.homeDirectoryForCurrentUser.path

func sanitize(_ s: String) -> String { s.replacingOccurrences(of: home, with: "~") }

@discardableResult
func step(_ name: String, _ body: (inout [String: String]) throws -> Bool) -> Bool {
    var detail: [String: String] = [:]
    let start = Date()
    var ok = false
    do {
        ok = try body(&detail)
    } catch {
        detail["error"] = sanitize(String(describing: error))
    }
    let s = Step(name: name, ok: ok, seconds: Date().timeIntervalSince(start), detail: detail.mapValues(sanitize))
    steps.append(s)
    let fields = s.detail.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: "  ")
    print("\(ok ? "✓" : "✗") \(name)（\(String(format: "%.2f", s.seconds)) 秒）  \(fields)")
    return ok
}

// MARK: - 工具

let fm = FileManager.default
let drive = fm.homeDirectoryForCurrentUser.appendingPathComponent("Library/Mobile Documents/com~apple~CloudDocs")
let base = drive.appendingPathComponent("Keevo-iCloud-验证")
let runID: String = {
    let f = DateFormatter()
    f.dateFormat = "yyyyMMdd-HHmmss"
    return f.string(from: Date()) + "-" + String(UUID().uuidString.prefix(6))
}()
let root = base.appendingPathComponent(runID)

let keys: Set<URLResourceKey> = [
    .isUbiquitousItemKey, .ubiquitousItemIsUploadedKey, .ubiquitousItemIsUploadingKey,
    .ubiquitousItemUploadingErrorKey, .ubiquitousItemDownloadingStatusKey, .ubiquitousItemIsDownloadingKey,
]

func values(_ url: URL) -> URLResourceValues? {
    var u = url
    u.removeAllCachedResourceValues()
    return try? u.resourceValues(forKeys: keys)
}

/// 文件内容是否只在云端（APFS dataless 标志 SF_DATALESS = 0x40000000）。
func isDataless(_ url: URL) -> Bool {
    var st = stat()
    guard lstat(url.path, &st) == 0 else { return false }
    return st.st_flags & 0x4000_0000 != 0
}

func sha(_ data: Data) -> String {
    SHA256.hash(data: data).prefix(8).map { String(format: "%02x", $0) }.joined()
}

func wait(timeout: Double, interval: Double = 0.5, _ done: () -> Bool) -> Double? {
    let start = Date()
    while Date().timeIntervalSince(start) < timeout {
        if done() { return Date().timeIntervalSince(start) }
        Thread.sleep(forTimeInterval: interval)
    }
    return nil
}

/// 原子写入（sync.md §4.2）：同目录写以 . 开头的临时文件，fsync，再重命名为正式文件名。
func atomicWrite(_ data: Data, to final: URL) throws {
    var coordError: NSError?
    var inner: Error?
    NSFileCoordinator().coordinate(writingItemAt: final, options: .forReplacing, error: &coordError) { url in
        do {
            let tmp = url.deletingLastPathComponent().appendingPathComponent(".tmp-\(UUID().uuidString)")
            guard fm.createFile(atPath: tmp.path, contents: nil) else { throw CocoaError(.fileWriteUnknown) }
            let h = try FileHandle(forWritingTo: tmp)
            try h.write(contentsOf: data)
            try h.synchronize()
            try h.close()
            if rename(tmp.path, url.path) != 0 { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        } catch {
            inner = error
        }
    }
    if let e = coordError ?? inner { throw e }
}

func run(_ tool: String, _ args: [String]) -> (Int32, String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: tool)
    p.arguments = args
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = pipe
    do { try p.run() } catch { return (-1, String(describing: error)) }
    p.waitUntilExit()
    let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    return (p.terminationStatus, out.trimmingCharacters(in: .whitespacesAndNewlines))
}

// MARK: - 验证

print("Keevo iCloud 云盘普通文件夹验证 · 运行 \(runID)")
var files: [(url: URL, hash: String)] = []

let envOK = step("1 环境：iCloud 云盘可用") { d in
    d["ubiquityIdentityToken"] = fm.ubiquityIdentityToken == nil ? "nil（未签名进程拿不到，属预期）" : "存在"
    d["iCloud 云盘目录"] = fm.fileExists(atPath: drive.path) ? "存在" : "不存在"
    try fm.createDirectory(at: root, withIntermediateDirectories: true)
    let v = values(root)
    d["运行目录 isUbiquitousItem"] = String(describing: v?.isUbiquitousItem ?? false)
    return fm.fileExists(atPath: drive.path) && v?.isUbiquitousItem == true
}
guard envOK else {
    print("iCloud 云盘不可用，终止。")
    exit(1)
}

step("2 原子写入 20 个不可变文件并读回校验") { d in
    for seq in 1 ... 20 {
        var bytes = [UInt8](repeating: 0, count: 4096)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        let data = Data(bytes)
        let h = sha(data)
        let url = root.appendingPathComponent(String(format: "%010d-%@.kseg", seq, h))
        try atomicWrite(data, to: url)
        files.append((url, h))
    }
    let mismatched = try files.filter { sha(try Data(contentsOf: $0.url)) != $0.hash }.count
    let leftovers = try fm.contentsOfDirectory(atPath: root.path).filter { $0.hasPrefix(".tmp-") }.count
    d["读回不一致"] = "\(mismatched)"
    d["残留临时文件"] = "\(leftovers)"
    return mismatched == 0 && leftovers == 0
}

var uploadedAll = false
step("3 等待全部上传到 iCloud（上限 240 秒）") { d in
    var firstAt: Double?
    var polls = 0
    var pollsWithError = 0
    var errorWhileUploaded = 0
    let start = Date()
    let t = wait(timeout: 240) {
        polls += 1
        let states = files.map { values($0.url) }
        let up = states.filter { $0?.ubiquitousItemIsUploaded == true }.count
        if up > 0 && firstAt == nil { firstAt = Date().timeIntervalSince(start) }
        if let err = states.compactMap({ $0?.ubiquitousItemUploadingError }).first {
            pollsWithError += 1
            d["上传错误（原文）"] = err.localizedDescription
            d["上传错误码"] = "\((err as NSError).domain) \((err as NSError).code)"
        }
        // 同一个文件既报告"已上传"又带着上传错误：说明错误只是过期的状态，不代表失败
        errorWhileUploaded += states.filter { $0?.ubiquitousItemIsUploaded == true && $0?.ubiquitousItemUploadingError != nil }.count
        return up == files.count
    }
    Thread.sleep(forTimeInterval: 2)
    let finalErrors = files.compactMap { values($0.url)?.ubiquitousItemUploadingError }.count
    d["轮询次数 / 出现错误的轮询"] = "\(polls) / \(pollsWithError)"
    d["已上传却仍带错误（文件·次）"] = "\(errorWhileUploaded)"
    d["全部上传 2 秒后仍带错误的文件"] = "\(finalErrors)"
    d["首个文件上传完成（秒）"] = firstAt.map { String(format: "%.1f", $0) } ?? "未完成"
    d["全部上传完成（秒）"] = t.map { String(format: "%.1f", $0) } ?? "超时"
    uploadedAll = t != nil
    return uploadedAll
}

step("4 NSMetadataQuery（未签名、无 iCloud 权限）能否看到文件") { d in
    let q = NSMetadataQuery()
    q.searchScopes = [NSMetadataQueryUbiquitousDocumentsScope, NSMetadataQueryUbiquitousDataScope]
    q.predicate = NSPredicate(format: "%K BEGINSWITH %@", NSMetadataItemPathKey, root.path)
    var gathered = false
    let obs = NotificationCenter.default.addObserver(forName: .NSMetadataQueryDidFinishGathering, object: q, queue: nil) { _ in gathered = true }
    let started = q.start()
    let deadline = Date().addingTimeInterval(8)
    while !gathered && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.2)) }
    q.stop()
    NotificationCenter.default.removeObserver(obs)
    d["start()"] = "\(started)"
    d["完成收集"] = "\(gathered)"
    d["结果数"] = "\(q.resultCount)"
    // 这一项记录的是行为，不要求通过：结果为 0 说明文件夹方案的变化监听必须用 FSEvents 或目录监视
    return true
}

step("5 目录变化通知：另一进程写入后多久收到") { d in
    let fd = open(root.path, O_EVTONLY)
    guard fd >= 0 else { return false }
    defer { close(fd) }
    let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: .write, queue: .global())
    var firedAt: Date?
    source.setEventHandler { if firedAt == nil { firedAt = Date() } }
    source.resume()
    let start = Date()
    let (status, _) = run("/bin/sh", ["-c", "printf external > \"$0/external.txt\"", root.path])
    let t = wait(timeout: 5, interval: 0.02) { firedAt != nil }
    source.cancel()
    d["外部写入退出码"] = "\(status)"
    d["收到通知（毫秒）"] = firedAt.map { String(format: "%.0f", $0.timeIntervalSince(start) * 1000) } ?? "未收到"
    return t != nil
}

if uploadedAll && files.count >= 3 {
    let targets = Array(files.prefix(3))

    step("6 从本机移除 3 个文件的内容（evict）") { d in
        var apiErrors = 0
        for f in targets {
            do { try fm.evictUbiquitousItem(at: f.url) } catch {
                apiErrors += 1
                d["evict API 错误"] = error.localizedDescription
                _ = run("/usr/bin/brctl", ["evict", f.url.path])
            }
        }
        d["evict API 失败次数（失败时改用 brctl）"] = "\(apiErrors)"
        let t = wait(timeout: 30) {
            targets.allSatisfy { isDataless($0.url) || values($0.url)?.ubiquitousItemDownloadingStatus == .notDownloaded }
        }
        d["变为仅云端（秒）"] = t.map { String(format: "%.1f", $0) } ?? "超时"
        d["dataless 标志"] = targets.map { isDataless($0.url) ? "是" : "否" }.joined(separator: "/")
        d["下载状态"] = targets.map { values($0.url)?.ubiquitousItemDownloadingStatus?.rawValue ?? "?" }.joined(separator: " / ")
        return t != nil
    }

    step("7 显式请求下载（startDownloadingUbiquitousItem）") { d in
        let f = targets[0]
        try fm.startDownloadingUbiquitousItem(at: f.url)
        let t = wait(timeout: 60) { values(f.url)?.ubiquitousItemDownloadingStatus == .current && !isDataless(f.url) }
        d["下载完成（秒）"] = t.map { String(format: "%.1f", $0) } ?? "超时"
        let ok = t != nil && (try? sha(Data(contentsOf: f.url))) == f.hash
        d["内容校验"] = ok ? "一致" : "不一致或未下载"
        return ok
    }

    step("8 直接读取仅云端的文件（不先请求下载）") { d in
        let f = targets[1]
        d["读取前 dataless"] = isDataless(f.url) ? "是" : "否"
        let start = Date()
        let data = try Data(contentsOf: f.url)
        d["读取耗时（秒）"] = String(format: "%.2f", Date().timeIntervalSince(start))
        d["读到字节数"] = "\(data.count)"
        let ok = sha(data) == f.hash
        d["内容校验"] = ok ? "一致（读取会自动触发下载）" : "不一致"
        return ok
    }

    step("9 用 NSFileCoordinator 读取仅云端的文件") { d in
        let f = targets[2]
        d["读取前 dataless"] = isDataless(f.url) ? "是" : "否"
        var coordError: NSError?
        var data: Data?
        let start = Date()
        NSFileCoordinator().coordinate(readingItemAt: f.url, options: [], error: &coordError) { url in
            data = try? Data(contentsOf: url)
        }
        if let e = coordError { throw e }
        d["读取耗时（秒）"] = String(format: "%.2f", Date().timeIntervalSince(start))
        let ok = data.map(sha) == f.hash
        d["内容校验"] = ok ? "一致" : "不一致"
        return ok
    }
} else {
    print("跳过 6–9：上传未完成，无法测试移除与按需下载。")
}

step("10 清理：删除运行目录") { d in
    var coordError: NSError?
    var inner: Error?
    NSFileCoordinator().coordinate(writingItemAt: root, options: .forDeleting, error: &coordError) { url in
        do { try fm.removeItem(at: url) } catch { inner = error }
    }
    if let e = coordError ?? inner { throw e }
    if let rest = try? fm.contentsOfDirectory(atPath: base.path), rest.filter({ !$0.hasPrefix(".") }).isEmpty {
        try? fm.removeItem(at: base)
        d["父目录"] = "已删除（为空）"
    }
    return !fm.fileExists(atPath: root.path)
}

// MARK: - 报告

struct Report: Encodable {
    let runID: String
    let macOS: String
    let steps: [Step]
}

let report = Report(runID: runID, macOS: ProcessInfo.processInfo.operatingSystemVersionString, steps: steps)
if CommandLine.arguments.count > 1 {
    let enc = JSONEncoder()
    enc.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    try enc.encode(report).write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
}
let failed = steps.filter { !$0.ok }.count
print(failed == 0 ? "全部通过（\(steps.count) 项）" : "失败 \(failed) 项")
exit(failed == 0 ? 0 : 1)
