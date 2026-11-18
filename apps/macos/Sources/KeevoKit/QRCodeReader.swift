// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）

import CoreImage
import Foundation
import ScreenCaptureKit

/// 从图片中识别二维码（docs/product.md §5.4"添加方式"）。只在本机用 CoreImage 识别，图片不离开这台 Mac。
public enum QRCodeReader {
    /// 识别图片中的全部二维码，返回其中的文本。
    public static func decode(_ image: CGImage) -> [String] {
        let detector = CIDetector(
            ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]
        )
        let features = detector?.features(in: CIImage(cgImage: image)) ?? []
        return features.compactMap { ($0 as? CIQRCodeFeature)?.messageString }
    }

    /// 识别图片文件（拖入的截图、选择的文件）中的二维码。
    public static func decode(contentsOf url: URL) -> [String] {
        guard let source = CGImageSourceCreateWithURL(url as CFURL, nil),
              let image = CGImageSourceCreateImageAtIndex(source, 0, nil)
        else { return [] }
        return decode(image)
    }

    /// 识别图片数据（粘贴的图片）中的二维码。
    public static func decode(data: Data) -> [String] {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              let image = CGImageSourceCreateImageAtIndex(source, 0, nil)
        else { return [] }
        return decode(image)
    }

    /// 在识别结果中挑出一次性密码：第一个 `otpauth://totp/` URI。
    public static func otpURI(in texts: [String]) -> String? {
        texts.first { $0.lowercased().hasPrefix("otpauth://totp/") }
    }
}

/// 扫描屏幕上的二维码：弹出系统的内容共享选择器，由用户选一个窗口或屏幕，截取一帧后识别。
///
/// 使用 `SCContentSharingPicker`，用户在系统界面中明确选择要共享的内容，因此不需要长期的"屏幕录制"权限
/// （docs/product.md §5.4）。截取的画面只在内存中识别，不保存。
@MainActor
public final class ScreenQRScanner: NSObject, SCContentSharingPickerObserver {
    public enum ScanError: Error {
        case cancelled
        case failed
    }

    public static let shared = ScreenQRScanner()
    private var continuation: CheckedContinuation<[String], Error>?

    /// 让用户选择内容并识别其中的二维码。用户取消时抛出 `ScanError.cancelled`。
    public func scan() async throws -> [String] {
        guard continuation == nil else { throw ScanError.failed }
        let picker = SCContentSharingPicker.shared
        var configuration = SCContentSharingPickerConfiguration()
        configuration.allowedPickerModes = [.singleWindow, .singleDisplay]
        picker.defaultConfiguration = configuration
        picker.add(self)
        picker.isActive = true
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            picker.present()
        }
    }

    private func finish(_ result: Result<[String], Error>) {
        let picker = SCContentSharingPicker.shared
        picker.remove(self)
        picker.isActive = false
        continuation?.resume(with: result)
        continuation = nil
    }

    nonisolated public func contentSharingPicker(
        _ picker: SCContentSharingPicker, didUpdateWith filter: SCContentFilter, for stream: SCStream?
    ) {
        Task { @MainActor in
            do {
                let configuration = SCStreamConfiguration()
                let scale = CGFloat(filter.pointPixelScale)
                configuration.width = Int(filter.contentRect.width * scale)
                configuration.height = Int(filter.contentRect.height * scale)
                configuration.showsCursor = false
                let image = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: configuration)
                self.finish(.success(QRCodeReader.decode(image)))
            } catch {
                self.finish(.failure(ScanError.failed))
            }
        }
    }

    nonisolated public func contentSharingPicker(_ picker: SCContentSharingPicker, didCancelFor stream: SCStream?) {
        Task { @MainActor in self.finish(.failure(ScanError.cancelled)) }
    }

    nonisolated public func contentSharingPickerStartDidFailWithError(_ error: Error) {
        Task { @MainActor in self.finish(.failure(ScanError.failed)) }
    }
}
