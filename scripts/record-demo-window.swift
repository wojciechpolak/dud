// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import AVFoundation
import AppKit
import CoreGraphics
import ScreenCaptureKit

final class RecordingDelegate: NSObject, SCRecordingOutputDelegate {
    let ready: URL
    private let lock = NSLock()
    private var stopped = false
    private var failure: Error?

    init(ready: URL) {
        self.ready = ready
    }

    func recordingOutputDidStartRecording(_ recordingOutput: SCRecordingOutput) {
        do {
            try Data().write(to: ready)
        } catch {
            finish(error)
        }
    }

    func recordingOutput(_ recordingOutput: SCRecordingOutput, didFailWithError error: Error) {
        finish(error)
    }

    func recordingOutputDidFinishRecording(_ recordingOutput: SCRecordingOutput) {
        finish(nil)
    }

    private func finish(_ error: Error?) {
        lock.lock()
        failure = error
        stopped = true
        lock.unlock()
    }

    func result() -> (Bool, Error?) {
        lock.lock()
        defer { lock.unlock() }
        return (stopped, failure)
    }
}

@main
struct RecordDemoWindow {
    @MainActor
    static func main() async throws {
        NSApplication.shared.setActivationPolicy(.prohibited)
        let args = CommandLine.arguments
        guard args.count == 5, let windowID = UInt32(args[1]), let seconds = Double(args[3]), seconds > 0 else {
            throw error("Usage: record-demo-window WINDOW_ID OUTPUT.mp4 SECONDS READY_FILE")
        }
        guard CGPreflightScreenCaptureAccess() else {
            throw error("macOS Screen Recording permission is required.")
        }
        let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
        guard let window = content.windows.first(where: { $0.windowID == windowID }) else {
            throw error("The demo window is not available for capture.")
        }
        let filter = SCContentFilter(desktopIndependentWindow: window)
        let settings = SCStreamConfiguration()
        settings.width = Int(filter.contentRect.width * CGFloat(filter.pointPixelScale))
        settings.height = Int(filter.contentRect.height * CGFloat(filter.pointPixelScale))
        settings.minimumFrameInterval = CMTime(value: 1, timescale: 30)
        settings.showsCursor = false
        settings.showMouseClicks = false
        settings.capturesAudio = false
        settings.ignoreShadowsSingleWindow = true
        let destination = SCRecordingOutputConfiguration()
        destination.outputURL = URL(fileURLWithPath: args[2])
        destination.videoCodecType = .h264
        destination.outputFileType = .mp4
        let delegate = RecordingDelegate(ready: URL(fileURLWithPath: args[4]))
        let recording = SCRecordingOutput(configuration: destination, delegate: delegate)
        let stream = SCStream(filter: filter, configuration: settings, delegate: nil)
        try stream.addRecordingOutput(recording)
        try await stream.startCapture()
        try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
        try await stream.stopCapture()
        for _ in 0..<100 {
            let (finished, failure) = delegate.result()
            if let failure { throw failure }
            if finished { return }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        throw error("The demo recording did not finish writing.")
    }

    static func error(_ message: String) -> NSError {
        NSError(domain: "DUDDemoCapture", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
