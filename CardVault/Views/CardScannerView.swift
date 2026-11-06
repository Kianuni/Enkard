import AVFoundation
import Combine
import SwiftUI
import UIKit
import Vision

/// Volatile-memory-only bank card scanner using Apple's on-device `Vision` Neural Engine.
///
/// Security guarantees:
/// 1. Zero disk writes: uses `AVCaptureVideoDataOutput` transient YUV `CVPixelBuffer`s only — never captures photos,
///    never encodes JPEG/PNG/HEIC, never accesses Photo Library, and drops late frames immediately.
/// 2. Anti-screenshot & anti-recording: embeds the live preview layer inside `SecureCanvasSupport` (`isSecureTextEntry`)
///    and immediately cuts camera power if screen recording (`UIScreen.isCaptured`), app backgrounding, or vault lock occurs.
/// 3. Front-side only: extracts Luhn-verified PAN, expiry (`MM/YY`), and cardholder name; never prompts for rear CVV.
struct CardScannerSheet: View {
    @ObservedObject var store: VaultStore
    let onScanned: (ScannedCardCandidate) -> Void

    @Environment(\.dismiss) private var dismiss
    @StateObject private var scanner = CardScannerController()

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()

                switch scanner.state {
                case .preparing:
                    VStack(spacing: 14) {
                        ProgressView()
                            .tint(.white)
                            .scaleEffect(1.2)
                        Text("正在初始化本地安全相机流...")
                            .font(.subheadline)
                            .foregroundStyle(.white.opacity(0.8))
                    }

                case .unauthorized:
                    permissionUnavailableView(
                        icon: "camera.macro.slash",
                        fallbackIcon: "video.slash.fill",
                        title: "未开启相机权限",
                        message: "请在 iPhone「设置 → App → CardSe → 相机」中允许访问，或返回直接手动输入卡号。\n\nCardSe 仅在内存中实时提取卡号数字，绝不拍照存档、绝不访问相册。"
                    )

                case .unavailable(let reason):
                    permissionUnavailableView(
                        icon: "exclamationmark.triangle.fill",
                        fallbackIcon: "exclamationmark.triangle.fill",
                        title: "当前无法启用相机扫描",
                        message: reason
                    )

                case .running:
                    SecureCameraPreviewRepresentable(session: scanner.captureSession)
                        .ignoresSafeArea()
                        .privacySensitive()

                    scannerOverlayHUD
                }
            }
            .navigationTitle("扫描银行卡正面")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarColorScheme(.dark, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbarBackground(Color.black.opacity(0.75), for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") {
                        scanner.stopAndScrub()
                        dismiss()
                    }
                    .foregroundStyle(.white)
                }

                if scanner.hasTorch && scanner.state == .running {
                    ToolbarItem(placement: .confirmationAction) {
                        Button {
                            scanner.toggleTorch()
                        } label: {
                            Image(systemName: scanner.isTorchOn ? "flashlight.on.fill" : "flashlight.off.fill")
                                .foregroundStyle(scanner.isTorchOn ? Color.yellow : Color.white)
                        }
                        .accessibilityLabel(scanner.isTorchOn ? "关闭补光灯" : "开启补光灯")
                    }
                }
            }
            .onAppear {
                guard !store.isScreenCaptured else {
                    scanner.stopAndScrub()
                    dismiss()
                    return
                }
                scanner.onConfirmed = { candidate in
                    store.noteActivity()
                    UINotificationFeedbackGenerator().notificationOccurred(.success)
                    onScanned(candidate)
                    scanner.stopAndScrub()
                    dismiss()
                }
                scanner.startIfPermitted()
            }
            .onDisappear {
                scanner.stopAndScrub()
            }
            .onValueChange(of: store.isScreenCaptured) { captured in
                if captured {
                    scanner.stopAndScrub()
                    dismiss()
                }
            }
            .onValueChange(of: store.phase) { newPhase in
                if newPhase != .unlocked {
                    scanner.stopAndScrub()
                    dismiss()
                }
            }
            .onReceive(NotificationCenter.default.publisher(for: UIApplication.willResignActiveNotification)) { _ in
                scanner.stopAndScrub()
                dismiss()
            }
            .onReceive(NotificationCenter.default.publisher(for: UIApplication.didEnterBackgroundNotification)) { _ in
                scanner.stopAndScrub()
                dismiss()
            }
        }
    }

    private var scannerOverlayHUD: some View {
        GeometryReader { geo in
            let horizontalPadding: CGFloat = 24
            let frameWidth = max(220, geo.size.width - horizontalPadding * 2)
            let frameHeight = frameWidth / 1.586

            VStack(spacing: 20) {
                // Security Assurance Pill
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundStyle(Color(red: 0.35, green: 0.88, blue: 0.58))
                    Text("纯内存离线识别 · 零拍照零落盘 · 防截屏保护中")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.white)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .background(Color.black.opacity(0.68), in: Capsule())
                .padding(.top, 14)

                Spacer(minLength: 8)

                // Credit Card Alignment Frame
                ZStack {
                    RoundedRectangle(cornerRadius: 20, style: .continuous)
                        .strokeBorder(
                            scanner.provisionalCandidate != nil
                                ? Color(red: 0.35, green: 0.88, blue: 0.58)
                                : Color(red: 0.95, green: 0.82, blue: 0.52),
                            lineWidth: 2.6
                        )
                        .background(
                            RoundedRectangle(cornerRadius: 20, style: .continuous)
                                .fill(Color.white.opacity(0.03))
                        )

                    VStack {
                        HStack {
                            Text("请将银行卡正面对准框内")
                                .font(.caption.weight(.medium))
                                .foregroundStyle(.white.opacity(0.88))
                                .padding(.horizontal, 10)
                                .padding(.vertical, 5)
                                .background(Color.black.opacity(0.55), in: Capsule())
                            Spacer()
                        }
                        Spacer()
                        HStack {
                            Text("6225  ••••  ••••  8888")
                                .font(.system(size: 16, weight: .semibold, design: .monospaced))
                                .foregroundStyle(.white.opacity(0.32))
                            Spacer()
                        }
                    }
                    .padding(18)
                }
                .frame(width: frameWidth, height: frameHeight)
                .shadow(color: .black.opacity(0.55), radius: 18)

                // Provisional instant-accept button if 1 frame already passed Luhn
                if let provisional = scanner.provisionalCandidate {
                    Button {
                        scanner.acceptProvisionalImmediately()
                    } label: {
                        HStack(spacing: 8) {
                            ProgressView()
                                .tint(.black)
                                .scaleEffect(0.85)
                            Text("已识别尾号 \(String(provisional.cardNumber.suffix(4))) · 点击立即填入")
                                .font(.subheadline.weight(.semibold))
                                .foregroundStyle(.black)
                        }
                        .padding(.horizontal, 18)
                        .padding(.vertical, 11)
                        .background(
                            Color(red: 0.95, green: 0.82, blue: 0.52),
                            in: Capsule()
                        )
                    }
                    .buttonStyle(.plain)
                } else {
                    Text("自动校验 Luhn 卡号位、有效期与姓名\n请勿翻转拍摄背面 CVV 安全码")
                        .font(.footnote)
                        .foregroundStyle(.white.opacity(0.78))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 28)
                        .padding(.vertical, 8)
                        .background(Color.black.opacity(0.52), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                }

                Spacer(minLength: 24)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func permissionUnavailableView(
        icon: String,
        fallbackIcon: String,
        title: String,
        message: String
    ) -> some View {
        VStack(spacing: 18) {
            Image(systemName: UIImage(systemName: icon) != nil ? icon : fallbackIcon)
                .font(.system(size: 42, weight: .semibold))
                .foregroundStyle(Color(red: 0.95, green: 0.82, blue: 0.52))

            Text(title)
                .font(.title3.bold())
                .foregroundStyle(.white)

            Text(message)
                .font(.subheadline)
                .foregroundStyle(.white.opacity(0.75))
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)

            Button {
                scanner.stopAndScrub()
                dismiss()
            } label: {
                Text("返回手动输入")
                    .fontWeight(.semibold)
                    .padding(.horizontal, 24)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.borderedProminent)
            .padding(.top, 6)
        }
    }
}

// MARK: - Screenshot-Protected Live Camera Preview

private final class CameraPreviewLayerView: UIView {
    override class var layerClass: AnyClass {
        AVCaptureVideoPreviewLayer.self
    }

    var previewLayer: AVCaptureVideoPreviewLayer {
        // Guaranteed by `layerClass` override above.
        layer as! AVCaptureVideoPreviewLayer
    }

    override func layoutSubviews() {
        super.layoutSubviews()
        applyPortraitOrientation()
    }

    override func didMoveToWindow() {
        super.didMoveToWindow()
        applyPortraitOrientation()
        DispatchQueue.main.async { [weak self] in
            self?.applyPortraitOrientation()
        }
    }

    func bind(session: AVCaptureSession) {
        if previewLayer.session !== session {
            previewLayer.session = session
        }
        previewLayer.videoGravity = .resizeAspectFill
        applyPortraitOrientation()
    }

    private func applyPortraitOrientation() {
        guard let connection = previewLayer.connection else { return }
        if #available(iOS 17.0, *) {
            if connection.isVideoRotationAngleSupported(90) {
                connection.videoRotationAngle = 90
            }
        } else {
            if connection.isVideoOrientationSupported {
                connection.videoOrientation = .portrait
            }
        }
    }
}

private final class SecureCameraContainerView: UIView {
    private let previewView = CameraPreviewLayerView()
    private var retainedSecureField: UITextField?

    init(session: AVCaptureSession) {
        super.init(frame: .zero)
        backgroundColor = .black
        isUserInteractionEnabled = false
        previewView.bind(session: session)

        if let pair = SecureCanvasSupport.makeSecurePair(),
           pair.canvas.isDescendant(of: pair.ownerField) {
            retainedSecureField = pair.ownerField
            let field = pair.ownerField
            let canvas = pair.canvas

            field.translatesAutoresizingMaskIntoConstraints = false
            previewView.translatesAutoresizingMaskIntoConstraints = false
            addSubview(field)
            canvas.addSubview(previewView)

            NSLayoutConstraint.activate([
                field.leadingAnchor.constraint(equalTo: leadingAnchor),
                field.trailingAnchor.constraint(equalTo: trailingAnchor),
                field.topAnchor.constraint(equalTo: topAnchor),
                field.bottomAnchor.constraint(equalTo: bottomAnchor),
                previewView.leadingAnchor.constraint(equalTo: canvas.leadingAnchor),
                previewView.trailingAnchor.constraint(equalTo: canvas.trailingAnchor),
                previewView.topAnchor.constraint(equalTo: canvas.topAnchor),
                previewView.bottomAnchor.constraint(equalTo: canvas.bottomAnchor)
            ])
        } else {
            previewView.translatesAutoresizingMaskIntoConstraints = false
            addSubview(previewView)
            NSLayoutConstraint.activate([
                previewView.leadingAnchor.constraint(equalTo: leadingAnchor),
                previewView.trailingAnchor.constraint(equalTo: trailingAnchor),
                previewView.topAnchor.constraint(equalTo: topAnchor),
                previewView.bottomAnchor.constraint(equalTo: bottomAnchor)
            ])
        }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func update(session: AVCaptureSession) {
        previewView.bind(session: session)
    }
}

private struct SecureCameraPreviewRepresentable: UIViewRepresentable {
    let session: AVCaptureSession

    func makeUIView(context: Context) -> SecureCameraContainerView {
        SecureCameraContainerView(session: session)
    }

    func updateUIView(_ uiView: SecureCameraContainerView, context: Context) {
        uiView.update(session: session)
    }
}

// MARK: - Camera & Vision Pipeline Controller

@MainActor
final class CardScannerController: NSObject, ObservableObject {
    enum ScannerState: Equatable {
        case preparing
        case running
        case unauthorized
        case unavailable(String)
    }

    @Published private(set) var state: ScannerState = .preparing
    @Published private(set) var hasTorch: Bool = false
    @Published private(set) var isTorchOn: Bool = false
    @Published private(set) var provisionalCandidate: ScannedCardCandidate?

    var onConfirmed: ((ScannedCardCandidate) -> Void)?

    nonisolated let captureSession = AVCaptureSession()

    private let sessionQueue = DispatchQueue(label: "com.local.cardse.scanner.session", qos: .userInitiated)
    private let videoOutputQueue = DispatchQueue(label: "com.local.cardse.scanner.video", qos: .userInitiated)
    private let workerGate = FrameWorkerGate()
    private var isConfigured = false
    private var hasCompleted = false
    private var activeVideoDevice: AVCaptureDevice?

    func startIfPermitted() {
        #if !DEBUG
        if RuntimeSecurity.isDebuggerAttached() {
            state = .unavailable("检测到外部调试器附加，已拒绝启用安全相机流。")
            return
        }
        #endif

        hasCompleted = false
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            bootSession()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    guard let self else { return }
                    if granted {
                        self.bootSession()
                    } else {
                        self.state = .unauthorized
                    }
                }
            }
        case .denied, .restricted:
            state = .unauthorized
        @unknown default:
            state = .unauthorized
        }
    }

    func acceptProvisionalImmediately() {
        guard !hasCompleted, var candidate = provisionalCandidate else { return }
        hasCompleted = true
        let delivered = candidate
        candidate.scrub()
        provisionalCandidate = nil
        onConfirmed?(delivered)
    }

    func toggleTorch() {
        let sessionQueueRef = sessionQueue
        let deviceRef = activeVideoDevice
        sessionQueueRef.async { [weak self] in
            guard let device = deviceRef, device.hasTorch else { return }
            var nowOn = false
            do {
                try device.lockForConfiguration()
                if device.torchMode == .on {
                    device.torchMode = .off
                    nowOn = false
                } else if device.isTorchModeSupported(.on) {
                    try device.setTorchModeOn(level: 0.65)
                    nowOn = true
                }
                device.unlockForConfiguration()
            } catch {
                nowOn = false
            }
            let torchState = nowOn
            DispatchQueue.main.async { [weak self] in
                self?.isTorchOn = torchState
            }
        }
    }

    func stopAndScrub() {
        workerGate.resetAndSuspend()
        provisionalCandidate?.scrub()
        provisionalCandidate = nil
        isTorchOn = false

        let session = captureSession
        let deviceRef = activeVideoDevice
        sessionQueue.async {
            if let device = deviceRef, device.hasTorch, device.torchMode != .off {
                if (try? device.lockForConfiguration()) != nil {
                    device.torchMode = .off
                    device.unlockForConfiguration()
                }
            }
            if session.isRunning {
                session.stopRunning()
            }
        }
    }

    private func bootSession() {
        workerGate.resume()
        let alreadyConfigured = isConfigured
        let session = captureSession
        let outputQueue = videoOutputQueue

        sessionQueue.async { [weak self] in
            guard let self else { return }

            if !alreadyConfigured {
                guard let camera = Self.selectBestBackCamera() else {
                    DispatchQueue.main.async { [weak self] in
                        self?.state = .unavailable("当前设备未检测到可用后置摄像头，请返回手动输入卡号。")
                    }
                    return
                }

                let input: AVCaptureDeviceInput
                do {
                    input = try AVCaptureDeviceInput(device: camera)
                } catch {
                    DispatchQueue.main.async { [weak self] in
                        self?.state = .unavailable("无法初始化安全相机输入流：\(error.localizedDescription)")
                    }
                    return
                }

                Self.configureNearAutoFocus(camera)

                let output = AVCaptureVideoDataOutput()
                output.alwaysDiscardsLateVideoFrames = true
                output.videoSettings = [
                    kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_420YpCbCr8BiPlanarFullRange
                ]
                output.setSampleBufferDelegate(self, queue: outputQueue)

                session.beginConfiguration()
                if session.canSetSessionPreset(.hd1920x1080) {
                    session.sessionPreset = .hd1920x1080
                } else {
                    session.sessionPreset = .high
                }

                guard session.canAddInput(input), session.canAddOutput(output) else {
                    session.commitConfiguration()
                    DispatchQueue.main.async { [weak self] in
                        self?.state = .unavailable("当前设备不支持安全视频帧流管线，请返回手动输入。")
                    }
                    return
                }
                session.addInput(input)
                session.addOutput(output)
                session.commitConfiguration()

                let torchAvailable = camera.hasTorch
                DispatchQueue.main.async { [weak self] in
                    self?.activeVideoDevice = camera
                    self?.isConfigured = true
                    self?.hasTorch = torchAvailable
                }
            }

            if !session.isRunning {
                session.startRunning()
            }
            DispatchQueue.main.async { [weak self] in
                guard let self, !self.hasCompleted else { return }
                self.state = .running
            }
        }
    }

    /// Prefers virtual multi-camera devices on Pro iPhones so close-up cards automatically engage macro focus.
    private nonisolated static func selectBestBackCamera() -> AVCaptureDevice? {
        let preferredTypes: [AVCaptureDevice.DeviceType] = [
            .builtInTripleCamera,
            .builtInDualWideCamera,
            .builtInDualCamera,
            .builtInWideAngleCamera
        ]
        let discovery = AVCaptureDevice.DiscoverySession(
            deviceTypes: preferredTypes,
            mediaType: .video,
            position: .back
        )
        return discovery.devices.first ?? AVCaptureDevice.default(for: .video)
    }

    private nonisolated static func configureNearAutoFocus(_ device: AVCaptureDevice) {
        guard (try? device.lockForConfiguration()) != nil else { return }
        defer { device.unlockForConfiguration() }

        if device.isFocusModeSupported(.continuousAutoFocus) {
            device.focusMode = .continuousAutoFocus
        }
        if device.isAutoFocusRangeRestrictionSupported {
            device.autoFocusRangeRestriction = .near
        }
        if device.isExposureModeSupported(.continuousAutoExposure) {
            device.exposureMode = .continuousAutoExposure
        }
    }
}

extension CardScannerController: AVCaptureVideoDataOutputSampleBufferDelegate {
    nonisolated func captureOutput(
        _ output: AVCaptureOutput,
        didOutput sampleBuffer: CMSampleBuffer,
        from connection: AVCaptureConnection
    ) {
        #if !DEBUG
        if RuntimeSecurity.isDebuggerAttached() {
            DispatchQueue.main.async { [weak self] in
                self?.stopAndScrub()
            }
            return
        }
        #endif

        guard workerGate.tryAcquireFrameSlot() else { return }
        defer { workerGate.releaseFrameSlot() }

        guard let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }

        let request = VNRecognizeTextRequest()
        request.recognitionLevel = .accurate
        request.usesLanguageCorrection = false
        if let supported = try? request.supportedRecognitionLanguages() {
            let preferred = ["en-US", "zh-Hans"].filter { supported.contains($0) }
            request.recognitionLanguages = preferred.isEmpty ? ["en-US"] : preferred
        } else {
            request.recognitionLanguages = ["en-US"]
        }
        request.minimumTextHeight = 0.020
        // Central card region of interest speeds up Neural Engine inference and ignores peripheral desk text.
        request.regionOfInterest = CGRect(x: 0.03, y: 0.18, width: 0.94, height: 0.64)

        let orientation: CGImagePropertyOrientation =
            CVPixelBufferGetWidth(pixelBuffer) > CVPixelBufferGetHeight(pixelBuffer) ? .right : .up
        let handler = VNImageRequestHandler(cvPixelBuffer: pixelBuffer, orientation: orientation, options: [:])
        do {
            try handler.perform([request])
        } catch {
            return
        }

        guard let observations = request.results, !observations.isEmpty else { return }
        let blocks: [RecognizedTextBlock] = observations.compactMap { obs in
            guard let top = obs.topCandidates(1).first else { return nil }
            return RecognizedTextBlock(text: top.string, boundingBox: obs.boundingBox)
        }

        let parsed = CardOCRParser.parseFrame(blocks)
        let outcome = workerGate.ingest(parsed)

        switch outcome {
        case .none:
            break
        case .provisional(let candidate):
            DispatchQueue.main.async { [weak self] in
                guard let self, !self.hasCompleted else { return }
                self.provisionalCandidate = candidate
            }
        case .confirmed(let candidate):
            workerGate.resetAndSuspend()
            DispatchQueue.main.async { [weak self] in
                guard let self, !self.hasCompleted else { return }
                self.hasCompleted = true
                self.provisionalCandidate = nil
                self.onConfirmed?(candidate)
            }
        }
    }
}

/// Thread-safe throttle and multi-frame consensus gate shared between `@MainActor` UI and `videoOutputQueue`.
private final class FrameWorkerGate: @unchecked Sendable {
    private let lock = NSLock()
    private var isProcessing = false
    private var isSuspended = false
    private var lastFrameTimeNs: UInt64 = 0
    private var accumulator = CardScanConsensusAccumulator(requiredConfirmations: 2)

    /// Limits OCR rate to ~11 FPS (`90ms` spacing) with zero queued backlog.
    func tryAcquireFrameSlot() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !isSuspended, !isProcessing else { return false }
        let now = DispatchTime.now().uptimeNanoseconds
        guard now - lastFrameTimeNs >= 90_000_000 else { return false }
        isProcessing = true
        lastFrameTimeNs = now
        return true
    }

    func releaseFrameSlot() {
        lock.lock()
        isProcessing = false
        lock.unlock()
    }

    func ingest(_ candidate: ScannedCardCandidate?) -> CardScanConsensusAccumulator.Outcome {
        lock.lock()
        defer { lock.unlock() }
        guard !isSuspended else { return .none }
        return accumulator.ingest(candidate)
    }

    func resume() {
        lock.lock()
        isSuspended = false
        accumulator.reset()
        lock.unlock()
    }

    func resetAndSuspend() {
        lock.lock()
        isSuspended = true
        accumulator.reset()
        lock.unlock()
    }
}
