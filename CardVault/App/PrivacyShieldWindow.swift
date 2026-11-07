import SwiftUI
import UIKit
import UIKit.UIGestureRecognizerSubclass

/// Owns a dedicated UIKit window above the entire app (including alerts and sheets) that hides all content.
///
/// Shown *synchronously* from `willResignActive` (observer with `queue: nil`, followed by
/// `CATransaction.flush()`), so it is already composited when iOS takes the app-switcher
/// snapshot. Also covers the whole UI from frame 0 if screen recording or mirroring is active.
@MainActor
final class PrivacyShieldWindowManager {
    static let shared = PrivacyShieldWindowManager()
    /// Strictly above both `.statusBar` (1000) and `.alert` (2000) so open confirmation dialogs / alerts
    /// displaying card names or prompts are 100% covered in app-switcher snapshots and screen recordings.
    static let shieldWindowLevel = UIWindow.Level(
        rawValue: max(UIWindow.Level.alert.rawValue, UIWindow.Level.statusBar.rawValue) + 500
    )

    enum Reason: Hashable {
        case inactive
        case captured
    }

    /// Called on every touch anywhere in the app (drives the foreground idle lock).
    var activityHandler: (() -> Void)?

    private var reasons = Set<Reason>()
    private var shieldWindow: UIWindow?
    private var hostingController: UIHostingController<PrivacyShieldView>?
    private var observers: [NSObjectProtocol] = []
    private weak var monitoredWindow: UIWindow?
    private var started = false

    private init() {}

    func start() {
        guard !started else { return }
        started = true

        let center = NotificationCenter.default
        observers.append(center.addObserver(
            forName: UIScene.willConnectNotification, object: nil, queue: nil
        ) { _ in
            Self.performOnMain { Self.shared.refreshCaptureState() }
        })
        observers.append(center.addObserver(
            forName: UIScene.didActivateNotification, object: nil, queue: nil
        ) { _ in
            Self.performOnMain {
                Self.shared.refreshCaptureState()
                Self.shared.installActivityMonitorIfNeeded()
            }
        })
        observers.append(center.addObserver(
            forName: UIApplication.willResignActiveNotification, object: nil, queue: nil
        ) { _ in
            Self.performOnMain { Self.shared.setReason(.inactive, active: true) }
        })
        observers.append(center.addObserver(
            forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: nil
        ) { _ in
            Self.performOnMain { Self.shared.setReason(.inactive, active: true) }
        })
        observers.append(center.addObserver(
            forName: UIApplication.didBecomeActiveNotification, object: nil, queue: nil
        ) { _ in
            Self.performOnMain {
                Self.shared.refreshCaptureState()
                Self.shared.installActivityMonitorIfNeeded()
                // Keep the shield up until VaultStore has re-evaluated auto-lock on return and SwiftUI has
                // committed the locked UI, so unlocked card content can never flash for a single frame.
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.12) {
                    guard UIApplication.shared.applicationState == .active else { return }
                    Self.shared.setReason(.inactive, active: false)
                }
            }
        })
        observers.append(center.addObserver(
            forName: UIScreen.capturedDidChangeNotification, object: nil, queue: nil
        ) { _ in
            Self.performOnMain { Self.shared.refreshCaptureState() }
        })

        refreshCaptureState()
    }

    /// Executes synchronously when already on the main thread (preserving 0ms snapshot protection),
    /// and hops safely to the main queue if a system notification ever posts off-main-thread.
    private nonisolated static func performOnMain(_ block: @escaping @Sendable @MainActor () -> Void) {
        if Thread.isMainThread {
            MainActor.assumeIsolated(block)
        } else {
            DispatchQueue.main.async(execute: block)
        }
    }

    func refreshCaptureState() {
        let sceneCaptured = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .contains { $0.screen.isCaptured }
        setReason(.captured, active: sceneCaptured)
    }

    private func setReason(_ reason: Reason, active: Bool) {
        if active {
            reasons.insert(reason)
        } else {
            reasons.remove(reason)
        }
        render()
    }

    private func render() {
        guard !reasons.isEmpty else {
            shieldWindow?.isHidden = true
            shieldWindow = nil
            hostingController = nil
            return
        }

        let style: PrivacyShieldView.Style = reasons.contains(.captured) ? .captured : .inactive
        if let hostingController {
            hostingController.rootView = PrivacyShieldView(style: style)
        } else if let scene = Self.targetScene() {
            let host = UIHostingController(rootView: PrivacyShieldView(style: style))
            host.view.backgroundColor = .black
            let window = UIWindow(windowScene: scene)
            window.windowLevel = Self.shieldWindowLevel
            window.rootViewController = host
            window.isHidden = false
            shieldWindow = window
            hostingController = host
        }
        shieldWindow?.layoutIfNeeded()
        CATransaction.flush()
    }

    private static func targetScene() -> UIWindowScene? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        return scenes.first { $0.activationState == .foregroundActive }
            ?? scenes.first { $0.activationState == .foregroundInactive }
            ?? scenes.first
    }

    private func installActivityMonitorIfNeeded() {
        guard let scene = Self.targetScene(),
              let mainWindow = scene.windows.first(where: { $0 !== shieldWindow }) else { return }
        guard monitoredWindow !== mainWindow else { return }

        let recognizer = ActivityTouchRecognizer { [weak self] in
            self?.activityHandler?()
        }
        mainWindow.addGestureRecognizer(recognizer)
        monitoredWindow = mainWindow
    }
}

/// Observes touches without interfering with any other gesture or control.
final class ActivityTouchRecognizer: UIGestureRecognizer, UIGestureRecognizerDelegate {
    private let onTouch: () -> Void

    init(onTouch: @escaping () -> Void) {
        self.onTouch = onTouch
        super.init(target: nil, action: nil)
        cancelsTouchesInView = false
        delaysTouchesBegan = false
        delaysTouchesEnded = false
        delegate = self
    }

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
        onTouch()
        state = .failed
    }

    func gestureRecognizer(
        _ gestureRecognizer: UIGestureRecognizer,
        shouldRecognizeSimultaneouslyWith otherGestureRecognizer: UIGestureRecognizer
    ) -> Bool {
        true
    }
}
