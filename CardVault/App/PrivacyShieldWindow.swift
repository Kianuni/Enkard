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
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.refreshCaptureState() }
        })
        observers.append(center.addObserver(
            forName: UIScene.didActivateNotification, object: nil, queue: nil
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.refreshCaptureState()
                self?.installActivityMonitorIfNeeded()
            }
        })
        observers.append(center.addObserver(
            forName: UIApplication.willResignActiveNotification, object: nil, queue: nil
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.setReason(.inactive, active: true) }
        })
        observers.append(center.addObserver(
            forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: nil
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.setReason(.inactive, active: true) }
        })
        observers.append(center.addObserver(
            forName: UIApplication.didBecomeActiveNotification, object: nil, queue: nil
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.setReason(.inactive, active: false)
                self?.refreshCaptureState()
                self?.installActivityMonitorIfNeeded()
            }
        })
        observers.append(center.addObserver(
            forName: UIScreen.capturedDidChangeNotification, object: nil, queue: nil
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.refreshCaptureState() }
        })

        refreshCaptureState()
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
            window.windowLevel = .statusBar + 100
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
