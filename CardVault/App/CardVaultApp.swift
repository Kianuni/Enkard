import SwiftUI
import UIKit

/// Explicit `UIWindowSceneDelegate` lifecycle compatible with iOS 16 through iOS 27+ strict scene enforcement.
final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    private static var inputHygieneObservers: [NSObjectProtocol] = []

    func scene(
        _ scene: UIScene,
        willConnectTo session: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions
    ) {
        guard let windowScene = scene as? UIWindowScene else { return }
        Self.configureGlobalInputHygieneOnce()

        let rootController = UIHostingController(rootView: RootBootstrapView())
        rootController.view.backgroundColor = UIColor(red: 0.06, green: 0.07, blue: 0.11, alpha: 1.0)

        let mainWindow = UIWindow(windowScene: windowScene)
        mainWindow.backgroundColor = UIColor(red: 0.06, green: 0.07, blue: 0.11, alpha: 1.0)
        mainWindow.rootViewController = rootController
        self.window = mainWindow
        mainWindow.makeKeyAndVisible()

        PrivacyShieldWindowManager.shared.refreshCaptureState()
    }

    /// Enforces UIKit text-input hygiene on concrete `UITextField` / `UITextView` instances when editing begins.
    /// IMPORTANT: Never invoke `UITextInputTraits` setters on `UIAppearance` proxies (`UITextField.appearance()`),
    /// as `UITextInputTraits` properties are not `UI_APPEARANCE_SELECTOR`s and trigger `NSInternalInconsistencyException`
    /// inside `PushNextClassForSettingIMP` when a text field moves into a `UIWindow`.
    private static func configureGlobalInputHygieneOnce() {
        guard inputHygieneObservers.isEmpty else { return }
        let center = NotificationCenter.default

        inputHygieneObservers.append(
            center.addObserver(
                forName: UITextField.textDidBeginEditingNotification,
                object: nil,
                queue: .main
            ) { notification in
                guard let field = notification.object as? UITextField else { return }
                var changed = false
                if field.autocorrectionType != .no { field.autocorrectionType = .no; changed = true }
                if field.spellCheckingType != .no { field.spellCheckingType = .no; changed = true }
                if field.smartQuotesType != .no { field.smartQuotesType = .no; changed = true }
                if field.smartDashesType != .no { field.smartDashesType = .no; changed = true }
                if field.smartInsertDeleteType != .no { field.smartInsertDeleteType = .no; changed = true }
                if #available(iOS 17.0, *), field.inlinePredictionType != .no {
                    field.inlinePredictionType = .no
                    changed = true
                }
                // Traits changed after editing began only take effect once the keyboard reloads.
                if changed { field.reloadInputViews() }
            }
        )

        inputHygieneObservers.append(
            center.addObserver(
                forName: UITextView.textDidBeginEditingNotification,
                object: nil,
                queue: .main
            ) { notification in
                guard let textView = notification.object as? UITextView else { return }
                var changed = false
                if textView.autocorrectionType != .no { textView.autocorrectionType = .no; changed = true }
                if textView.spellCheckingType != .no { textView.spellCheckingType = .no; changed = true }
                if textView.smartQuotesType != .no { textView.smartQuotesType = .no; changed = true }
                if textView.smartDashesType != .no { textView.smartDashesType = .no; changed = true }
                if textView.smartInsertDeleteType != .no { textView.smartInsertDeleteType = .no; changed = true }
                if #available(iOS 17.0, *), textView.inlinePredictionType != .no {
                    textView.inlinePredictionType = .no
                    changed = true
                }
                if changed { textView.reloadInputViews() }
            }
        )
    }
}

/// Ensures `VaultStore` is only instantiated and bootstrapped AFTER `UIApplicationMain` and `UIWindowScene` are active.
struct RootBootstrapView: View {
    @StateObject private var store = VaultStore()

    var body: some View {
        ContentView(store: store)
            .onAppear {
                store.bootstrapIfNeeded()
            }
    }
}
