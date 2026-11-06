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
                if field.autocorrectionType != .no { field.autocorrectionType = .no }
                if field.spellCheckingType != .no { field.spellCheckingType = .no }
                if field.smartQuotesType != .no { field.smartQuotesType = .no }
                if field.smartDashesType != .no { field.smartDashesType = .no }
                if field.smartInsertDeleteType != .no { field.smartInsertDeleteType = .no }
                if #available(iOS 17.0, *), field.inlinePredictionType != .no {
                    field.inlinePredictionType = .no
                }
            }
        )

        inputHygieneObservers.append(
            center.addObserver(
                forName: UITextView.textDidBeginEditingNotification,
                object: nil,
                queue: .main
            ) { notification in
                guard let textView = notification.object as? UITextView else { return }
                if textView.autocorrectionType != .no { textView.autocorrectionType = .no }
                if textView.spellCheckingType != .no { textView.spellCheckingType = .no }
                if textView.smartQuotesType != .no { textView.smartQuotesType = .no }
                if textView.smartDashesType != .no { textView.smartDashesType = .no }
                if textView.smartInsertDeleteType != .no { textView.smartInsertDeleteType = .no }
                if #available(iOS 17.0, *), textView.inlinePredictionType != .no {
                    textView.inlinePredictionType = .no
                }
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
