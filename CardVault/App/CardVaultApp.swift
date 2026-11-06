import SwiftUI
import UIKit

/// Explicit `UIWindowSceneDelegate` lifecycle compatible with iOS 16 through iOS 27+ strict scene enforcement.
final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    private static var didConfigureInputHygiene = false

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

    private static func configureGlobalInputHygieneOnce() {
        guard !didConfigureInputHygiene else { return }
        didConfigureInputHygiene = true

        let textFieldProxy = UITextField.appearance()
        textFieldProxy.autocorrectionType = .no
        textFieldProxy.spellCheckingType = .no
        textFieldProxy.smartQuotesType = .no
        textFieldProxy.smartDashesType = .no
        textFieldProxy.smartInsertDeleteType = .no

        let textViewProxy = UITextView.appearance()
        textViewProxy.autocorrectionType = .no
        textViewProxy.spellCheckingType = .no
        textViewProxy.smartQuotesType = .no
        textViewProxy.smartDashesType = .no
        textViewProxy.smartInsertDeleteType = .no
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
