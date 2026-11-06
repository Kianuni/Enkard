import UIKit

final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        NetworkLockdown.activate()
        configureGlobalInputHygiene()
        PrivacyShieldWindowManager.shared.start()
        return true
    }

    /// Strictest policy: refuse ALL third-party extensions (custom keyboards, share/action extensions, etc.).
    func application(
        _ application: UIApplication,
        shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier
    ) -> Bool {
        false
    }

    /// Refuse Handoff / Continuity / NSUserActivity cross-device synchronization.
    func application(
        _ application: UIApplication,
        willContinueUserActivityWithType userActivityType: String
    ) -> Bool {
        false
    }

    private func configureGlobalInputHygiene() {
        UITextField.appearance().autocorrectionType = .no
        UITextField.appearance().spellCheckingType = .no
        UITextField.appearance().smartQuotesType = .no
        UITextField.appearance().smartDashesType = .no
        UITextField.appearance().smartInsertDeleteType = .no

        UITextView.appearance().autocorrectionType = .no
        UITextView.appearance().spellCheckingType = .no
        UITextView.appearance().smartQuotesType = .no
        UITextView.appearance().smartDashesType = .no
        UITextView.appearance().smartInsertDeleteType = .no
    }
}
