import UIKit

@main
@objc final class AppDelegate: UIResponder, UIApplicationDelegate {
    private(set) static var antiDebugEnabledAtLaunch = false

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        Self.antiDebugEnabledAtLaunch = RuntimeSecurity.enforceReleaseAntiDebug()
        NetworkLockdown.activate()
        PrivacyShieldWindowManager.shared.start()
        return true
    }

    func application(
        _ application: UIApplication,
        configurationForConnecting connectingSceneSession: UISceneSession,
        options: UIScene.ConnectionOptions
    ) -> UISceneConfiguration {
        let configuration = UISceneConfiguration(
            name: "Default Configuration",
            sessionRole: connectingSceneSession.role
        )
        configuration.sceneClass = UIWindowScene.self
        configuration.delegateClass = SceneDelegate.self
        return configuration
    }

    /// Blocks third-party custom keyboards, AutoFill/credential providers, broadcast/screen-sharing,
    /// and share/action extensions while allowing internal Apple UIKit system scene services.
    func application(
        _ application: UIApplication,
        shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier
    ) -> Bool {
        if extensionPointIdentifier == .keyboard {
            return false
        }
        let raw = extensionPointIdentifier.rawValue.lowercased()
        if !raw.hasPrefix("com.apple.") {
            return false
        }
        if raw.contains("keyboard")
            || raw.contains("share")
            || raw.contains("action")
            || raw.contains("broadcast")
            || raw.contains("autofill")
            || raw.contains("credential")
            || raw.contains("widget") {
            return false
        }
        return true
    }

    /// Refuse Handoff / Continuity / NSUserActivity cross-device synchronization.
    func application(
        _ application: UIApplication,
        willContinueUserActivityWithType userActivityType: String
    ) -> Bool {
        false
    }
}
