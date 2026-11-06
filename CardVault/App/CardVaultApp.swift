import SwiftUI

@main
struct CardVaultApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var store = VaultStore()

    var body: some Scene {
        WindowGroup {
            ContentView(store: store)
        }
    }
}
