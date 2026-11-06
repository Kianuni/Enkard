import SwiftUI

@main
struct CardVaultApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            RootBootstrapView()
        }
    }
}

/// Ensures `VaultStore` is only instantiated AFTER `UIApplicationMain` and the `UIWindowScene` are fully initialized.
private struct RootBootstrapView: View {
    @State private var store: VaultStore?

    var body: some View {
        Group {
            if let store {
                ContentView(store: store)
            } else {
                Color(red: 0.06, green: 0.07, blue: 0.11)
                    .ignoresSafeArea()
            }
        }
        .onAppear {
            if store == nil {
                let initialized = VaultStore()
                initialized.bootstrapIfNeeded()
                store = initialized
            }
        }
    }
}
