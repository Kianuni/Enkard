import Combine
import SwiftUI
import UIKit

struct ContentView: View {
    @ObservedObject var store: VaultStore

    private let idleTimer = Timer.publish(every: 5, on: .main, in: .common).autoconnect()

    var body: some View {
        ZStack(alignment: .bottom) {
            Group {
                switch store.phase {
                case .loading:
                    Color(red: 0.06, green: 0.07, blue: 0.11)
                        .ignoresSafeArea()
                case .onboarding:
                    OnboardingSetupView(store: store)
                case .locked:
                    LockScreenView(store: store)
                case .unlocked:
                    CardListView(store: store)
                }
            }

            if let toast = store.clipboard.activeToast {
                ClipboardToastBanner(toast: toast) {
                    store.clipboard.clearImmediately()
                }
                .padding(.bottom, 14)
                .transition(.move(edge: .bottom).combined(with: .opacity))
                .zIndex(50)
            }
        }
        .lockdownTextInput()
        .disableSystemWritingTools()
        .animation(.easeInOut(duration: 0.22), value: store.clipboard.activeToast)
        .alert(
            "Enkard 安全警报",
            isPresented: Binding(
                get: { store.securityNotice != nil },
                set: { if !$0 { store.securityNotice = nil } }
            )
        ) {
            Button("知道了", role: .cancel) {}
        } message: {
            Text(store.securityNotice ?? "")
        }
        .onAppear {
            let currentStore = store
            PrivacyShieldWindowManager.shared.activityHandler = { [weak currentStore] in
                currentStore?.noteActivity()
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.willResignActiveNotification)) { _ in
            store.handleWillResignActive()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.didEnterBackgroundNotification)) { _ in
            store.handleDidEnterBackground()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)) { _ in
            store.handleDidBecomeActive()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.protectedDataWillBecomeUnavailableNotification)) { _ in
            store.handleProtectedDataWillBecomeUnavailable()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.protectedDataDidBecomeAvailableNotification)) { _ in
            store.handleProtectedDataDidBecomeAvailable()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in
            store.refreshScreenCaptureState()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.userDidTakeScreenshotNotification)) { _ in
            store.handleScreenshot()
        }
        .onReceive(idleTimer) { _ in
            store.periodicSecurityTick()
        }
    }
}
