import Combine
import Foundation
import UIKit
import UniformTypeIdentifiers

@MainActor
final class SecureClipboard: ObservableObject {
    struct ToastState: Equatable {
        let id: UUID
        let label: String
        var remainingSeconds: Int
    }

    @Published private(set) var activeToast: ToastState?
    private var countdownTask: Task<Void, Never>?
    /// `changeCount` right after our last write; lets us clear ONLY what we put there.
    private var ownedChangeCount: Int?

    func copy(_ text: String, label: String, ttlSeconds: Int) {
        guard !text.isEmpty else { return }

        let expiration = Date().addingTimeInterval(TimeInterval(ttlSeconds))
        let item: [String: Any] = [
            UTType.utf8PlainText.identifier: text,
            UTType.plainText.identifier: text
        ]

        UIPasteboard.general.setItems(
            [item],
            options: [
                .localOnly: true,           // Never sync via Universal Clipboard / Handoff / Continuity
                .expirationDate: expiration // OS clears it even if CardSe is killed
            ]
        )
        ownedChangeCount = UIPasteboard.general.changeCount

        let generator = UIImpactFeedbackGenerator(style: .light)
        generator.impactOccurred()

        let toastID = UUID()
        activeToast = ToastState(id: toastID, label: label, remainingSeconds: ttlSeconds)

        countdownTask?.cancel()
        countdownTask = Task { [weak self] in
            var remaining = ttlSeconds
            while remaining > 0, !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard !Task.isCancelled, let self else { return }
                remaining -= 1
                if self.activeToast?.id == toastID {
                    if remaining > 0 {
                        self.activeToast?.remainingSeconds = remaining
                    } else {
                        // Actively scrub the pasteboard on expiry in addition to OS expirationDate!
                        self.clearIfOwned()
                    }
                }
            }
        }
    }

    /// Clears the pasteboard only if its current content is still the value we copied.
    /// Never wipes unrelated text the user copied from another app afterwards.
    @discardableResult
    func clearIfOwned() -> Bool {
        countdownTask?.cancel()
        countdownTask = nil
        activeToast = nil
        defer { ownedChangeCount = nil }

        guard let owned = ownedChangeCount,
              UIPasteboard.general.changeCount == owned else {
            return false
        }
        UIPasteboard.general.items = []
        return true
    }

    func clearImmediately() {
        clearIfOwned()
        let generator = UINotificationFeedbackGenerator()
        generator.notificationOccurred(.success)
    }
}
