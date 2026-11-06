import SwiftUI
import UIKit

/// Screenshot / screen-recording redaction using the system's secure-text rendering layer.
///
/// iOS renders the internal canvas of a `UITextField` with `isSecureTextEntry = true` as blank
/// in screenshots, recordings and AirPlay mirroring. We retain the owning `UITextField` strongly
/// and verify view hierarchy ancestry before activating AutoLayout constraints.
@MainActor
enum SecureCanvasSupport {
    private static var cachedAvailability: Bool?

    static var isAvailable: Bool {
        if let cachedAvailability {
            return cachedAvailability
        }
        let available = makeSecurePair() != nil
        cachedAvailability = available
        return available
    }

    static func makeSecurePair() -> (ownerField: UITextField, canvas: UIView)? {
        let field = UITextField()
        field.isSecureTextEntry = true
        field.isUserInteractionEnabled = false
        field.backgroundColor = .clear
        field.layoutIfNeeded()

        guard let canvas = field.subviews.first,
              canvas.superview === field,
              String(describing: type(of: canvas)).contains("Canvas") else {
            return nil
        }
        canvas.subviews.forEach { $0.removeFromSuperview() }
        canvas.isUserInteractionEnabled = false
        canvas.backgroundColor = .clear
        return (field, canvas)
    }
}

final class SecureHostingContainer<Content: View>: UIView {
    let hosting: UIHostingController<Content>
    /// Retained strongly so `canvas` never loses its `isSecureTextEntry` backing controller.
    private var retainedSecureField: UITextField?

    init(rootView: Content) {
        hosting = UIHostingController(rootView: rootView)
        super.init(frame: .zero)

        backgroundColor = .clear
        isUserInteractionEnabled = false

        hosting.view.backgroundColor = .clear
        hosting.view.isUserInteractionEnabled = false
        hosting.safeAreaRegions = []

        if let pair = SecureCanvasSupport.makeSecurePair(),
           pair.canvas.isDescendant(of: pair.ownerField) {
            retainedSecureField = pair.ownerField
            let field = pair.ownerField
            let canvas = pair.canvas
            field.translatesAutoresizingMaskIntoConstraints = false
            addSubview(field)

            hosting.view.translatesAutoresizingMaskIntoConstraints = false
            canvas.addSubview(hosting.view)

            NSLayoutConstraint.activate([
                field.leadingAnchor.constraint(equalTo: leadingAnchor),
                field.trailingAnchor.constraint(equalTo: trailingAnchor),
                field.topAnchor.constraint(equalTo: topAnchor),
                field.bottomAnchor.constraint(equalTo: bottomAnchor),
                hosting.view.leadingAnchor.constraint(equalTo: canvas.leadingAnchor),
                hosting.view.trailingAnchor.constraint(equalTo: canvas.trailingAnchor),
                hosting.view.topAnchor.constraint(equalTo: canvas.topAnchor),
                hosting.view.bottomAnchor.constraint(equalTo: canvas.bottomAnchor)
            ])
        } else {
            hosting.view.translatesAutoresizingMaskIntoConstraints = false
            addSubview(hosting.view)
            NSLayoutConstraint.activate([
                hosting.view.leadingAnchor.constraint(equalTo: leadingAnchor),
                hosting.view.trailingAnchor.constraint(equalTo: trailingAnchor),
                hosting.view.topAnchor.constraint(equalTo: topAnchor),
                hosting.view.bottomAnchor.constraint(equalTo: bottomAnchor)
            ])
        }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func update(rootView: Content) {
        hosting.rootView = rootView
        hosting.view.invalidateIntrinsicContentSize()
    }
}

struct ScreenshotProtected<Content: View>: UIViewRepresentable {
    let content: Content

    func makeUIView(context: Context) -> SecureHostingContainer<Content> {
        SecureHostingContainer(rootView: content)
    }

    func updateUIView(_ uiView: SecureHostingContainer<Content>, context: Context) {
        uiView.update(rootView: content)
    }

    func sizeThatFits(
        _ proposal: ProposedViewSize,
        uiView: SecureHostingContainer<Content>,
        context: Context
    ) -> CGSize? {
        let target = CGSize(
            width: proposal.width ?? .greatestFiniteMagnitude,
            height: proposal.height ?? .greatestFiniteMagnitude
        )
        return uiView.hosting.sizeThatFits(in: target)
    }
}

/// Disables keyboard lexicon learning, AutoFill/iCloud Keychain prompts, and Apple Intelligence Writing Tools.
private struct LockdownTextInputModifier: ViewModifier {
    let autocapitalization: TextInputAutocapitalization

    func body(content: Content) -> some View {
        let base = content
            .autocorrectionDisabled(true)
            .textInputAutocapitalization(autocapitalization)
            .textContentType(nil)

        if #available(iOS 18.0, *) {
            base.writingToolsBehavior(.disabled)
        } else {
            base
        }
    }
}

private struct DisableWritingToolsRootModifier: ViewModifier {
    func body(content: Content) -> some View {
        if #available(iOS 18.0, *) {
            content.writingToolsBehavior(.disabled)
        } else {
            content
        }
    }
}

extension View {
    /// Renders display-only content inside the secure text layer AND marks it `.privacySensitive()` for OS snapshots.
    func screenshotProtected() -> some View {
        ScreenshotProtected(content: self)
            .privacySensitive()
    }

    /// Blocks system keyboard dictionary sync, AutoFill heuristics, and iOS 18+ Apple Intelligence Writing Tools.
    func lockdownTextInput(autocapitalization: TextInputAutocapitalization = .never) -> some View {
        modifier(LockdownTextInputModifier(autocapitalization: autocapitalization))
    }

    /// Disables Apple Intelligence Writing Tools across an entire view hierarchy on iOS 18+.
    func disableSystemWritingTools() -> some View {
        modifier(DisableWritingToolsRootModifier())
    }
}
