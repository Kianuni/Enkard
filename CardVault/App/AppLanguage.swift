import Foundation
import SwiftUI

enum AppLanguageMode: String, Codable, CaseIterable, Identifiable, Sendable {
    case system = "system"
    case zhHans = "zh-Hans"
    case en = "en"

    var id: String { rawValue }

    var displayTitle: String {
        switch self {
        case .system:
            return tr("跟随系统", "Follow System")
        case .zhHans:
            return "简体中文"
        case .en:
            return "English"
        }
    }
}

enum EffectiveLanguage: String, Equatable, Sendable {
    case zhHans = "zh-Hans"
    case en = "en"
}

enum L10n {
    private static let lock = NSLock()
    private nonisolated(unsafe) static var storedMode: AppLanguageMode = .system

    static var currentMode: AppLanguageMode {
        lock.lock()
        defer { lock.unlock() }
        return storedMode
    }

    static func setMode(_ newMode: AppLanguageMode) {
        lock.lock()
        storedMode = newMode
        lock.unlock()
    }

    static func resolveSystemLanguage(preferredLanguages: [String] = Locale.preferredLanguages) -> EffectiveLanguage {
        for tag in preferredLanguages {
            let lower = tag.lowercased()
            if lower.hasPrefix("zh") {
                return .zhHans
            }
            if lower.hasPrefix("en") {
                return .en
            }
        }
        return preferredLanguages.isEmpty ? .zhHans : .en
    }

    static var effectiveLanguage: EffectiveLanguage {
        switch currentMode {
        case .system:
            return resolveSystemLanguage()
        case .zhHans:
            return .zhHans
        case .en:
            return .en
        }
    }

    static var isEnglish: Bool {
        effectiveLanguage == .en
    }

    static var locale: Locale {
        Locale(identifier: isEnglish ? "en_US" : "zh_Hans_CN")
    }
}

@inline(__always)
func tr(_ zh: String, _ en: String) -> String {
    L10n.isEnglish ? en : zh
}

struct LanguageMenuButton: View {
    @Binding var selection: AppLanguageMode
    var isDarkSurface: Bool = false

    var body: some View {
        Menu {
            ForEach(AppLanguageMode.allCases) { mode in
                Button {
                    selection = mode
                } label: {
                    if selection == mode {
                        Label(mode.displayTitle, systemImage: "checkmark")
                    } else {
                        Text(mode.displayTitle)
                    }
                }
            }
        } label: {
            if isDarkSurface {
                HStack(spacing: 5) {
                    Image(systemName: "globe")
                    Text(L10n.isEnglish ? "EN" : "中文")
                }
                .font(.caption.weight(.semibold))
                .foregroundStyle(.white.opacity(0.85))
                .padding(.horizontal, 11)
                .padding(.vertical, 6)
                .background(Color.white.opacity(0.10), in: Capsule())
            } else {
                Label(tr("语言", "Language"), systemImage: "globe")
            }
        }
        .accessibilityLabel(tr("切换界面语言", "Switch App Language"))
    }
}
