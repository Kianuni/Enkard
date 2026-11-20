import SwiftUI

struct PrivacyShieldView: View {
    enum Style {
        case inactive
        case captured
    }

    var style: Style = .inactive

    private var iconName: String {
        style == .captured ? "eye.slash.fill" : "lock.shield.fill"
    }

    private var title: String {
        style == .captured
            ? tr("检测到录屏或投屏", "Screen Recording or Mirroring Detected")
            : tr("Enkard · 防窥保护中", "Enkard · Privacy Shield Active")
    }

    private var subtitle: String {
        style == .captured
            ? tr(
                "为防止银行卡敏感信息外泄，画面已全部隐藏。\n停止录屏或投屏后自动恢复。",
                "All card details are hidden to protect sensitive data.\nDisplay resumes automatically when recording stops."
            )
            : tr(
                "已遮挡所有卡片信息，防止多任务快照泄露",
                "Card details concealed to prevent app-switcher snapshot leaks"
            )
    }

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    Color(red: 0.06, green: 0.07, blue: 0.10),
                    Color(red: 0.10, green: 0.11, blue: 0.16)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            VStack(spacing: 16) {
                ZStack {
                    Circle()
                        .fill(Color.white.opacity(0.08))
                        .frame(width: 84, height: 84)
                    Image(systemName: iconName)
                        .font(.system(size: 38, weight: .semibold))
                        .foregroundStyle(
                            LinearGradient(
                                colors: [
                                    Color(red: 0.94, green: 0.81, blue: 0.53),
                                    Color(red: 0.78, green: 0.61, blue: 0.32)
                                ],
                                startPoint: .top,
                                endPoint: .bottom
                            )
                        )
                }

                Text(title)
                    .font(.headline)
                    .foregroundStyle(.white)

                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.white.opacity(0.6))
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal, 32)
        }
    }
}

struct ClipboardToastBanner: View {
    let toast: SecureClipboard.ToastState
    let onClearNow: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "checkmark.shield.fill")
                .foregroundStyle(Color(red: 0.35, green: 0.88, blue: 0.58))
                .font(.system(size: 16, weight: .semibold))

            Text(tr(
                "已复制\(toast.label) · \(toast.remainingSeconds)s 后销毁",
                "Copied \(toast.label) · Clears in \(toast.remainingSeconds)s"
            ))
                .font(.footnote.weight(.medium))
                .foregroundStyle(.white)
                .lineLimit(1)

            Spacer(minLength: 4)

            Button(action: onClearNow) {
                Text(tr("立即清空", "Clear Now"))
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(Color(red: 0.95, green: 0.82, blue: 0.52))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(Color.white.opacity(0.12), in: Capsule())
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 11)
        .background(
            Capsule()
                .fill(Color(red: 0.11, green: 0.12, blue: 0.16).opacity(0.96))
                .shadow(color: .black.opacity(0.28), radius: 12, y: 4)
        )
        .overlay(
            Capsule()
                .strokeBorder(Color.white.opacity(0.14), lineWidth: 0.8)
        )
        .padding(.horizontal, 20)
    }
}

struct ScreenCaptureWarningBanner: View {
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "eye.trianglebadge.exclamationmark.fill")
                .foregroundStyle(.white)
            Text(tr(
                "检测到正在录屏或镜像投屏，已强制隐藏全部敏感信息",
                "Screen recording or mirroring active. All sensitive info is masked."
            ))
                .font(.caption.weight(.semibold))
                .foregroundStyle(.white)
            Spacer()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .background(Color.red.opacity(0.90))
    }
}
