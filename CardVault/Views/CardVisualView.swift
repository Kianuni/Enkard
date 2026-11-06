import SwiftUI

struct CardVisualView: View {
    let card: BankCard
    var isRevealed: Bool = false
    var forceMasked: Bool = false

    private var showPlaintext: Bool {
        isRevealed && !forceMasked
    }

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: card.theme.gradientColors,
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )

            // Subtle metallic diagonal sheen
            GeometryReader { geo in
                Path { path in
                    let w = geo.size.width
                    let h = geo.size.height
                    path.move(to: CGPoint(x: w * 0.18, y: 0))
                    path.addLine(to: CGPoint(x: w * 0.62, y: 0))
                    path.addLine(to: CGPoint(x: w * 0.30, y: h))
                    path.addLine(to: CGPoint(x: -w * 0.12, y: h))
                    path.closeSubpath()
                }
                .fill(
                    LinearGradient(
                        colors: [
                            Color.white.opacity(0.11),
                            Color.white.opacity(0.02)
                        ],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
            }
            .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))

            VStack(alignment: .leading, spacing: 0) {
                // Top Row: Bank + Nickname + Network
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) {
                            Text(card.bankName.isEmpty ? "发卡银行" : card.bankName)
                                .font(.system(size: 18, weight: .bold, design: .rounded))
                                .foregroundStyle(.white)
                                .lineLimit(1)

                            if card.isFavorite {
                                Image(systemName: "star.fill")
                                    .font(.caption2)
                                    .foregroundStyle(Color(red: 0.98, green: 0.82, blue: 0.36))
                            }
                        }

                        Text(card.nickname.isEmpty ? card.cardType.title : "\(card.nickname) · \(card.cardType.title)")
                            .font(.caption)
                            .foregroundStyle(.white.opacity(0.72))
                            .lineLimit(1)
                    }

                    Spacer(minLength: 8)

                    Text(card.network.badgeText)
                        .font(.system(size: 13, weight: .heavy, design: .rounded))
                        .foregroundStyle(card.theme.accentTint)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(Color.white.opacity(0.12), in: Capsule())
                }

                Spacer(minLength: 10)

                // EMV Chip + Contactless
                HStack(spacing: 10) {
                    EMVChipIcon()
                    Image(systemName: "wave.3.right")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(.white.opacity(0.60))

                    Spacer()

                    if card.expiryStatus == .expired {
                        Text("已过期")
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(.white)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(Color.red.opacity(0.82), in: Capsule())
                    } else if card.expiryStatus == .expiringSoon {
                        Text("即将到期")
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(.black)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(Color.yellow.opacity(0.90), in: Capsule())
                    }
                }

                Spacer(minLength: 12)

                // Card Number
                Text(displayedCardNumber)
                    .font(.system(size: 20, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.white)
                    .minimumScaleFactor(0.72)
                    .lineLimit(1)
                    .tracking(1.1)

                Spacer(minLength: 12)

                // Bottom Row: Cardholder, Valid Thru, CVV
                HStack(alignment: .bottom, spacing: 18) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("CARDHOLDER")
                            .font(.system(size: 9, weight: .semibold, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.55))
                        Text(card.cardholderName.isEmpty ? "—" : card.cardholderName.uppercased())
                            .font(.system(size: 13, weight: .medium, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.92))
                            .lineLimit(1)
                    }

                    Spacer(minLength: 4)

                    VStack(alignment: .leading, spacing: 2) {
                        Text("VALID THRU")
                            .font(.system(size: 9, weight: .semibold, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.55))
                        Text(card.formattedExpiry.isEmpty ? "--/--" : card.formattedExpiry)
                            .font(.system(size: 13, weight: .semibold, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.95))
                    }

                    VStack(alignment: .leading, spacing: 2) {
                        Text("CVV")
                            .font(.system(size: 9, weight: .semibold, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.55))
                        Text(displayedCVV)
                            .font(.system(size: 13, weight: .semibold, design: .monospaced))
                            .foregroundStyle(showPlaintext ? Color(red: 0.98, green: 0.86, blue: 0.50) : .white.opacity(0.92))
                    }
                }
            }
            .padding(20)
        }
        .aspectRatio(1.586, contentMode: .fit)
        .overlay(
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .strokeBorder(
                    LinearGradient(
                        colors: [
                            Color.white.opacity(0.28),
                            Color.white.opacity(0.06)
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: 1
                )
        )
        .shadow(color: .black.opacity(0.22), radius: 12, y: 6)
    }

    private var displayedCardNumber: String {
        if card.digitsOnly.isEmpty {
            return "••••  ••••  ••••  ••••"
        }
        return showPlaintext ? card.formattedNumber : card.maskedNumber
    }

    private var displayedCVV: String {
        guard !card.cvv.isEmpty else { return "—" }
        if showPlaintext {
            return card.cvv
        }
        return String(repeating: "•", count: max(3, card.cvv.count))
    }
}

private struct EMVChipIcon: View {
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [
                            Color(red: 0.91, green: 0.79, blue: 0.53),
                            Color(red: 0.73, green: 0.58, blue: 0.32)
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .frame(width: 38, height: 28)

            VStack(spacing: 5) {
                Rectangle().fill(Color.black.opacity(0.22)).frame(height: 0.8)
                Rectangle().fill(Color.black.opacity(0.22)).frame(height: 0.8)
            }
            .frame(width: 34)

            HStack(spacing: 10) {
                Rectangle().fill(Color.black.opacity(0.22)).frame(width: 0.8)
                Rectangle().fill(Color.black.opacity(0.22)).frame(width: 0.8)
            }
            .frame(height: 24)
        }
        .overlay(
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .strokeBorder(Color.white.opacity(0.35), lineWidth: 0.6)
        )
    }
}
