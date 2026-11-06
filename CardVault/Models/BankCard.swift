import Foundation
import SwiftUI

enum CardType: String, Codable, CaseIterable, Identifiable, Sendable {
    case credit = "credit"
    case debit = "debit"
    case virtual = "virtual"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .credit: return "信用卡"
        case .debit: return "借记卡"
        case .virtual: return "虚拟卡"
        }
    }

    var iconName: String {
        switch self {
        case .credit: return "creditcard.fill"
        case .debit: return "banknote.fill"
        case .virtual: return "sparkles.rectangle.stack.fill"
        }
    }
}

enum CardNetwork: String, Codable, CaseIterable, Identifiable, Sendable {
    case unionPay = "unionpay"
    case visa = "visa"
    case mastercard = "mastercard"
    case amex = "amex"
    case jcb = "jcb"
    case discover = "discover"
    case other = "other"

    var id: String { rawValue }

    var badgeText: String {
        switch self {
        case .unionPay: return "银联 UnionPay"
        case .visa: return "VISA"
        case .mastercard: return "Mastercard"
        case .amex: return "AMEX"
        case .jcb: return "JCB"
        case .discover: return "DISCOVER"
        case .other: return "BANK CARD"
        }
    }

    var shortName: String {
        switch self {
        case .unionPay: return "银联"
        case .visa: return "Visa"
        case .mastercard: return "万事达"
        case .amex: return "美国运通"
        case .jcb: return "JCB"
        case .discover: return "Discover"
        case .other: return "其他"
        }
    }

    var expectedCVVLength: Int {
        self == .amex ? 4 : 3
    }

    static func detect(from rawInput: String) -> CardNetwork {
        let digits = rawInput.filter(\.isWholeNumber)
        guard !digits.isEmpty else { return .unionPay }

        if digits.hasPrefix("4") {
            return .visa
        }
        if digits.hasPrefix("34") || digits.hasPrefix("37") {
            return .amex
        }
        if digits.hasPrefix("62") || digits.hasPrefix("81") {
            return .unionPay
        }
        if let prefix2 = Int(digits.prefix(2)), (51...55).contains(prefix2) {
            return .mastercard
        }
        if let prefix4 = Int(digits.prefix(4)), (2221...2720).contains(prefix4) {
            return .mastercard
        }
        if let prefix4 = Int(digits.prefix(4)), (3528...3589).contains(prefix4) {
            return .jcb
        }
        if digits.hasPrefix("6011") || digits.hasPrefix("65") {
            return .discover
        }
        if let prefix3 = Int(digits.prefix(3)), (644...649).contains(prefix3) {
            return .discover
        }
        return .other
    }
}

enum CardTheme: String, Codable, CaseIterable, Identifiable, Sendable {
    case obsidianGold = "obsidian_gold"
    case midnightBlue = "midnight_blue"
    case titaniumSlate = "titanium_slate"
    case emeraldJade = "emerald_jade"
    case crimsonRuby = "crimson_ruby"
    case royalViolet = "royal_violet"
    case auroraTeal = "aurora_teal"
    case roseBronze = "rose_bronze"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .obsidianGold: return "曜石黑金"
        case .midnightBlue: return "深海鎏蓝"
        case .titaniumSlate: return "钛金深灰"
        case .emeraldJade: return "翡翠暗绿"
        case .crimsonRuby: return "绯红丝绒"
        case .royalViolet: return "流光暗紫"
        case .auroraTeal: return "极光青黛"
        case .roseBronze: return "玫瑰古铜"
        }
    }

    var gradientColors: [Color] {
        switch self {
        case .obsidianGold:
            return [
                Color(red: 0.14, green: 0.13, blue: 0.12),
                Color(red: 0.07, green: 0.07, blue: 0.08),
                Color(red: 0.22, green: 0.18, blue: 0.11)
            ]
        case .midnightBlue:
            return [
                Color(red: 0.07, green: 0.16, blue: 0.34),
                Color(red: 0.04, green: 0.09, blue: 0.20),
                Color(red: 0.11, green: 0.25, blue: 0.46)
            ]
        case .titaniumSlate:
            return [
                Color(red: 0.25, green: 0.27, blue: 0.31),
                Color(red: 0.13, green: 0.15, blue: 0.18),
                Color(red: 0.32, green: 0.35, blue: 0.39)
            ]
        case .emeraldJade:
            return [
                Color(red: 0.06, green: 0.26, blue: 0.20),
                Color(red: 0.03, green: 0.14, blue: 0.11),
                Color(red: 0.11, green: 0.36, blue: 0.28)
            ]
        case .crimsonRuby:
            return [
                Color(red: 0.38, green: 0.08, blue: 0.14),
                Color(red: 0.19, green: 0.04, blue: 0.08),
                Color(red: 0.48, green: 0.13, blue: 0.19)
            ]
        case .royalViolet:
            return [
                Color(red: 0.22, green: 0.12, blue: 0.38),
                Color(red: 0.11, green: 0.06, blue: 0.22),
                Color(red: 0.33, green: 0.18, blue: 0.50)
            ]
        case .auroraTeal:
            return [
                Color(red: 0.06, green: 0.27, blue: 0.33),
                Color(red: 0.04, green: 0.14, blue: 0.20),
                Color(red: 0.12, green: 0.38, blue: 0.44)
            ]
        case .roseBronze:
            return [
                Color(red: 0.36, green: 0.21, blue: 0.19),
                Color(red: 0.19, green: 0.11, blue: 0.10),
                Color(red: 0.46, green: 0.28, blue: 0.24)
            ]
        }
    }

    var accentTint: Color {
        switch self {
        case .obsidianGold:
            return Color(red: 0.90, green: 0.76, blue: 0.48)
        case .roseBronze:
            return Color(red: 0.95, green: 0.78, blue: 0.72)
        default:
            return Color.white.opacity(0.92)
        }
    }
}

struct BankCard: Identifiable, Codable, Equatable, Hashable, Sendable {
    var id: UUID
    var bankName: String
    var nickname: String
    var cardType: CardType
    var network: CardNetwork
    var cardNumber: String
    var cardholderName: String
    var expiryMonth: String
    var expiryYear: String
    var cvv: String
    var pin: String
    var billingAddress: String
    var postalCode: String
    var phoneLast4: String
    var statementDay: Int?
    var dueDay: Int?
    var creditLimit: String
    var notes: String
    var theme: CardTheme
    var isFavorite: Bool
    var createdAt: Date
    var updatedAt: Date

    init(
        id: UUID = UUID(),
        bankName: String,
        nickname: String = "",
        cardType: CardType = .credit,
        network: CardNetwork = .unionPay,
        cardNumber: String,
        cardholderName: String = "",
        expiryMonth: String = "",
        expiryYear: String = "",
        cvv: String = "",
        pin: String = "",
        billingAddress: String = "",
        postalCode: String = "",
        phoneLast4: String = "",
        statementDay: Int? = nil,
        dueDay: Int? = nil,
        creditLimit: String = "",
        notes: String = "",
        theme: CardTheme = .obsidianGold,
        isFavorite: Bool = false,
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.bankName = bankName.trimmingCharacters(in: .whitespacesAndNewlines)
        self.nickname = nickname.trimmingCharacters(in: .whitespacesAndNewlines)
        self.cardType = cardType
        self.network = network
        self.cardNumber = cardNumber.filter(\.isWholeNumber)
        self.cardholderName = cardholderName.trimmingCharacters(in: .whitespacesAndNewlines)
        self.expiryMonth = expiryMonth.filter(\.isWholeNumber)
        self.expiryYear = Self.normalizeYear(expiryYear)
        self.cvv = cvv.filter(\.isWholeNumber)
        self.pin = pin.trimmingCharacters(in: .whitespacesAndNewlines)
        self.billingAddress = billingAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        self.postalCode = postalCode.trimmingCharacters(in: .whitespacesAndNewlines)
        self.phoneLast4 = String(phoneLast4.filter(\.isWholeNumber).suffix(4))
        self.statementDay = statementDay
        self.dueDay = dueDay
        self.creditLimit = creditLimit.trimmingCharacters(in: .whitespacesAndNewlines)
        self.notes = notes.trimmingCharacters(in: .whitespacesAndNewlines)
        self.theme = theme
        self.isFavorite = isFavorite
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    static func normalizeYear(_ raw: String) -> String {
        let digits = raw.filter(\.isWholeNumber)
        if digits.count == 4 {
            return String(digits.suffix(2))
        }
        return String(digits.prefix(2))
    }

    var digitsOnly: String {
        cardNumber.filter(\.isWholeNumber)
    }

    var last4: String {
        let digits = digitsOnly
        guard digits.count >= 4 else { return digits }
        return String(digits.suffix(4))
    }

    var displayTitle: String {
        if !bankName.isEmpty && !nickname.isEmpty {
            return "\(bankName) · \(nickname)"
        }
        return bankName.isEmpty ? (nickname.isEmpty ? "未命名卡片" : nickname) : bankName
    }

    var formattedNumber: String {
        Self.formatCardNumber(digitsOnly, network: network)
    }

    var maskedNumber: String {
        let suffix = last4
        if network == .amex {
            return "••••  ••••••  •\(suffix)"
        }
        return "••••  ••••  ••••  \(suffix)"
    }

    var formattedExpiry: String {
        let m = expiryMonth.filter(\.isWholeNumber)
        let y = Self.normalizeYear(expiryYear)
        guard !m.isEmpty, !y.isEmpty else { return "" }
        let paddedMonth = m.count == 1 ? "0\(m)" : String(m.prefix(2))
        return "\(paddedMonth)/\(y)"
    }

    var expiryStatus: ExpiryStatus {
        guard let month = Int(expiryMonth), (1...12).contains(month),
              let shortYear = Int(Self.normalizeYear(expiryYear)) else {
            return .unknown
        }
        let fullYear = 2000 + shortYear
        let calendar = Calendar.current
        let now = Date()
        let currentYear = calendar.component(.year, from: now)
        let currentMonth = calendar.component(.month, from: now)

        let monthsRemaining = (fullYear - currentYear) * 12 + (month - currentMonth)
        if monthsRemaining < 0 {
            return .expired
        } else if monthsRemaining <= 2 {
            return .expiringSoon
        } else {
            return .valid
        }
    }

    static func formatCardNumber(_ rawDigits: String, network: CardNetwork) -> String {
        let digits = Array(rawDigits.filter(\.isWholeNumber).prefix(19))
        guard !digits.isEmpty else { return "" }

        if network == .amex {
            // 4 - 6 - 5 grouping for American Express
            let groupSizes = [4, 6, 5]
            var result: [String] = []
            var index = 0
            for size in groupSizes where index < digits.count {
                let end = min(index + size, digits.count)
                result.append(String(digits[index..<end]))
                index = end
            }
            if index < digits.count {
                result.append(String(digits[index..<digits.count]))
            }
            return result.joined(separator: " ")
        } else {
            var groups: [String] = []
            var index = 0
            while index < digits.count {
                let end = min(index + 4, digits.count)
                groups.append(String(digits[index..<end]))
                index = end
            }
            return groups.joined(separator: " ")
        }
    }
}

enum ExpiryStatus: Equatable, Sendable {
    case valid
    case expiringSoon
    case expired
    case unknown
}

enum LuhnValidator {
    static func isValid(_ rawInput: String) -> Bool {
        let digits = rawInput.compactMap(\.wholeNumberValue)
        guard (13...19).contains(digits.count) else { return false }

        var sum = 0
        let reversedDigits = digits.reversed()
        for (index, digit) in reversedDigits.enumerated() {
            if index % 2 == 1 {
                let doubled = digit * 2
                sum += doubled > 9 ? (doubled - 9) : doubled
            } else {
                sum += digit
            }
        }
        return sum % 10 == 0
    }
}
