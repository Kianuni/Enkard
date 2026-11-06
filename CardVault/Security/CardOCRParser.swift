import CoreGraphics
import Foundation

struct RecognizedTextBlock: Equatable, Sendable {
    let text: String
    /// Normalized Vision bounding box (`[0, 1]`, origin at bottom-left).
    let boundingBox: CGRect
}

struct ScannedCardCandidate: Equatable, Sendable {
    var cardNumber: String
    var expiryMonth: String?
    var expiryYear: String?
    var cardholderName: String?
    var bankName: String? = nil

    mutating func scrub() {
        cardNumber = ""
        expiryMonth = nil
        expiryYear = nil
        cardholderName = nil
        bankName = nil
    }
}

/// Pure, zero-I/O parser for extracting Luhn-verified PAN, expiry (`MM/YY`), and embossed/printed
/// Latin cardholder names from Apple Vision text observations entirely in volatile memory.
enum CardOCRParser {
    private static let validPANLengths = 13...19

    private static let nonNameStopwords: Set<String> = [
        "UNIONPAY", "VISA", "MASTERCARD", "MASTER", "AMEX", "AMERICAN", "EXPRESS", "DISCOVER", "JCB",
        "DINERS", "CLUB", "MAESTRO", "MIR", "RUPAY", "QUICKPASS", "PAYWAVE", "PAYPASS",
        "BANK", "BANKING", "CHINA", "HONGKONG", "SHANGHAI", "BEIJING", "SHENZHEN", "GUANGZHOU",
        "COMMERCIAL", "MERCHANTS", "CONSTRUCTION", "INDUSTRIAL", "AGRICULTURAL", "COMMUNICATIONS",
        "POSTAL", "SAVINGS", "CITIC", "MINSHENG", "EVERBRIGHT", "HUATAI", "HUAXIA", "PINGAN", "PING",
        "SPDB", "PUDONG", "DEVELOPMENT", "GUANGFA", "CGB", "CIB", "BOC", "ICBC", "CCB", "ABC", "CMB",
        "HSBC", "CITI", "CITIBANK", "STANDARD", "CHARTERED", "CHASE", "BARCLAYS", "WELLS", "FARGO",
        "CAPITAL", "ONE", "SANTANDER", "UBS", "DBS", "OCBC", "UOB", "MUFG", "SMBC", "MIZUHO",
        "CREDIT", "DEBIT", "PREPAID", "CARD", "CARDS", "PLATINUM", "SIGNATURE", "INFINITE", "WORLD",
        "ELITE", "TITANIUM", "GOLD", "SILVER", "CLASSIC", "STANDARD", "DIAMOND", "BLACK", "CENTURION",
        "BUSINESS", "CORPORATE", "COMMERCIAL", "EXECUTIVE", "PREMIER", "PRIVILEGE", "PRIVATE", "WEALTH",
        "REWARDS", "CASHBACK", "MILES", "TRAVEL", "INTERNATIONAL", "GLOBAL", "DUAL", "CURRENCY",
        "VALID", "THRU", "THROUGH", "GOOD", "FROM", "UNTIL", "END", "EXP", "EXPIRES", "EXPIRY", "DATE",
        "MONTH", "YEAR", "MEMBER", "SINCE", "ISSUED", "BY", "AUTHORIZED", "SIGNATURE", "NOT",
        "CUSTOMER", "SERVICE", "HOTLINE", "VIP", "PASS", "PAY", "ONLY", "ELECTRONIC", "USE"
    ]

    static func parseFrame(_ blocks: [RecognizedTextBlock]) -> ScannedCardCandidate? {
        guard !blocks.isEmpty else { return nil }

        guard let pan = extractValidPAN(from: blocks) else {
            return nil
        }

        let expiry = extractExpiry(from: blocks)
        let holder = extractCardholderName(from: blocks)
        let issuer = extractBankName(from: blocks)
        return ScannedCardCandidate(
            cardNumber: pan,
            expiryMonth: expiry?.month,
            expiryYear: expiry?.year,
            cardholderName: holder,
            bankName: issuer
        )
    }

    // MARK: - PAN Extraction (Single-line + Horizontal Stitching + Vertical 4x4 Stack Stitching)

    private struct NumericFragment {
        let digits: String
        let box: CGRect
    }

    private static func extractValidPAN(from blocks: [RecognizedTextBlock]) -> String? {
        var candidates: [(pan: String, score: Int)] = []

        // 1. Direct single-observation extraction (raw digits first, then cautious OCR-deconfused digits).
        for block in blocks {
            for variant in digitCandidates(fromLine: block.text) {
                if let matched = findBestLuhnRun(in: variant) {
                    candidates.append((matched, scorePAN(matched, box: block.boundingBox)))
                }
            }
        }

        // Collect short 3–6 digit fragments for multi-box stitching (split horizontal groups or vertical cards).
        var fragments: [NumericFragment] = []
        for block in blocks {
            let trimmed = block.text.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.contains("/"), !trimmed.contains(":") else { continue }
            let clean = deconfuseNumericToken(trimmed)
            let digits = String(clean.filter(\.isWholeNumber))
            let nonSpaceCount = trimmed.filter { !$0.isWhitespace && $0 != "-" }.count
            guard (3...6).contains(digits.count), nonSpaceCount <= digits.count + 1 else { continue }
            fragments.append(NumericFragment(digits: digits, box: block.boundingBox))
        }

        // 2. Horizontal same-row stitching (left -> right).
        if fragments.count >= 3 {
            let sortedByY = fragments.sorted { $0.box.midY > $1.box.midY }
            for anchor in sortedByY {
                let sameRow = fragments
                    .filter {
                        abs($0.box.midY - anchor.box.midY) <= max(0.042, anchor.box.height * 0.75)
                    }
                    .sorted { $0.box.minX < $1.box.minX }
                guard sameRow.count >= 3 else { continue }
                for start in 0..<sameRow.count {
                    var combined = ""
                    var unionBox = sameRow[start].box
                    for end in start..<min(sameRow.count, start + 5) {
                        combined += sameRow[end].digits
                        unionBox = unionBox.union(sameRow[end].box)
                        if validPANLengths.contains(combined.count), LuhnValidator.isValid(combined) {
                            candidates.append((combined, scorePAN(combined, box: unionBox)))
                        }
                    }
                }
            }
        }

        // 3. Vertical column stack stitching (top -> bottom; Vision `midY` decreases downward).
        if fragments.count >= 3 {
            for anchor in fragments {
                let sameColumn = fragments
                    .filter {
                        abs($0.box.minX - anchor.box.minX) <= 0.065
                            || abs($0.box.midX - anchor.box.midX) <= 0.065
                    }
                    .sorted { $0.box.midY > $1.box.midY }
                guard sameColumn.count >= 3 else { continue }
                for start in 0..<sameColumn.count {
                    var combined = ""
                    var unionBox = sameColumn[start].box
                    for end in start..<min(sameColumn.count, start + 5) {
                        combined += sameColumn[end].digits
                        unionBox = unionBox.union(sameColumn[end].box)
                        if validPANLengths.contains(combined.count), LuhnValidator.isValid(combined) {
                            candidates.append((combined, scorePAN(combined, box: unionBox) - 2))
                        }
                    }
                }
            }
        }

        return candidates.max(by: { $0.score < $1.score })?.pan
    }

    private static func digitCandidates(fromLine text: String) -> [String] {
        let rawDigits = String(text.filter(\.isWholeNumber))
        var results = [rawDigits]

        let deconfused = String(deconfuseNumericToken(text).filter(\.isWholeNumber))
        if deconfused != rawDigits {
            results.append(deconfused)
        }
        return results
    }

    /// Converts common embossed-foil OCR confusions ONLY when the token is predominantly numeric.
    private static func deconfuseNumericToken(_ text: String) -> String {
        let stripped = text.filter { !$0.isWhitespace && $0 != "-" && $0 != "·" }
        guard !stripped.isEmpty else { return text }

        let digitLikeCount = stripped.filter { ch in
            ch.isWholeNumber || "OoDQIl|SsBbZz".contains(ch)
        }.count
        let actualDigitCount = stripped.filter(\.isWholeNumber).count
        guard actualDigitCount >= 2, digitLikeCount * 4 >= stripped.count * 3 else {
            return text
        }

        let map: [Character: Character] = [
            "O": "0", "o": "0", "D": "0", "Q": "0",
            "I": "1", "l": "1", "|": "1",
            "Z": "2", "z": "2",
            "S": "5", "s": "5",
            "b": "6",
            "B": "8"
        ]
        return String(text.map { map[$0] ?? $0 })
    }

    private static func findBestLuhnRun(in digits: String) -> String? {
        guard digits.count >= validPANLengths.lowerBound else { return nil }
        if validPANLengths.contains(digits.count), LuhnValidator.isValid(digits) {
            return digits
        }
        guard digits.count > validPANLengths.upperBound else { return nil }

        let chars = Array(digits)
        for length in [16, 19, 15, 14, 13, 18, 17] where length <= chars.count {
            for start in 0...(chars.count - length) {
                let sub = String(chars[start..<(start + length)])
                if LuhnValidator.isValid(sub) {
                    return sub
                }
            }
        }
        return nil
    }

    private static func scorePAN(_ pan: String, box: CGRect) -> Int {
        var score = 0
        switch pan.count {
        case 16: score += 40
        case 15: score += 36 // Amex
        case 19: score += 34 // UnionPay 19-digit debit/credit
        case 14: score += 28
        default: score += 20
        }
        if CardNetwork.detect(from: pan) != .other {
            score += 20
        }
        if box.width >= 0.35 {
            score += 10
        }
        return score
    }

    // MARK: - Expiry Date Extraction (`MM/YY` or `MM/YYYY`)

    private static let expiryRegex: NSRegularExpression? = try? NSRegularExpression(
        pattern: #"(?:^|[^\d])(0?[1-9]|1[0-2])\s*[/\-]\s*(\d{2}|\d{4})(?:$|[^\d])"#
    )

    private static func extractExpiry(from blocks: [RecognizedTextBlock]) -> (month: String, year: String)? {
        guard let regex = expiryRegex else { return nil }
        var found: [(monthInt: Int, yearInt: Int, monthStr: String, yearStr: String)] = []

        for block in blocks {
            let line = block.text
            let nsRange = NSRange(line.startIndex..<line.endIndex, in: line)
            for match in regex.matches(in: line, range: nsRange) {
                guard match.numberOfRanges >= 3,
                      let mRange = Range(match.range(at: 1), in: line),
                      let yRange = Range(match.range(at: 2), in: line),
                      let monthInt = Int(line[mRange]),
                      (1...12).contains(monthInt) else {
                    continue
                }
                let rawYear = String(line[yRange])
                let shortYearStr = BankCard.normalizeYear(rawYear)
                guard let shortYear = Int(shortYearStr), (20...49).contains(shortYear) else {
                    continue
                }
                let paddedMonth = monthInt < 10 ? "0\(monthInt)" : "\(monthInt)"
                found.append((monthInt, 2000 + shortYear, paddedMonth, shortYearStr))
            }
        }

        // If a card prints both `VALID FROM` and `VALID THRU`, `VALID THRU` is always the later date.
        guard let latest = found.max(by: {
            $0.yearInt != $1.yearInt ? ($0.yearInt < $1.yearInt) : ($0.monthInt < $1.monthInt)
        }) else {
            return nil
        }
        return (latest.monthStr, latest.yearStr)
    }

    // MARK: - Cardholder Name Extraction

    private static func extractCardholderName(from blocks: [RecognizedTextBlock]) -> String? {
        var best: (name: String, score: Int)?

        for block in blocks {
            let upper = block.text
                .uppercased()
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard (4...26).contains(upper.count) else { continue }
            guard !upper.contains(where: \.isWholeNumber) else { continue }

            // Allow only ASCII uppercase letters, spaces, dots, and slashes (e.g. `ZHANG SAN`, `SAN ZHANG`).
            guard upper.allSatisfy({ ($0 >= "A" && $0 <= "Z") || $0 == " " || $0 == "." }) else {
                continue
            }

            let words = upper
                .replacingOccurrences(of: ".", with: " ")
                .split(whereSeparator: \.isWhitespace)
                .map(String.init)
            guard (2...4).contains(words.count) else { continue }
            guard words.allSatisfy({ $0.count >= 2 }) else { continue }
            guard words.allSatisfy({ !nonNameStopwords.contains($0) }) else { continue }

            let normalized = words.joined(separator: " ")
            // Cardholder names typically sit in the lower half of horizontal cards (`midY < 0.45`).
            var score = 10
            if block.boundingBox.midY < 0.45 {
                score += 15
            }
            if words.count == 2 || words.count == 3 {
                score += 5
            }
            if best == nil || score > best!.score {
                best = (normalized, score)
            }
        }

        return best?.name
    }

    // MARK: - Issuing Bank Detection (Chinese & English)

    private static let bankPhraseRules: [(phrase: String, canonical: String)] = [
        ("招商银行", "招商银行"), ("CHINA MERCHANTS BANK", "招商银行"),
        ("工商银行", "工商银行"), ("INDUSTRIAL AND COMMERCIAL BANK", "工商银行"),
        ("建设银行", "建设银行"), ("CHINA CONSTRUCTION BANK", "建设银行"),
        ("农业银行", "农业银行"), ("AGRICULTURAL BANK OF CHINA", "农业银行"),
        ("中国银行", "中国银行"), ("BANK OF CHINA", "中国银行"),
        ("交通银行", "交通银行"), ("BANK OF COMMUNICATIONS", "交通银行"),
        ("邮政储蓄", "邮储银行"), ("邮储银行", "邮储银行"), ("POSTAL SAVINGS BANK", "邮储银行"),
        ("中信银行", "中信银行"), ("CITIC BANK", "中信银行"),
        ("平安银行", "平安银行"), ("PING AN BANK", "平安银行"),
        ("浦发银行", "浦发银行"), ("浦东发展银行", "浦发银行"), ("PUDONG DEVELOPMENT BANK", "浦发银行"),
        ("广发银行", "广发银行"), ("CHINA GUANGFA BANK", "广发银行"),
        ("兴业银行", "兴业银行"), ("INDUSTRIAL BANK", "兴业银行"),
        ("民生银行", "民生银行"), ("CHINA MINSHENG BANK", "民生银行"),
        ("光大银行", "光大银行"), ("CHINA EVERBRIGHT BANK", "光大银行"),
        ("华夏银行", "华夏银行"), ("HUAXIA BANK", "华夏银行"),
        ("汇丰", "汇丰银行"), ("HSBC", "汇丰银行"),
        ("花旗", "花旗银行"), ("CITIBANK", "花旗银行"),
        ("渣打", "渣打银行"), ("STANDARD CHARTERED", "渣打银行"),
        ("东亚银行", "东亚银行"), ("BANK OF EAST ASIA", "东亚银行"),
        ("中银香港", "中银香港"), ("BOCHK", "中银香港"),
        ("AMERICAN EXPRESS", "American Express"),
        ("JPMORGAN CHASE", "Chase"), ("CHASE", "Chase")
    ]

    private static let bankTokenRules: [String: String] = [
        "CMB": "招商银行",
        "ICBC": "工商银行",
        "CCB": "建设银行",
        "BOC": "中国银行",
        "SPDB": "浦发银行",
        "CGB": "广发银行",
        "CIB": "兴业银行",
        "CMBC": "民生银行"
    ]

    private static func extractBankName(from blocks: [RecognizedTextBlock]) -> String? {
        for block in blocks {
            let upper = block.text.uppercased()
            for rule in bankPhraseRules where upper.contains(rule.phrase) {
                return rule.canonical
            }
            let tokens = upper.split { !($0 >= "A" && $0 <= "Z") }.map(String.init)
            for token in tokens {
                if let canonical = bankTokenRules[token] {
                    return canonical
                }
            }
        }
        return nil
    }
}

/// Multi-frame confirmation buffer that requires N consistent Luhn-valid PAN reads before auto-filling,
/// while merging auxiliary fields (`MM/YY` expiry, cardholder name, and bank name) observed across frames.
struct CardScanConsensusAccumulator: Sendable {
    enum Outcome: Equatable, Sendable {
        case none
        case provisional(ScannedCardCandidate)
        case confirmed(ScannedCardCandidate)
    }

    let requiredConfirmations: Int
    private var countsByPAN: [String: Int] = [:]
    private var bestExpiryByPAN: [String: (month: String, year: String)] = [:]
    private var bestNameByPAN: [String: String] = [:]
    private var bestBankByPAN: [String: String] = [:]
    private var totalFramesTracked = 0

    init(requiredConfirmations: Int = 2) {
        self.requiredConfirmations = max(1, requiredConfirmations)
    }

    mutating func ingest(_ candidate: ScannedCardCandidate?) -> Outcome {
        guard let candidate, LuhnValidator.isValid(candidate.cardNumber) else {
            return .none
        }

        totalFramesTracked += 1
        if totalFramesTracked > 24 {
            // Bound memory and evict stale partial reads periodically.
            reset()
            totalFramesTracked = 1
        }

        let pan = candidate.cardNumber
        let hits = (countsByPAN[pan] ?? 0) + 1
        countsByPAN[pan] = hits

        if let month = candidate.expiryMonth, let year = candidate.expiryYear {
            bestExpiryByPAN[pan] = (month, year)
        }
        if let name = candidate.cardholderName, !name.isEmpty {
            bestNameByPAN[pan] = name
        }
        if let bank = candidate.bankName, !bank.isEmpty {
            bestBankByPAN[pan] = bank
        }

        let merged = ScannedCardCandidate(
            cardNumber: pan,
            expiryMonth: bestExpiryByPAN[pan]?.month,
            expiryYear: bestExpiryByPAN[pan]?.year,
            cardholderName: bestNameByPAN[pan],
            bankName: bestBankByPAN[pan]
        )

        if hits >= requiredConfirmations {
            return .confirmed(merged)
        }
        return .provisional(merged)
    }

    mutating func reset() {
        countsByPAN.removeAll(keepingCapacity: false)
        bestExpiryByPAN.removeAll(keepingCapacity: false)
        bestNameByPAN.removeAll(keepingCapacity: false)
        bestBankByPAN.removeAll(keepingCapacity: false)
        totalFramesTracked = 0
    }
}
