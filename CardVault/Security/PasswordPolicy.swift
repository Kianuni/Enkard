import Foundation

enum PasswordPurpose: Sendable {
    case master
    case backup
}

struct PasswordAssessment: Equatable, Sendable {
    let estimatedBits: Double
    let warnings: [String]

    var score: Int {
        switch estimatedBits {
        case ..<28: return 0
        case ..<40: return 1
        case ..<65: return 2
        case ..<85: return 3
        default: return 4
        }
    }

    var label: String {
        ["极弱", "弱", "中等", "强", "极强"][score]
    }
}

/// Offline password strength estimation and policy enforcement (v2).
/// Hardened against CJK / full-width punctuation entropy inflation (`1234567！`, `19900101。`),
/// dictionary/pinyin/leet combinations, dates, phone numbers, ID numbers, repeats and keyboard walks.
enum PasswordPolicy {
    static let masterMinimumLength = VaultCrypto.minimumVaultPasswordLength   // 8
    static let backupMinimumLength = VaultCrypto.minimumBackupPasswordLength  // 12
    static let maximumPasswordLength = 256
    static let masterMinimumBits = 40.0
    static let backupMinimumBits = 65.0

    static func validationMessage(_ rawPassword: String, for purpose: PasswordPurpose) -> String? {
        let name = purpose == .master ? "主密码" : "备份密码"
        if rawPassword.utf8.count > maximumPasswordLength * 4 {
            return "\(name)长度不能超过 \(maximumPasswordLength) 位"
        }

        let password = VaultCrypto.normalizePassword(rawPassword)
        let minimumLength = purpose == .master ? masterMinimumLength : backupMinimumLength
        let minimumBits = purpose == .master ? masterMinimumBits : backupMinimumBits

        if password.count < minimumLength {
            return "\(name)至少需要 \(minimumLength) 位"
        }
        if password.count > maximumPasswordLength {
            return "\(name)长度不能超过 \(maximumPasswordLength) 位"
        }

        if containsDisallowedInvisibleOrControlScalar(password) {
            return "\(name)包含不可见格式字符或控制字符，请手动重新输入可打印字符"
        }

        let assessment = assess(password)
        guard assessment.estimatedBits < minimumBits else { return nil }

        if let warning = assessment.warnings.first {
            return "\(name)太容易被猜到：\(warning)"
        }
        switch purpose {
        case .master:
            return "主密码强度不足（需达到约 \(Int(minimumBits)) bit），请增加长度或混合大小写字母、数字与符号"
        case .backup:
            return "备份文件可被离线无限次暴力破解，请使用更长口令（强烈推荐使用随机恢复口令）"
        }
    }

    static func assess(_ rawPassword: String) -> PasswordAssessment {
        if rawPassword.utf8.count > maximumPasswordLength * 4 {
            return PasswordAssessment(
                estimatedBits: 0,
                warnings: ["密码长度超出安全上限（最多 \(maximumPasswordLength) 位）"]
            )
        }
        let normalizedInput = VaultCrypto.normalizePassword(rawPassword)
        if normalizedInput.count > maximumPasswordLength {
            return PasswordAssessment(
                estimatedBits: 0,
                warnings: ["密码长度超出安全上限（最多 \(maximumPasswordLength) 位）"]
            )
        }
        if containsDisallowedInvisibleOrControlScalar(normalizedInput) {
            return PasswordAssessment(estimatedBits: 0, warnings: ["包含不可见格式字符或控制字符"])
        }
        let password = halfwidthNormalized(normalizedInput)
        guard !password.isEmpty else {
            return PasswordAssessment(estimatedBits: 0, warnings: [])
        }

        let lowered = password.lowercased()
        let strippedPunct = lowered.filter { !$0.isWhitespace && !$0.isPunctuation && !$0.isSymbol }
        if commonPasswords.contains(lowered)
            || commonPasswords.contains(lowered.replacingOccurrences(of: " ", with: ""))
            || (!strippedPunct.isEmpty && strippedPunct.count >= lowered.count - 2 && commonPasswords.contains(strippedPunct)) {
            return PasswordAssessment(estimatedBits: 10, warnings: ["属于常见泄露弱密码（加标点也极易被字典规则猜中）"])
        }

        let scalars = Array(password.unicodeScalars)
        var hasDigit = false, hasLower = false, hasUpper = false, hasSymbol = false
        var cjkOrNonAsciiLetterCount = 0

        for scalar in scalars {
            switch classifyScalar(scalar) {
            case .digit: hasDigit = true
            case .lower: hasLower = true
            case .upper: hasUpper = true
            case .symbol: hasSymbol = true
            case .nonAsciiLetter: cjkOrNonAsciiLetterCount += 1
            }
        }

        // ASCII/symbol character pool NEVER gets inflated by CJK characters or full-width punctuation!
        let asciiPool = max(
            (hasDigit ? 10 : 0) + (hasLower ? 26 : 0) + (hasUpper ? 26 : 0) + (hasSymbol ? 33 : 0),
            2
        )
        let asciiPoolBits = log2(Double(asciiPool))

        // Per-position entropy weighted by repetition/sequence discounting.
        var rawBits = 0.0
        for (index, scalar) in scalars.enumerated() {
            let weight: Double
            if index == 0 {
                weight = 1.0
            } else {
                let prev = scalars[index - 1].value
                if scalar.value == prev {
                    weight = 0.15
                } else if scalar.value == prev &+ 1 || scalar.value &+ 1 == prev {
                    weight = 0.35
                } else {
                    weight = 1.0
                }
            }
            let charBits = classifyScalar(scalar) == .nonAsciiLetter ? 9.5 : asciiPoolBits
            rawBits += weight * charBits
        }

        let uniqueCount = Set(scalars).count
        let uniquenessCap = Double(uniqueCount) * 2.5 * max(asciiPoolBits, cjkOrNonAsciiLetterCount > 0 ? 7.5 : asciiPoolBits)
        var bits = min(rawBits, uniquenessCap)
        var warnings: [String] = []

        // LZ77 repeated-block compression cap (defeats `Ab1!Ab1!`, `Ab1!Ab1!Ab1!`, `Q9#Q9#Q9#`).
        let repeatCheck = repeatedBlockCompressedBits(scalars: scalars, asciiPoolBits: asciiPoolBits)
        if repeatCheck.hasRepeatedBlock && repeatCheck.bits < bits {
            bits = repeatCheck.bits
            warnings.append("包含重复循环片段，实际抗破解强度远低于长度")
        }

        // Dictionary / pinyin / leet / date / phone / year segmentation model.
        let segmented = segmentedBits(password, asciiPoolBits: asciiPoolBits)
        if segmented.bits < bits {
            bits = segmented.bits
        }
        if let word = segmented.words.first {
            warnings.append("包含常见单词或拼音（\(word)），字典规则攻击会优先尝试")
        }
        if segmented.hasDate {
            warnings.append("包含完整生日或日期")
        } else if segmented.hasYear {
            warnings.append("包含年份")
        }
        if segmented.hasPhone {
            warnings.append("包含手机号特征片段")
        }

        // Inspect digit core even when wrapped in symbols/punctuation (e.g. `19900101。`, `@13812345678!`).
        let digitsExtracted = String(password.filter(\.isWholeNumber))
        let nonDigitCount = password.count - digitsExtracted.count
        let extraTailBits = Double(nonDigitCount) * min(asciiPoolBits, 5.5)

        if digitsExtracted.count >= 6 && nonDigitCount <= 3 {
            if looksLikeDate(digitsExtracted) || looksLikeDate(String(digitsExtracted.prefix(8))) {
                bits = min(bits, 18 + extraTailBits)
                warnings.append("主体看起来像生日或日期")
            }
            if digitsExtracted.count == 11 && digitsExtracted.hasPrefix("1") {
                bits = min(bits, 28 + extraTailBits)
                warnings.append("主体看起来像手机号")
            }
            if digitsExtracted.count == 15 || digitsExtracted.count == 18 {
                bits = min(bits, 28 + extraTailBits)
                warnings.append("主体看起来像身份证号")
            }
        }

        if let walk = keyboardWalks.first(where: { lowered.contains($0) }) {
            bits -= 12
            warnings.append("包含键盘连续按键（\(walk)）")
        }
        if let fragment = commonFragments.first(where: { lowered.contains($0) }) {
            bits -= 12
            warnings.append("包含常见弱密码片段（\(fragment)）")
        }
        if uniqueCount <= 3 {
            bits = min(bits, 20)
            warnings.append("使用的字符种类太少")
        }
        if nonDigitCount == 0 && warnings.isEmpty {
            warnings.append("纯数字密码很容易被暴力破解")
        }

        return PasswordAssessment(estimatedBits: max(0, bits), warnings: warnings)
    }

    /// 25 symbols from the Crockford Base32 alphabet (no I/L/O/U) in 5 groups = 125 bits.
    static func generateRecoveryPassphrase(groups: Int = 5, groupLength: Int = 5) -> String {
        let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        var generator = SystemRandomNumberGenerator()
        let characters = (0..<(groups * groupLength)).map { _ in
            alphabet[Int.random(in: 0..<alphabet.count, using: &generator)]
        }
        return stride(from: 0, to: characters.count, by: groupLength)
            .map { String(characters[$0..<($0 + groupLength)]) }
            .joined(separator: "-")
    }

    // MARK: - Classification & Heuristics

    private enum ScalarClass {
        case digit
        case lower
        case upper
        case symbol
        case nonAsciiLetter
    }

    private static func classifyScalar(_ scalar: Unicode.Scalar) -> ScalarClass {
        switch scalar.value {
        case 48...57:
            return .digit
        case 97...122:
            return .lower
        case 65...90:
            return .upper
        case 32...126:
            return .symbol
        default:
            if CharacterSet.punctuationCharacters.contains(scalar)
                || CharacterSet.symbols.contains(scalar)
                || CharacterSet.whitespacesAndNewlines.contains(scalar)
                || (0x3000...0x303F).contains(scalar.value)
                || (0x2000...0x206F).contains(scalar.value)
                || (0xFE30...0xFE6F).contains(scalar.value)
                || (0xFF00...0xFFEF).contains(scalar.value) {
                return .symbol
            }
            if CharacterSet.decimalDigits.contains(scalar) {
                return .digit
            }
            return .nonAsciiLetter
        }
    }

    /// Maps full-width ASCII (`！` `０`-`９` `Ａ`-`Ｚ` `ａ`-`ｚ`) and `。`/`，` to ASCII equivalents for pattern detection.
    private static func halfwidthNormalized(_ input: String) -> String {
        var scalars: [Unicode.Scalar] = []
        scalars.reserveCapacity(input.unicodeScalars.count)
        for s in input.unicodeScalars {
            if (0xFF01...0xFF5E).contains(s.value), let mapped = Unicode.Scalar(s.value - 0xFEE0) {
                scalars.append(mapped)
            } else if s.value == 0x3000 {
                scalars.append(" ")
            } else {
                scalars.append(s)
            }
        }
        return String(String.UnicodeScalarView(scalars))
    }

    private static let leetMap: [Character: Character] = [
        "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"
    ]

    private static func containsDisallowedInvisibleOrControlScalar(_ text: String) -> Bool {
        for scalar in text.unicodeScalars {
            let v = scalar.value
            if v < 0x20 || (0x7F...0x9F).contains(v) {
                return true
            }
            if (0x200B...0x200F).contains(v)
                || (0x202A...0x202E).contains(v)
                || (0x2060...0x206F).contains(v)
                || v == 0xFEFF
                || (0xFFF9...0xFFFB).contains(v)
                || CharacterSet.controlCharacters.contains(scalar)
                || CharacterSet.illegalCharacters.contains(scalar) {
                return true
            }
        }
        return false
    }

    private static func repeatedBlockCompressedBits(
        scalars: [Unicode.Scalar],
        asciiPoolBits: Double
    ) -> (bits: Double, hasRepeatedBlock: Bool) {
        var bits = 0.0
        var hasRepeated = false
        var i = 0
        while i < scalars.count {
            var bestMatchLen = 0
            if i >= 3 {
                let maxCandidate = scalars.count - i
                for start in 0..<i {
                    var len = 0
                    while len < maxCandidate, scalars[start + len] == scalars[i + len] {
                        len += 1
                    }
                    if len > bestMatchLen {
                        bestMatchLen = len
                    }
                }
            }
            if bestMatchLen >= 3 {
                bits += 2.5
                hasRepeated = true
                i += bestMatchLen
            } else {
                bits += classifyScalar(scalars[i]) == .nonAsciiLetter ? 9.5 : asciiPoolBits
                i += 1
            }
        }
        return (bits, hasRepeated)
    }

    private static func segmentedBits(
        _ password: String,
        asciiPoolBits: Double
    ) -> (bits: Double, words: [String], hasYear: Bool, hasDate: Bool, hasPhone: Bool) {
        let original = Array(password)
        let normalized = original.map { char -> Character in
            let lower = Character(char.lowercased())
            return leetMap[lower] ?? lower
        }
        let maxWordLength = dictionaryWords.map(\.count).max() ?? 0

        var bits = 0.0
        var words: [String] = []
        var hasYear = false
        var hasDate = false
        var hasPhone = false
        var index = 0
        while index < original.count {
            if index + 11 <= original.count {
                let sub11 = String(original[index..<(index + 11)])
                if sub11.allSatisfy(\.isWholeNumber),
                   sub11.hasPrefix("1"),
                   let second = sub11.dropFirst().first?.wholeNumberValue,
                   (3...9).contains(second) {
                    bits += 25.0
                    hasPhone = true
                    index += 11
                    continue
                }
            }
            if index + 8 <= original.count {
                let sub8 = String(original[index..<(index + 8)])
                if sub8.allSatisfy(\.isWholeNumber), looksLikeDate(sub8) {
                    bits += 14.5
                    hasDate = true
                    index += 8
                    continue
                }
            }
            if index + 4 <= original.count,
               let year = Int(String(original[index..<(index + 4)])),
               (1900...2099).contains(year) {
                bits += 7
                hasYear = true
                index += 4
                continue
            }
            var matched = 0
            var length = min(maxWordLength, original.count - index)
            while length >= 4 {
                if dictionaryWords.contains(String(normalized[index..<(index + length)])) {
                    matched = length
                    break
                }
                length -= 1
            }
            if matched > 0 {
                let segment = original[index..<(index + matched)]
                let mutated = segment.contains { $0.isUppercase || leetMap[$0] != nil }
                bits += 11 + (mutated ? 1 : 0)
                words.append(String(normalized[index..<(index + matched)]))
                index += matched
            } else {
                let ch = original[index]
                let scalar = ch.unicodeScalars.first ?? Unicode.Scalar(UInt8(32))
                bits += classifyScalar(scalar) == .nonAsciiLetter ? 9.5 : asciiPoolBits
                index += 1
            }
        }
        return (bits, words, hasYear, hasDate, hasPhone)
    }

    private static let dictionaryWords: Set<String> = [
        "love", "baby", "angel", "monkey", "dragon", "shadow", "master", "sunshine", "princess",
        "football", "baseball", "soccer", "hockey", "killer", "flower", "summer", "winter", "spring",
        "autumn", "hello", "welcome", "freedom", "secret", "money", "letmein", "admin", "qwerty",
        "super", "star", "lucky", "happy", "smile", "apple", "banana", "orange", "cherry", "chocolate",
        "cookie", "pepper", "ginger", "tiger", "lion", "eagle", "horse", "puppy", "kitty", "bear",
        "wolf", "fish", "bird", "rabbit", "panda", "computer", "internet", "google", "iphone",
        "samsung", "china", "london", "paris", "america", "family", "friend", "mother", "father",
        "sister", "brother", "jesus", "christ", "heaven", "forever", "always", "never", "matrix",
        "ninja", "pokemon", "batman", "superman", "spider", "hunter", "ranger", "soldier", "pirate",
        "knight", "king", "queen", "prince", "gold", "silver", "diamond", "crystal", "magic", "power",
        "energy", "thunder", "storm", "rain", "snow", "fire", "water", "ocean", "river", "mountain",
        "moon", "light", "dark", "black", "white", "blue", "green", "purple", "pink", "yellow",
        "correct", "battery", "staple", "password", "passwd", "pass", "trustno", "whatever",
        "nothing", "someone", "charlie", "michael", "jordan", "thomas", "robert", "jennifer",
        "jessica", "ashley", "daniel", "andrew", "joshua", "matthew", "david", "james", "john",
        "william", "george", "test", "user", "login", "guest", "iloveyou", "cool", "best", "game",
        "home", "life", "time", "good", "girl", "boys", "card", "bank", "visa", "cardse", "enkard",
        "woaini", "aini", "wode", "baobei", "laopo", "laogong", "qinai", "xingfu", "kuaile",
        "pingan", "zhongguo", "beijing", "shanghai", "shenzhen", "guangzhou", "zhang", "wang",
        "chen", "yang", "huang", "zhao", "zhou", "xiao", "liang", "ming", "hong", "jian", "yong",
        "feng", "long", "tian", "xing", "mima", "nihao", "haha", "hehe", "taobao", "weixin", "baidu"
    ]

    private static func looksLikeDate(_ digits: String) -> Bool {
        let values = digits.compactMap(\.wholeNumberValue)
        func number(_ range: Range<Int>) -> Int {
            values[range].reduce(0) { $0 * 10 + $1 }
        }
        if values.count == 8 {
            let year = number(0..<4), month = number(4..<6), day = number(6..<8)
            if (1900...2099).contains(year), (1...12).contains(month), (1...31).contains(day) { return true }
            let month2 = number(0..<2), day2 = number(2..<4), year2 = number(4..<8)
            if (1900...2099).contains(year2), (1...12).contains(month2), (1...31).contains(day2) { return true }
        }
        if values.count == 6 {
            let month = number(2..<4), day = number(4..<6)
            if (1...12).contains(month), (1...31).contains(day) { return true }
        }
        return false
    }

    private static let keyboardWalks = [
        "qwert", "werty", "asdfg", "sdfgh", "zxcvb", "yuiop", "hjkl",
        "1qaz", "2wsx", "3edc", "qazwsx", "1q2w3e", "!@#$", "zaq1"
    ]

    private static let commonFragments = [
        "abc123", "5201314", "1314520", "123456", "654321", "888888", "666666", "111111"
    ]

    private static let commonPasswords: Set<String> = [
        "123456", "1234567", "12345678", "123456789", "1234567890", "12345678910",
        "111111", "000000", "888888", "666666", "123123", "654321", "112233", "121212",
        "147258", "147258369", "159753", "789456", "987654321", "11111111", "00000000",
        "88888888", "12341234", "123321", "520520", "5201314", "1314520", "a123456",
        "a12345678", "123456a", "aa123456", "qq123456", "abc123", "abc12345", "abcd1234",
        "abcdef", "password", "password1", "password123", "passw0rd", "p@ssw0rd", "qwerty",
        "qwerty123", "qwertyuiop", "1qaz2wsx", "1q2w3e4r", "1q2w3e", "zaq12wsx", "asdfgh",
        "asd123", "zxcvbn", "iloveyou", "woaini", "woaini1314", "woaini520", "admin",
        "admin123", "letmein", "welcome", "dragon", "monkey", "sunshine", "football",
        "baseball", "master", "superman", "michael", "trustno1", "computer", "internet",
        "taobao", "alipay", "wechat", "weixin", "baidu", "iloveyou1", "qwe123", "123qwe",
        "aaaaaa", "aaaaaaaa", "a1b2c3", "a1b2c3d4", "correcthorsebatterystaple", "tr0ub4dor&3"
    ]
}
