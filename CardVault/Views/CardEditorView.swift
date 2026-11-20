import SwiftUI

struct CardEditorView: View {
    @ObservedObject var store: VaultStore
    let existingCard: BankCard?

    @Environment(\.dismiss) private var dismiss

    @State private var bankName = ""
    @State private var nickname = ""
    @State private var cardType: CardType = .credit
    @State private var network: CardNetwork = .unionPay
    @State private var didManuallySelectNetwork = false

    @State private var cardNumberDigits = ""
    @State private var isEditingCardNumber = false
    @FocusState private var cardNumberFocused: Bool

    @State private var cardholderName = ""
    @State private var expiryMonth = ""
    @State private var expiryYear = ""
    @State private var cvv = ""

    /// Controls whether the `.screenshotProtected()` preview card at top displays full card number & CVV.
    @State private var revealInSecurePreview = false
    @State private var previewRevealTask: Task<Void, Never>? = nil
    @State private var didPopulateInitialValues = false

    @State private var theme: CardTheme = .obsidianGold
    @State private var isFavorite = false

    // Extended optional fields
    @State private var showExtendedFields = false
    @State private var billingAddress = ""
    @State private var postalCode = ""
    @State private var pin = ""
    @State private var phoneLast4 = ""
    @State private var statementDayString = ""
    @State private var dueDayString = ""
    @State private var creditLimit = ""
    @State private var notes = ""

    @State private var validationError: String? = nil

    private var commonBanks: [String] {
        L10n.isEnglish
            ? [
                "Chase", "Citi", "Amex", "HSBC", "Bank of America",
                "Capital One", "Standard Chartered", "Barclays", "CMB", "ICBC", "BOC"
            ]
            : [
                "招商银行", "工商银行", "建设银行", "中国银行", "农业银行",
                "交通银行", "中信银行", "平安银行", "浦发银行", "广发银行", "兴业银行"
            ]
    }

    private var previewCard: BankCard {
        BankCard(
            id: existingCard?.id ?? UUID(),
            bankName: bankName,
            nickname: nickname,
            cardType: cardType,
            network: network,
            cardNumber: cardNumberDigits,
            cardholderName: cardholderName,
            expiryMonth: expiryMonth,
            expiryYear: expiryYear,
            cvv: cvv,
            theme: theme,
            isFavorite: isFavorite
        )
    }

    var body: some View {
        NavigationStack {
            Form {
                // Live Card Preview inside ScreenshotProtected Canvas!
                Section {
                    VStack(spacing: 10) {
                        CardVisualView(
                            card: previewCard,
                            isRevealed: revealInSecurePreview,
                            forceMasked: store.isScreenCaptured
                        )
                        .screenshotProtected()

                        Button {
                            toggleSecurePreview()
                        } label: {
                            Label(
                                revealInSecurePreview
                                    ? tr("隐藏安全预览卡面明文", "Hide Preview Card Details")
                                    : tr("在防截屏卡面上核对完整卡号与 CVV（8秒自动收起）", "Verify Full Number & CVV on Secure Card (Auto-hides in 8s)"),
                                systemImage: revealInSecurePreview ? "eye.slash.fill" : "eye.fill"
                            )
                            .font(.caption.weight(.medium))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 8)
                            .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                        }
                        .buttonStyle(.plain)
                        .disabled(store.isScreenCaptured)
                    }
                    .listRowInsets(EdgeInsets(top: 8, leading: 0, bottom: 8, trailing: 0))
                    .listRowBackground(Color.clear)
                }

                // Core Card Details
                Section(tr("核心卡面信息（禁输入法同步与写作工具）", "Core Card Details (Keyboard Learning & AI Disabled)")) {
                    VStack(alignment: .leading, spacing: 8) {
                        TextField(tr("发卡银行（如：招商银行）", "Issuing Bank (e.g. Chase, CMB)"), text: $bankName)
                            .lockdownTextInput()
                            .onValueChange(of: bankName) { val in
                                if val.count > BankCard.maxBankNameLength {
                                    bankName = String(val.prefix(BankCard.maxBankNameLength))
                                }
                            }

                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 6) {
                                ForEach(commonBanks, id: \.self) { bank in
                                    Button {
                                        bankName = bank
                                    } label: {
                                        Text(bank)
                                            .font(.caption)
                                            .padding(.horizontal, 9)
                                            .padding(.vertical, 4)
                                            .background(
                                                bankName == bank ? Color.accentColor.opacity(0.20) : Color(.tertiarySystemGroupedBackground),
                                                in: Capsule()
                                            )
                                    }
                                    .buttonStyle(.plain)
                                }
                            }
                        }
                    }

                    TextField(tr("卡片别名（选填，如：全币种海淘卡）", "Nickname (Optional, e.g. Travel Rewards)"), text: $nickname)
                        .lockdownTextInput()
                        .onValueChange(of: nickname) { val in
                            if val.count > BankCard.maxNicknameLength {
                                nickname = String(val.prefix(BankCard.maxNicknameLength))
                            }
                        }

                    // Card Number: SecureField by default so screenshots cannot capture full PAN in the form!
                    VStack(alignment: .leading, spacing: 6) {
                        SecureField(
                            tr("输入银行卡号（13–19 位纯数字，上方安全卡面可核对）", "Card Number (13–19 digits; verify via preview above)"),
                            text: $cardNumberDigits
                        )
                            .keyboardType(.numberPad)
                            .lockdownTextInput()
                            .focused($cardNumberFocused)
                            .font(.system(.body, design: .monospaced))
                            .onValueChange(of: cardNumberDigits) { newValue in
                                let filtered = String(BankCard.asciiDigitsOnly(newValue).prefix(BankCard.maxCardNumberDigits))
                                if filtered != newValue {
                                    cardNumberDigits = filtered
                                }
                                if !didManuallySelectNetwork && filtered.count >= 2 {
                                    network = CardNetwork.detect(from: filtered)
                                }
                                store.noteActivity()
                            }

                        if cardNumberDigits.count >= 13 {
                            if LuhnValidator.isValid(cardNumberDigits) {
                                Label(
                                    tr("Luhn 卡号校验位通过（\(cardNumberDigits.count) 位）", "Luhn check passed (\(cardNumberDigits.count) digits)"),
                                    systemImage: "checkmark.circle.fill"
                                )
                                    .font(.caption2)
                                    .foregroundStyle(.green)
                            } else {
                                Label(
                                    tr("卡号校验位异常，请点击上方安全预览核对是否输错数字", "Luhn check failed — tap secure preview above to verify digits"),
                                    systemImage: "exclamationmark.triangle.fill"
                                )
                                    .font(.caption2)
                                    .foregroundStyle(.orange)
                            }
                        }
                    }

                    HStack(spacing: 12) {
                        Text(tr("有效期", "Expiry"))
                            .foregroundStyle(.secondary)
                        Spacer()
                        SecureField("MM", text: $expiryMonth)
                            .keyboardType(.numberPad)
                            .lockdownTextInput()
                            .multilineTextAlignment(.center)
                            .font(.system(.body, design: .monospaced))
                            .frame(width: 54)
                            .padding(.vertical, 6)
                            .background(Color(.tertiarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 8))
                            .onValueChange(of: expiryMonth) { val in
                                expiryMonth = String(val.filter(\.isWholeNumber).prefix(2))
                            }

                        Text("/")
                            .foregroundStyle(.secondary)

                        SecureField("YY", text: $expiryYear)
                            .keyboardType(.numberPad)
                            .lockdownTextInput()
                            .multilineTextAlignment(.center)
                            .font(.system(.body, design: .monospaced))
                            .frame(width: 54)
                            .padding(.vertical, 6)
                            .background(Color(.tertiarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 8))
                            .onValueChange(of: expiryYear) { val in
                                expiryYear = BankCard.normalizeYear(val)
                            }
                    }

                    // CVV is strictly a SecureField (never downgraded to plain TextField!)
                    SecureField(tr("安全码 CVV（卡背面末 3 位，运通 4 位）", "CVV / Security Code (3 digits, 4 for Amex)"), text: $cvv)
                        .keyboardType(.numberPad)
                        .lockdownTextInput()
                        .font(.system(.body, design: .monospaced))
                        .onValueChange(of: cvv) { val in
                            cvv = String(val.filter(\.isWholeNumber).prefix(4))
                        }

                    TextField(tr("持卡人英文/拼音（选填，如 SAN ZHANG）", "Cardholder Name (Optional, e.g. JOHN DOE)"), text: $cardholderName)
                        .lockdownTextInput(autocapitalization: .characters)
                        .onValueChange(of: cardholderName) { val in
                            if val.count > BankCard.maxCardholderNameLength {
                                cardholderName = String(val.prefix(BankCard.maxCardholderNameLength))
                            }
                        }
                }

                // Classification & Card Theme
                Section(tr("卡种与外观配色", "Category & Metallic Finish")) {
                    Picker(tr("卡片类型", "Card Type"), selection: $cardType) {
                        ForEach(CardType.allCases) { type in
                            Text(type.title).tag(type)
                        }
                    }

                    Picker(tr("卡组织", "Network"), selection: $network) {
                        ForEach(CardNetwork.allCases) { net in
                            Text(net.badgeText).tag(net)
                        }
                    }
                    .onValueChange(of: network) { _ in
                        didManuallySelectNetwork = true
                    }

                    VStack(alignment: .leading, spacing: 10) {
                        Text(tr("卡面金属配色：\(theme.title)", "Metallic Finish: \(theme.title)"))
                            .font(.subheadline)
                            .foregroundStyle(.secondary)

                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 12) {
                                ForEach(CardTheme.allCases) { item in
                                    Button {
                                        theme = item
                                    } label: {
                                        Circle()
                                            .fill(
                                                LinearGradient(
                                                    colors: item.gradientColors,
                                                    startPoint: .topLeading,
                                                    endPoint: .bottomTrailing
                                                )
                                            )
                                            .frame(width: 34, height: 34)
                                            .overlay(
                                                Circle()
                                                    .strokeBorder(
                                                        theme == item ? Color.primary : Color.white.opacity(0.25),
                                                        lineWidth: theme == item ? 2.5 : 1
                                                    )
                                            )
                                    }
                                    .buttonStyle(.plain)
                                }
                            }
                            .padding(.vertical, 2)
                        }
                    }

                    Toggle(tr("设为收藏置顶卡片", "Pin to Favorites"), isOn: $isFavorite)
                }

                // Optional Overseas Billing & Statement Info
                Section {
                    DisclosureGroup(tr("海淘账单地址、账单日与备注（选填）", "Billing Address, Statement Cycle & Notes (Optional)"), isExpanded: $showExtendedFields) {
                        TextField(tr("海淘账单地址 (Billing Address)", "Billing Address"), text: $billingAddress)
                            .lockdownTextInput()
                            .onValueChange(of: billingAddress) { val in
                                if val.count > BankCard.maxBillingAddressLength {
                                    billingAddress = String(val.prefix(BankCard.maxBillingAddressLength))
                                }
                            }
                        TextField(tr("账单邮编 (ZIP / Postal Code)", "ZIP / Postal Code"), text: $postalCode)
                            .keyboardType(.asciiCapable)
                            .lockdownTextInput()
                            .onValueChange(of: postalCode) { val in
                                if val.count > BankCard.maxPostalCodeLength {
                                    postalCode = String(val.prefix(BankCard.maxPostalCodeLength))
                                }
                            }

                        if !pin.isEmpty {
                            VStack(alignment: .leading, spacing: 6) {
                                Label(tr("这张卡包含旧版遗留的交易 PIN", "This card has a legacy PIN stored"), systemImage: "exclamationmark.triangle.fill")
                                    .font(.subheadline.weight(.medium))
                                    .foregroundStyle(.orange)
                                Text(tr("线下刷卡/取现 PIN 不应与线上 CVV 共同保存。强烈建议立即清除。", "ATM/offline PINs should not be stored alongside online CVV. Removing it is strongly recommended."))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Button(tr("清除已保存的 PIN", "Clear Stored PIN"), role: .destructive) {
                                    pin = ""
                                }
                                .font(.subheadline)
                            }
                            .padding(.vertical, 4)
                        }

                        SecureField(tr("银行预留手机号后四位", "Registered Phone Last 4 Digits"), text: $phoneLast4)
                            .keyboardType(.numberPad)
                            .lockdownTextInput()
                            .onValueChange(of: phoneLast4) { val in
                                phoneLast4 = String(BankCard.asciiDigitsOnly(val).prefix(BankCard.maxPhoneLast4Digits))
                            }

                        HStack {
                            Text(tr("每月账单日", "Statement Day"))
                            Spacer()
                            TextField(tr("如 5", "e.g. 5"), text: $statementDayString)
                                .keyboardType(.numberPad)
                                .lockdownTextInput()
                                .multilineTextAlignment(.trailing)
                                .frame(width: 70)
                                .onValueChange(of: statementDayString) { val in
                                    statementDayString = String(BankCard.asciiDigitsOnly(val).prefix(2))
                                }
                        }

                        HStack {
                            Text(tr("每月还款日", "Due Day"))
                            Spacer()
                            TextField(tr("如 23", "e.g. 23"), text: $dueDayString)
                                .keyboardType(.numberPad)
                                .lockdownTextInput()
                                .multilineTextAlignment(.trailing)
                                .frame(width: 70)
                                .onValueChange(of: dueDayString) { val in
                                    dueDayString = String(BankCard.asciiDigitsOnly(val).prefix(2))
                                }
                        }

                        TextField(tr("授信额度 / 币种（如 50,000 CNY）", "Credit Limit / Currency (e.g. $10,000 USD)"), text: $creditLimit)
                            .lockdownTextInput()
                            .onValueChange(of: creditLimit) { val in
                                if val.count > BankCard.maxCreditLimitLength {
                                    creditLimit = String(val.prefix(BankCard.maxCreditLimitLength))
                                }
                            }
                        SecureField(tr("安全备注（保存后默认打码）", "Secure Notes (Masked by default)"), text: $notes)
                            .lockdownTextInput()
                            .onValueChange(of: notes) { val in
                                if val.count > BankCard.maxNotesLength {
                                    notes = String(val.prefix(BankCard.maxNotesLength))
                                }
                            }
                    }
                }

                if let validationError {
                    Section {
                        Text(validationError)
                            .foregroundStyle(.red)
                            .font(.footnote)
                    }
                }
            }
            .navigationTitle(existingCard == nil ? tr("添加银行卡", "Add Card") : tr("编辑银行卡", "Edit Card"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(tr("取消", "Cancel")) {
                        scrubState()
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(tr("硬件加密保存", "Encrypt & Save")) {
                        saveCard()
                    }
                    .fontWeight(.semibold)
                    .disabled(cardNumberDigits.count < 8)
                }
            }
            .onAppear(perform: populateIfEditing)
            .onDisappear {
                scrubState()
            }
            .onValueChange(of: store.screenshotEventCount) { _ in
                previewRevealTask?.cancel()
                revealInSecurePreview = false
            }
            .onValueChange(of: store.isScreenCaptured) { captured in
                if captured {
                    scrubState()
                    dismiss()
                }
            }
            .onValueChange(of: store.phase) { newPhase in
                if newPhase != .unlocked {
                    scrubState()
                    dismiss()
                }
            }
        }
    }

    private func toggleSecurePreview() {
        if revealInSecurePreview {
            previewRevealTask?.cancel()
            revealInSecurePreview = false
        } else {
            startTemporarySecurePreview()
        }
    }

    private func startTemporarySecurePreview() {
        previewRevealTask?.cancel()
        guard !store.isScreenCaptured else { return }
        revealInSecurePreview = true
        previewRevealTask = Task {
            try? await Task.sleep(for: .seconds(8))
            guard !Task.isCancelled else { return }
            revealInSecurePreview = false
        }
    }

    private func populateIfEditing() {
        guard !didPopulateInitialValues else { return }
        didPopulateInitialValues = true
        guard let card = existingCard else { return }
        bankName = card.bankName
        nickname = card.nickname
        cardType = card.cardType
        network = card.network
        didManuallySelectNetwork = true
        cardNumberDigits = card.digitsOnly
        cardholderName = card.cardholderName
        expiryMonth = card.expiryMonth
        expiryYear = card.expiryYear
        cvv = card.cvv
        theme = card.theme
        isFavorite = card.isFavorite

        billingAddress = card.billingAddress
        postalCode = card.postalCode
        pin = card.pin
        phoneLast4 = card.phoneLast4
        statementDayString = card.statementDay.map(String.init) ?? ""
        dueDayString = card.dueDay.map(String.init) ?? ""
        creditLimit = card.creditLimit
        notes = card.notes

        if !billingAddress.isEmpty || !postalCode.isEmpty || !pin.isEmpty || card.statementDay != nil || !notes.isEmpty {
            showExtendedFields = true
        }
    }

    private func scrubState() {
        previewRevealTask?.cancel()
        revealInSecurePreview = false
        bankName = ""
        nickname = ""
        cardNumberDigits = ""
        cardholderName = ""
        expiryMonth = ""
        expiryYear = ""
        cvv = ""
        billingAddress = ""
        postalCode = ""
        pin = ""
        phoneLast4 = ""
        statementDayString = ""
        dueDayString = ""
        creditLimit = ""
        notes = ""
    }

    private func saveCard() {
        validationError = nil

        if !expiryMonth.isEmpty {
            guard let m = Int(expiryMonth), (1...12).contains(m) else {
                validationError = tr("有效期月份需在 01 到 12 之间", "Expiry month must be between 01 and 12")
                return
            }
        }

        let statementDay = Int(statementDayString).flatMap { (1...31).contains($0) ? $0 : nil }
        let dueDay = Int(dueDayString).flatMap { (1...31).contains($0) ? $0 : nil }

        let paddedMonth: String
        if expiryMonth.isEmpty {
            paddedMonth = ""
        } else {
            paddedMonth = expiryMonth.count == 1 ? "0\(expiryMonth)" : expiryMonth
        }

        let card = BankCard(
            id: existingCard?.id ?? UUID(),
            bankName: bankName.isEmpty ? network.shortName : bankName,
            nickname: nickname,
            cardType: cardType,
            network: network,
            cardNumber: cardNumberDigits,
            cardholderName: cardholderName.uppercased(),
            expiryMonth: paddedMonth,
            expiryYear: expiryYear,
            cvv: cvv,
            pin: pin,
            billingAddress: billingAddress,
            postalCode: postalCode,
            phoneLast4: phoneLast4,
            statementDay: statementDay,
            dueDay: dueDay,
            creditLimit: creditLimit,
            notes: notes,
            theme: theme,
            isFavorite: isFavorite,
            createdAt: existingCard?.createdAt ?? Date(),
            updatedAt: Date()
        )

        do {
            if existingCard != nil {
                try store.updateCard(card)
            } else {
                try store.addCard(card)
            }
            scrubState()
            dismiss()
        } catch {
            validationError = error.localizedDescription
        }
    }
}
