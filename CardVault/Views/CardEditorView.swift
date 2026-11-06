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

    private let commonBanks = [
        "招商银行", "工商银行", "建设银行", "中国银行", "农业银行",
        "交通银行", "中信银行", "平安银行", "浦发银行", "广发银行", "兴业银行"
    ]

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
                                revealInSecurePreview ? "隐藏安全预览卡面明文" : "在防截屏卡面上核对完整卡号与 CVV（8秒自动收起）",
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
                Section("核心卡面信息（禁输入法同步与写作工具）") {
                    VStack(alignment: .leading, spacing: 8) {
                        TextField("发卡银行（如：招商银行）", text: $bankName)
                            .lockdownTextInput()

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

                    TextField("卡片别名（选填，如：全币种海淘卡）", text: $nickname)
                        .lockdownTextInput()

                    // Card Number: SecureField by default so screenshots cannot capture full PAN in the form!
                    VStack(alignment: .leading, spacing: 6) {
                        SecureField("输入银行卡号（13–19 位纯数字，上方安全卡面可核对）", text: $cardNumberDigits)
                            .keyboardType(.numberPad)
                            .lockdownTextInput()
                            .focused($cardNumberFocused)
                            .font(.system(.body, design: .monospaced))
                            .onValueChange(of: cardNumberDigits) { newValue in
                                let filtered = String(newValue.filter(\.isWholeNumber).prefix(19))
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
                                Label("Luhn 卡号校验位通过（\(cardNumberDigits.count) 位）", systemImage: "checkmark.circle.fill")
                                    .font(.caption2)
                                    .foregroundStyle(.green)
                            } else {
                                Label("卡号校验位异常，请点击上方安全预览核对是否输错数字", systemImage: "exclamationmark.triangle.fill")
                                    .font(.caption2)
                                    .foregroundStyle(.orange)
                            }
                        }
                    }

                    HStack(spacing: 12) {
                        Text("有效期")
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
                    SecureField("安全码 CVV（卡背面末 3 位，运通 4 位）", text: $cvv)
                        .keyboardType(.numberPad)
                        .lockdownTextInput()
                        .font(.system(.body, design: .monospaced))
                        .onValueChange(of: cvv) { val in
                            cvv = String(val.filter(\.isWholeNumber).prefix(4))
                        }

                    TextField("持卡人英文/拼音（选填，如 SAN ZHANG）", text: $cardholderName)
                        .lockdownTextInput(autocapitalization: .characters)
                }

                // Classification & Card Theme
                Section("卡种与外观配色") {
                    Picker("卡片类型", selection: $cardType) {
                        ForEach(CardType.allCases) { type in
                            Text(type.title).tag(type)
                        }
                    }

                    Picker("卡组织", selection: $network) {
                        ForEach(CardNetwork.allCases) { net in
                            Text(net.badgeText).tag(net)
                        }
                    }
                    .onValueChange(of: network) { _ in
                        didManuallySelectNetwork = true
                    }

                    VStack(alignment: .leading, spacing: 10) {
                        Text("卡面金属配色：\(theme.title)")
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

                    Toggle("设为收藏置顶卡片", isOn: $isFavorite)
                }

                // Optional Overseas Billing & Statement Info
                Section {
                    DisclosureGroup("海淘账单地址、账单日与备注（选填）", isExpanded: $showExtendedFields) {
                        TextField("海淘账单地址 (Billing Address)", text: $billingAddress)
                            .lockdownTextInput()
                        TextField("账单邮编 (ZIP / Postal Code)", text: $postalCode)
                            .keyboardType(.asciiCapable)
                            .lockdownTextInput()

                        if !pin.isEmpty {
                            VStack(alignment: .leading, spacing: 6) {
                                Label("这张卡包含旧版遗留的交易 PIN", systemImage: "exclamationmark.triangle.fill")
                                    .font(.subheadline.weight(.medium))
                                    .foregroundStyle(.orange)
                                Text("线下刷卡/取现 PIN 不应与线上 CVV 共同保存。强烈建议立即清除。")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Button("清除已保存的 PIN", role: .destructive) {
                                    pin = ""
                                }
                                .font(.subheadline)
                            }
                            .padding(.vertical, 4)
                        }

                        SecureField("银行预留手机号后四位", text: $phoneLast4)
                            .keyboardType(.numberPad)
                            .lockdownTextInput()
                            .onValueChange(of: phoneLast4) { val in
                                phoneLast4 = String(val.filter(\.isWholeNumber).prefix(4))
                            }

                        HStack {
                            Text("每月账单日")
                            Spacer()
                            TextField("如 5", text: $statementDayString)
                                .keyboardType(.numberPad)
                                .lockdownTextInput()
                                .multilineTextAlignment(.trailing)
                                .frame(width: 70)
                        }

                        HStack {
                            Text("每月还款日")
                            Spacer()
                            TextField("如 23", text: $dueDayString)
                                .keyboardType(.numberPad)
                                .lockdownTextInput()
                                .multilineTextAlignment(.trailing)
                                .frame(width: 70)
                        }

                        TextField("授信额度 / 币种（如 50,000 CNY）", text: $creditLimit)
                            .lockdownTextInput()
                        SecureField("安全备注（保存后默认打码）", text: $notes)
                            .lockdownTextInput()
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
            .navigationTitle(existingCard == nil ? "添加银行卡" : "编辑银行卡")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") {
                        scrubState()
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("硬件加密保存") {
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
                    previewRevealTask?.cancel()
                    revealInSecurePreview = false
                }
            }
            .onValueChange(of: store.phase) { newPhase in
                if newPhase != .unlocked {
                    scrubState()
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
                validationError = "有效期月份需在 01 到 12 之间"
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
