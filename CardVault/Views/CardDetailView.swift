import SwiftUI

struct CardDetailView: View {
    @ObservedObject var store: VaultStore
    let cardID: UUID

    @Environment(\.dismiss) private var dismiss

    @State private var isRevealed = false
    @State private var revealRemaining = 0
    @State private var revealTask: Task<Void, Never>? = nil

    @State private var showingEditor = false
    @State private var showingDeleteConfirm = false

    private var card: BankCard? {
        store.cards.first(where: { $0.id == cardID })
    }

    var body: some View {
        Group {
            if let card {
                ScrollView {
                    VStack(spacing: 20) {
                        if store.isScreenCaptured {
                            ScreenCaptureWarningBanner()
                                .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                        }

                        // Card Visual + Reveal Toggle
                        VStack(spacing: 12) {
                            CardVisualView(
                                card: card,
                                isRevealed: isRevealed,
                                forceMasked: store.isScreenCaptured
                            )
                            .screenshotProtected()

                            Button {
                                toggleReveal()
                            } label: {
                                HStack(spacing: 6) {
                                    Image(systemName: isRevealed ? "eye.slash.fill" : "eye.fill")
                                    Text(isRevealed
                                        ? tr("隐藏明文（\(revealRemaining)s）", "Hide Details (\(revealRemaining)s)")
                                        : tr("在安全图层中显示明文（10秒自动隐藏）", "Reveal in Secure Layer (Auto-hides in 10s)"))
                                        .font(.subheadline.weight(.medium))
                                }
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 10)
                                .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                            }
                            .buttonStyle(.plain)
                            .disabled(store.isScreenCaptured)
                        }

                        // Primary Online Checkout Fields
                        VStack(alignment: .leading, spacing: 0) {
                            SectionHeaderLabel(title: tr("网购结账一键复制", "Quick Copy for Checkout"), icon: "cart.fill")

                            VStack(spacing: 0) {
                                DetailCopyRow(
                                    label: tr("卡号（无空格）", "Card Number (No Spaces)"),
                                    value: (isRevealed && !store.isScreenCaptured) ? card.formattedNumber : card.maskedNumber,
                                    monospaced: true,
                                    primaryActionTitle: tr("复制", "Copy"),
                                    onPrimaryCopy: {
                                        store.copySecure(card.digitsOnly, label: tr("无空格卡号", "Card Number"))
                                    }
                                )
                                .contextMenu {
                                    Button {
                                        store.copySecure(card.digitsOnly, label: tr("无空格卡号", "Card Number"))
                                    } label: {
                                        Label(tr("复制纯数字卡号（网购推荐）", "Copy Digits Only (Recommended)"), systemImage: "doc.on.doc")
                                    }
                                    Button {
                                        store.copySecure(card.formattedNumber, label: tr("分段卡号", "Formatted Number"))
                                    } label: {
                                        Label(tr("复制带空格卡号", "Copy Formatted Number"), systemImage: "textformat.123")
                                    }
                                }

                                if !card.formattedExpiry.isEmpty {
                                    Divider().padding(.leading, 16)
                                    ExpiryCopyRow(
                                        card: card,
                                        isMasked: store.isScreenCaptured,
                                        onCopyFull: {
                                            store.copySecure(card.formattedExpiry, label: tr("有效期", "Expiry"))
                                        },
                                        onCopyMonth: {
                                            let m = card.expiryMonth.count == 1 ? "0\(card.expiryMonth)" : card.expiryMonth
                                            store.copySecure(m, label: tr("有效期月份", "Expiry Month"))
                                        },
                                        onCopyYear: {
                                            store.copySecure(BankCard.normalizeYear(card.expiryYear), label: tr("有效期年份", "Expiry Year"))
                                        }
                                    )
                                }

                                if !card.cvv.isEmpty {
                                    Divider().padding(.leading, 16)
                                    DetailCopyRow(
                                        label: tr("安全码 (CVV / CVC)", "Security Code (CVV / CVC)"),
                                        value: (isRevealed && !store.isScreenCaptured)
                                            ? card.cvv
                                            : String(repeating: "•", count: max(3, card.cvv.count)),
                                        monospaced: true,
                                        primaryActionTitle: tr("复制", "Copy"),
                                        onPrimaryCopy: {
                                            store.copySecure(card.cvv, label: tr("安全码 CVV", "CVV"))
                                        }
                                    )
                                }

                                if !card.cardholderName.isEmpty {
                                    Divider().padding(.leading, 16)
                                    DetailCopyRow(
                                        label: tr("持卡人姓名", "Cardholder Name"),
                                        value: store.isScreenCaptured ? "•••• ••••" : card.cardholderName.uppercased(),
                                        monospaced: true,
                                        primaryActionTitle: tr("复制", "Copy"),
                                        onPrimaryCopy: {
                                            store.copySecure(card.cardholderName.uppercased(), label: tr("持卡人姓名", "Cardholder"))
                                        }
                                    )
                                }
                            }
                            .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                        }

                        // Billing Address & Overseas Info
                        if !card.billingAddress.isEmpty || !card.postalCode.isEmpty {
                            VStack(alignment: .leading, spacing: 0) {
                                SectionHeaderLabel(title: tr("海淘账单地址 (Billing Address)", "Billing Address"), icon: "globe.asia.australia.fill")

                                VStack(spacing: 0) {
                                    if !card.billingAddress.isEmpty {
                                        DetailCopyRow(
                                            label: tr("账单地址", "Street Address"),
                                            value: store.isScreenCaptured ? "••••••••" : card.billingAddress,
                                            monospaced: false,
                                            primaryActionTitle: tr("复制", "Copy"),
                                            onPrimaryCopy: {
                                                store.copySecure(card.billingAddress, label: tr("账单地址", "Billing Address"))
                                            }
                                        )
                                    }
                                    if !card.billingAddress.isEmpty && !card.postalCode.isEmpty {
                                        Divider().padding(.leading, 16)
                                    }
                                    if !card.postalCode.isEmpty {
                                        DetailCopyRow(
                                            label: tr("邮政编码 (ZIP / Postal)", "ZIP / Postal Code"),
                                            value: store.isScreenCaptured ? "•••••" : card.postalCode,
                                            monospaced: true,
                                            primaryActionTitle: tr("复制", "Copy"),
                                            onPrimaryCopy: {
                                                store.copySecure(card.postalCode, label: tr("邮政编码", "Postal Code"))
                                            }
                                        )
                                    }
                                }
                                .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                            }
                        }

                        // Extra Card Metadata (All values inside `.screenshotProtected()`; sensitive notes masked until revealed)
                        if hasExtendedMetadata(card) {
                            VStack(alignment: .leading, spacing: 0) {
                                SectionHeaderLabel(title: tr("用卡与账单详情", "Billing & Card Details"), icon: "info.circle.fill")

                                VStack(spacing: 0) {
                                    if !card.pin.isEmpty {
                                        DetailCopyRow(
                                            label: tr("交易 / 取现 PIN（旧版遗留，强烈建议在编辑页清除）", "Legacy PIN (Strongly recommended to remove in Edit)"),
                                            value: (isRevealed && !store.isScreenCaptured) ? card.pin : "••••••",
                                            monospaced: true,
                                            primaryActionTitle: tr("复制", "Copy"),
                                            onPrimaryCopy: {
                                                store.copySecure(card.pin, label: "PIN")
                                            }
                                        )
                                        Divider().padding(.leading, 16)
                                    }

                                    if card.statementDay != nil || card.dueDay != nil {
                                        MetadataStaticRow(
                                            label: tr("账单日 / 还款日", "Statement / Due Day"),
                                            value: formatBillingCycle(statement: card.statementDay, due: card.dueDay)
                                        )
                                        Divider().padding(.leading, 16)
                                    }

                                    if !card.creditLimit.isEmpty {
                                        MetadataStaticRow(
                                            label: tr("授信额度 / 币种", "Credit Limit / Currency"),
                                            value: store.isScreenCaptured ? "••••" : card.creditLimit
                                        )
                                        Divider().padding(.leading, 16)
                                    }

                                    if !card.phoneLast4.isEmpty {
                                        MetadataStaticRow(
                                            label: tr("银行预留手机尾号", "Registered Phone Last 4"),
                                            value: (isRevealed && !store.isScreenCaptured)
                                                ? tr("尾号 \(card.phoneLast4)", "Ending in \(card.phoneLast4)")
                                                : tr("尾号 ••••", "Ending in ••••")
                                        )
                                        Divider().padding(.leading, 16)
                                    }

                                    if !card.notes.isEmpty {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text(tr("安全备注（点击上方「显示明文」查看）", "Secure Notes (Tap \"Reveal\" above to view)"))
                                                .font(.caption)
                                                .foregroundStyle(.secondary)
                                            Text((isRevealed && !store.isScreenCaptured) ? card.notes : "••••••••••••")
                                                .font(.subheadline)
                                                .foregroundStyle(.primary)
                                                .frame(maxWidth: .infinity, alignment: .leading)
                                                .screenshotProtected()
                                        }
                                        .padding(16)
                                    }
                                }
                                .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                            }
                        }

                        // Delete Card Button
                        Button(role: .destructive) {
                            showingDeleteConfirm = true
                        } label: {
                            Label(tr("删除这张银行卡", "Delete This Card"), systemImage: "trash")
                                .font(.subheadline.weight(.medium))
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 13)
                                .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        }
                        .padding(.top, 6)
                        .padding(.bottom, 50)
                    }
                    .padding(16)
                }
                .background(Color(.systemGroupedBackground))
                .navigationTitle(card.bankName.isEmpty ? tr("卡片详情", "Card Details") : card.bankName)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItemGroup(placement: .cardSeTrailing) {
                        Button {
                            do {
                                try store.toggleFavorite(for: card.id)
                            } catch {
                                store.securityNotice = tr(
                                    "保存收藏状态失败：\(error.localizedDescription)",
                                    "Failed to update favorite status: \(error.localizedDescription)"
                                )
                            }
                        } label: {
                            Image(systemName: card.isFavorite ? "star.fill" : "star")
                                .foregroundStyle(card.isFavorite ? Color.yellow : Color.primary)
                        }

                        Button(tr("编辑", "Edit")) {
                            guard !store.isScreenCaptured else {
                                store.securityNotice = tr(
                                    "正在录屏或投屏期间，禁止进入编辑页面。",
                                    "Editing is blocked during screen recording or mirroring."
                                )
                                return
                            }
                            showingEditor = true
                        }
                        .disabled(store.isScreenCaptured)
                    }
                }
                .sheet(isPresented: $showingEditor) {
                    CardEditorView(store: store, existingCard: card)
                }
                .confirmationDialog(
                    tr("确定要永久删除「\(card.displayTitle)」吗？", "Permanently delete \"\(card.displayTitle)\"?"),
                    isPresented: $showingDeleteConfirm,
                    titleVisibility: .visible
                ) {
                    Button(tr("确认删除", "Delete Card"), role: .destructive) {
                        do {
                            try store.deleteCard(id: card.id)
                            dismiss()
                        } catch {
                            store.securityNotice = tr(
                                "删除银行卡失败：\(error.localizedDescription)",
                                "Failed to delete card: \(error.localizedDescription)"
                            )
                        }
                    }
                    Button(tr("取消", "Cancel"), role: .cancel) {}
                }
                .onDisappear {
                    hidePlaintextImmediately()
                }
                .onValueChange(of: store.screenshotEventCount) { _ in
                    hidePlaintextImmediately()
                }
                .onValueChange(of: store.isScreenCaptured) { captured in
                    if captured {
                        hidePlaintextImmediately()
                        showingEditor = false
                        showingDeleteConfirm = false
                    }
                }
                .onValueChange(of: store.phase) { newPhase in
                    if newPhase != .unlocked {
                        hidePlaintextImmediately()
                        showingEditor = false
                        showingDeleteConfirm = false
                    }
                }
            } else {
                EnkardUnavailableStateView(
                    icon: "creditcard",
                    title: tr("卡片不存在", "Card Not Found"),
                    subtitle: tr("该银行卡可能已被删除", "This card may have been deleted")
                )
            }
        }
    }

    private func toggleReveal() {
        if isRevealed {
            hidePlaintextImmediately()
        } else {
            isRevealed = true
            revealRemaining = 10
            revealTask?.cancel()
            revealTask = Task {
                while revealRemaining > 0, !Task.isCancelled {
                    try? await Task.sleep(for: .seconds(1))
                    guard !Task.isCancelled else { return }
                    revealRemaining -= 1
                }
                if !Task.isCancelled {
                    isRevealed = false
                }
            }
        }
    }

    private func hidePlaintextImmediately() {
        revealTask?.cancel()
        isRevealed = false
        revealRemaining = 0
    }

    private func hasExtendedMetadata(_ card: BankCard) -> Bool {
        !card.pin.isEmpty
            || card.statementDay != nil
            || card.dueDay != nil
            || !card.creditLimit.isEmpty
            || !card.phoneLast4.isEmpty
            || !card.notes.isEmpty
    }

    private func formatBillingCycle(statement: Int?, due: Int?) -> String {
        var parts: [String] = []
        if let s = statement {
            parts.append(tr("每月 \(s) 日出账", "Statement Day \(s)"))
        }
        if let d = due {
            parts.append(tr("每月 \(d) 日还款", "Due Day \(d)"))
        }
        return parts.joined(separator: " · ")
    }
}

private struct SectionHeaderLabel: View {
    let title: String
    let icon: String

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: icon)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            Text(title)
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.secondary)
        }
        .padding(.leading, 6)
        .padding(.bottom, 8)
    }
}

private struct DetailCopyRow: View {
    let label: String
    let value: String
    let monospaced: Bool
    let primaryActionTitle: String
    let onPrimaryCopy: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(value)
                    .font(monospaced ? .system(.body, design: .monospaced, weight: .semibold) : .body)
                    .foregroundStyle(.primary)
                    .screenshotProtected()
            }

            Spacer(minLength: 8)

            Button(action: onPrimaryCopy) {
                HStack(spacing: 4) {
                    Image(systemName: "doc.on.doc.fill")
                        .font(.caption2)
                    Text(primaryActionTitle)
                        .font(.caption.weight(.semibold))
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                .background(Color.accentColor.opacity(0.14), in: Capsule())
                .foregroundStyle(.tint)
            }
            .buttonStyle(.plain)
        }
        .padding(16)
    }
}

private struct ExpiryCopyRow: View {
    let card: BankCard
    let isMasked: Bool
    let onCopyFull: () -> Void
    let onCopyMonth: () -> Void
    let onCopyYear: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 4) {
                Text(tr("有效期 (MM/YY)", "Expiry (MM/YY)"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(isMasked ? "••/••" : card.formattedExpiry)
                    .font(.system(.body, design: .monospaced, weight: .semibold))
                    .screenshotProtected()
            }

            Spacer(minLength: 4)

            Button(tr("月", "MM"), action: onCopyMonth)
                .font(.caption.weight(.semibold))
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
                .background(Color(.tertiarySystemGroupedBackground), in: Capsule())
                .buttonStyle(.plain)

            Button(tr("年", "YY"), action: onCopyYear)
                .font(.caption.weight(.semibold))
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
                .background(Color(.tertiarySystemGroupedBackground), in: Capsule())
                .buttonStyle(.plain)

            Button(action: onCopyFull) {
                HStack(spacing: 4) {
                    Image(systemName: "doc.on.doc.fill")
                        .font(.caption2)
                    Text(tr("复制", "Copy"))
                        .font(.caption.weight(.semibold))
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                .background(Color.accentColor.opacity(0.14), in: Capsule())
                .foregroundStyle(.tint)
            }
            .buttonStyle(.plain)
        }
        .padding(16)
    }
}

private struct MetadataStaticRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.subheadline.weight(.medium))
                .foregroundStyle(.primary)
                .screenshotProtected()
        }
        .padding(16)
    }
}
