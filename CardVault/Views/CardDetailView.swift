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
                                    Text(isRevealed ? "隐藏明文（\(revealRemaining)s）" : "在安全图层中显示明文（10秒自动隐藏）")
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
                            SectionHeaderLabel(title: "网购结账一键复制", icon: "cart.fill")

                            VStack(spacing: 0) {
                                DetailCopyRow(
                                    label: "卡号（无空格）",
                                    value: (isRevealed && !store.isScreenCaptured) ? card.formattedNumber : card.maskedNumber,
                                    monospaced: true,
                                    primaryActionTitle: "复制",
                                    onPrimaryCopy: {
                                        store.copySecure(card.digitsOnly, label: "无空格卡号")
                                    }
                                )
                                .contextMenu {
                                    Button {
                                        store.copySecure(card.digitsOnly, label: "无空格卡号")
                                    } label: {
                                        Label("复制纯数字卡号（网购推荐）", systemImage: "doc.on.doc")
                                    }
                                    Button {
                                        store.copySecure(card.formattedNumber, label: "分段卡号")
                                    } label: {
                                        Label("复制带空格卡号", systemImage: "textformat.123")
                                    }
                                }

                                if !card.formattedExpiry.isEmpty {
                                    Divider().padding(.leading, 16)
                                    ExpiryCopyRow(
                                        card: card,
                                        isMasked: store.isScreenCaptured,
                                        onCopyFull: {
                                            store.copySecure(card.formattedExpiry, label: "有效期")
                                        },
                                        onCopyMonth: {
                                            let m = card.expiryMonth.count == 1 ? "0\(card.expiryMonth)" : card.expiryMonth
                                            store.copySecure(m, label: "有效期月份")
                                        },
                                        onCopyYear: {
                                            store.copySecure(BankCard.normalizeYear(card.expiryYear), label: "有效期年份")
                                        }
                                    )
                                }

                                if !card.cvv.isEmpty {
                                    Divider().padding(.leading, 16)
                                    DetailCopyRow(
                                        label: "安全码 (CVV / CVC)",
                                        value: (isRevealed && !store.isScreenCaptured)
                                            ? card.cvv
                                            : String(repeating: "•", count: max(3, card.cvv.count)),
                                        monospaced: true,
                                        primaryActionTitle: "复制",
                                        onPrimaryCopy: {
                                            store.copySecure(card.cvv, label: "安全码 CVV")
                                        }
                                    )
                                }

                                if !card.cardholderName.isEmpty {
                                    Divider().padding(.leading, 16)
                                    DetailCopyRow(
                                        label: "持卡人姓名",
                                        value: store.isScreenCaptured ? "•••• ••••" : card.cardholderName.uppercased(),
                                        monospaced: true,
                                        primaryActionTitle: "复制",
                                        onPrimaryCopy: {
                                            store.copySecure(card.cardholderName.uppercased(), label: "持卡人姓名")
                                        }
                                    )
                                }
                            }
                            .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                        }

                        // Billing Address & Overseas Info
                        if !card.billingAddress.isEmpty || !card.postalCode.isEmpty {
                            VStack(alignment: .leading, spacing: 0) {
                                SectionHeaderLabel(title: "海淘账单地址 (Billing Address)", icon: "globe.asia.australia.fill")

                                VStack(spacing: 0) {
                                    if !card.billingAddress.isEmpty {
                                        DetailCopyRow(
                                            label: "账单地址",
                                            value: store.isScreenCaptured ? "••••••••" : card.billingAddress,
                                            monospaced: false,
                                            primaryActionTitle: "复制",
                                            onPrimaryCopy: {
                                                store.copySecure(card.billingAddress, label: "账单地址")
                                            }
                                        )
                                    }
                                    if !card.billingAddress.isEmpty && !card.postalCode.isEmpty {
                                        Divider().padding(.leading, 16)
                                    }
                                    if !card.postalCode.isEmpty {
                                        DetailCopyRow(
                                            label: "邮政编码 (ZIP / Postal)",
                                            value: store.isScreenCaptured ? "•••••" : card.postalCode,
                                            monospaced: true,
                                            primaryActionTitle: "复制",
                                            onPrimaryCopy: {
                                                store.copySecure(card.postalCode, label: "邮政编码")
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
                                SectionHeaderLabel(title: "用卡与账单详情", icon: "info.circle.fill")

                                VStack(spacing: 0) {
                                    if !card.pin.isEmpty {
                                        DetailCopyRow(
                                            label: "交易 / 取现 PIN（旧版遗留，强烈建议在编辑页清除）",
                                            value: (isRevealed && !store.isScreenCaptured) ? card.pin : "••••••",
                                            monospaced: true,
                                            primaryActionTitle: "复制",
                                            onPrimaryCopy: {
                                                store.copySecure(card.pin, label: "PIN")
                                            }
                                        )
                                        Divider().padding(.leading, 16)
                                    }

                                    if card.statementDay != nil || card.dueDay != nil {
                                        MetadataStaticRow(
                                            label: "账单日 / 还款日",
                                            value: formatBillingCycle(statement: card.statementDay, due: card.dueDay)
                                        )
                                        Divider().padding(.leading, 16)
                                    }

                                    if !card.creditLimit.isEmpty {
                                        MetadataStaticRow(
                                            label: "授信额度 / 币种",
                                            value: store.isScreenCaptured ? "••••" : card.creditLimit
                                        )
                                        Divider().padding(.leading, 16)
                                    }

                                    if !card.phoneLast4.isEmpty {
                                        MetadataStaticRow(
                                            label: "银行预留手机尾号",
                                            value: (isRevealed && !store.isScreenCaptured) ? "尾号 \(card.phoneLast4)" : "尾号 ••••"
                                        )
                                        Divider().padding(.leading, 16)
                                    }

                                    if !card.notes.isEmpty {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text("安全备注（点击上方「显示明文」查看）")
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
                            Label("删除这张银行卡", systemImage: "trash")
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
                .navigationTitle(card.bankName.isEmpty ? "卡片详情" : card.bankName)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItemGroup(placement: .cardSeTrailing) {
                        Button {
                            do {
                                try store.toggleFavorite(for: card.id)
                            } catch {
                                store.securityNotice = "保存收藏状态失败：\(error.localizedDescription)"
                            }
                        } label: {
                            Image(systemName: card.isFavorite ? "star.fill" : "star")
                                .foregroundStyle(card.isFavorite ? Color.yellow : Color.primary)
                        }

                        Button("编辑") {
                            guard !store.isScreenCaptured else {
                                store.securityNotice = "正在录屏或投屏期间，禁止进入编辑页面。"
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
                    "确定要永久删除「\(card.displayTitle)」吗？",
                    isPresented: $showingDeleteConfirm,
                    titleVisibility: .visible
                ) {
                    Button("确认删除", role: .destructive) {
                        do {
                            try store.deleteCard(id: card.id)
                            dismiss()
                        } catch {
                            store.securityNotice = "删除银行卡失败：\(error.localizedDescription)"
                        }
                    }
                    Button("取消", role: .cancel) {}
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
                    }
                }
                .onValueChange(of: store.phase) { newPhase in
                    if newPhase != .unlocked {
                        hidePlaintextImmediately()
                        showingEditor = false
                    }
                }
            } else {
                CardSeUnavailableStateView(
                    icon: "creditcard",
                    title: "卡片不存在",
                    subtitle: "该银行卡可能已被删除"
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
        if let s = statement { parts.append("每月 \(s) 日出账") }
        if let d = due { parts.append("每月 \(d) 日还款") }
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
                Text("有效期 (MM/YY)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(isMasked ? "••/••" : card.formattedExpiry)
                    .font(.system(.body, design: .monospaced, weight: .semibold))
                    .screenshotProtected()
            }

            Spacer(minLength: 4)

            Button("月", action: onCopyMonth)
                .font(.caption.weight(.semibold))
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
                .background(Color(.tertiarySystemGroupedBackground), in: Capsule())
                .buttonStyle(.plain)

            Button("年", action: onCopyYear)
                .font(.caption.weight(.semibold))
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
                .background(Color(.tertiarySystemGroupedBackground), in: Capsule())
                .buttonStyle(.plain)

            Button(action: onCopyFull) {
                HStack(spacing: 4) {
                    Image(systemName: "doc.on.doc.fill")
                        .font(.caption2)
                    Text("复制")
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
