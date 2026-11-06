import SwiftUI

enum CardFilterCategory: String, CaseIterable, Identifiable {
    case all = "全部"
    case favorites = "收藏"
    case international = "外币/海淘卡"
    case unionPay = "银联"
    case credit = "信用卡"
    case debit = "借记卡"

    var id: String { rawValue }
}

struct CardListView: View {
    @ObservedObject var store: VaultStore

    @State private var searchText = ""
    @State private var selectedFilter: CardFilterCategory = .all
    @State private var showingAddCard = false
    @State private var showingSettings = false

    private var filteredCards: [BankCard] {
        store.sortedCards.filter { card in
            let matchesFilter: Bool
            switch selectedFilter {
            case .all:
                matchesFilter = true
            case .favorites:
                matchesFilter = card.isFavorite
            case .international:
                matchesFilter = [.visa, .mastercard, .amex, .jcb, .discover].contains(card.network)
            case .unionPay:
                matchesFilter = card.network == .unionPay
            case .credit:
                matchesFilter = card.cardType == .credit
            case .debit:
                matchesFilter = card.cardType == .debit
            }
            guard matchesFilter else { return false }

            let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !query.isEmpty else { return true }

            return card.bankName.lowercased().contains(query)
                || card.nickname.lowercased().contains(query)
                || card.last4.contains(query)
                || card.network.shortName.lowercased().contains(query)
                || card.network.badgeText.lowercased().contains(query)
                || card.cardholderName.lowercased().contains(query)
        }
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if store.isScreenCaptured {
                    ScreenCaptureWarningBanner()
                }
                if store.runtimeIntegrity.isCompromised {
                    RuntimeCompromiseBanner(text: store.runtimeIntegrity.summaryText)
                        .padding(.horizontal, 16)
                        .padding(.top, 8)
                }

                if store.cards.isEmpty {
                    emptyVaultView
                } else {
                    ScrollView {
                        VStack(spacing: 18) {
                            filterChipsBar

                            if filteredCards.isEmpty {
                                CardSeUnavailableStateView(
                                    icon: "magnifyingglass",
                                    title: "无匹配卡片",
                                    subtitle: searchText.isEmpty ? "当前筛选分类下暂无银行卡" : "未找到包含「\(searchText)」的银行卡"
                                )
                                .padding(.top, 40)
                            } else {
                                LazyVStack(spacing: 20) {
                                    ForEach(filteredCards) { card in
                                        CardDeckItemView(
                                            card: card,
                                            forceMasked: store.isScreenCaptured,
                                            onCopyNumber: {
                                                store.copySecure(card.digitsOnly, label: "无空格卡号")
                                            },
                                            onCopyExpiry: {
                                                store.copySecure(card.formattedExpiry, label: "有效期")
                                            },
                                            onCopyCVV: {
                                                store.copySecure(card.cvv, label: "安全码 CVV")
                                            }
                                        )
                                    }
                                }
                                .padding(.horizontal, 16)
                                .padding(.bottom, 80)
                            }
                        }
                        .padding(.top, 8)
                    }
                }
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("CardSe")
            .searchable(text: $searchText, prompt: "搜索银行、别名、尾号、卡组织")
            .lockdownTextInput()
            .toolbar {
                ToolbarItemGroup(placement: .cardSeLeading) {
                    Button {
                        store.lock(reason: .manual)
                    } label: {
                        Image(systemName: "lock.fill")
                    }
                    .accessibilityLabel("立即锁定")

                    if store.biometricsEnabled && store.biometricKind != .none {
                        Button {
                            store.enterEmergencyLockdown()
                        } label: {
                            Image(systemName: "exclamationmark.lock.fill")
                                .foregroundStyle(.orange)
                        }
                        .accessibilityLabel("紧急锁定（禁用生物识别）")
                    }

                    Button {
                        showingSettings = true
                    } label: {
                        Image(systemName: "shield.lefthalf.filled")
                    }
                    .accessibilityLabel("安全与备份设置")
                }

                ToolbarItem(placement: .cardSeTrailing) {
                    Button {
                        guard !store.isScreenCaptured else {
                            store.securityNotice = "正在录屏或投屏期间，禁止进入添加或编辑银行卡页面。"
                            return
                        }
                        showingAddCard = true
                    } label: {
                        Label("添加卡片", systemImage: "plus.circle.fill")
                            .fontWeight(.semibold)
                    }
                    .disabled(store.isScreenCaptured)
                }
            }
            .navigationDestination(for: UUID.self) { cardID in
                if let card = store.cards.first(where: { $0.id == cardID }) {
                    CardDetailView(store: store, cardID: card.id)
                }
            }
            .sheet(isPresented: $showingAddCard) {
                CardEditorView(store: store, existingCard: nil)
            }
            .sheet(isPresented: $showingSettings) {
                SecuritySettingsView(store: store)
            }
            .onValueChange(of: store.phase) { newPhase in
                if newPhase != .unlocked {
                    searchText = ""
                    showingAddCard = false
                    showingSettings = false
                }
            }
            .onValueChange(of: store.isScreenCaptured) { captured in
                if captured {
                    showingAddCard = false
                }
            }
            .onDisappear {
                searchText = ""
            }
        }
    }

    private var filterChipsBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(CardFilterCategory.allCases) { category in
                    let isSelected = selectedFilter == category
                    Button {
                        withAnimation(.easeInOut(duration: 0.2)) {
                            selectedFilter = category
                        }
                    } label: {
                        Text(category.rawValue)
                            .font(.subheadline.weight(isSelected ? .semibold : .regular))
                            .foregroundStyle(isSelected ? Color.white : Color.primary)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 7)
                            .background(
                                isSelected ? Color.accentColor : Color(.secondarySystemGroupedBackground),
                                in: Capsule()
                            )
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 16)
        }
    }

    private var emptyVaultView: some View {
        VStack(spacing: 18) {
            Spacer()
            ZStack {
                Circle()
                    .fill(Color.accentColor.opacity(0.12))
                    .frame(width: 88, height: 88)
                Image(systemName: "creditcard.and.123")
                    .font(.system(size: 36, weight: .semibold))
                    .foregroundStyle(.tint)
            }

            Text("还没有保存银行卡")
                .font(.title3.bold())

            Text("卡片信息由本机 Secure Enclave 安全芯片加密，零联网零同步。网购时一键复制，锁屏或到期自动销毁。")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 36)

            Button {
                guard !store.isScreenCaptured else { return }
                showingAddCard = true
            } label: {
                Label("添加第一张银行卡", systemImage: "plus")
                    .fontWeight(.semibold)
                    .padding(.horizontal, 22)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.borderedProminent)
            .disabled(store.isScreenCaptured)
            .padding(.top, 4)

            Spacer()
        }
    }
}

private struct CardDeckItemView: View {
    let card: BankCard
    let forceMasked: Bool
    let onCopyNumber: () -> Void
    let onCopyExpiry: () -> Void
    let onCopyCVV: () -> Void

    var body: some View {
        VStack(spacing: 10) {
            NavigationLink(value: card.id) {
                CardVisualView(card: card, isRevealed: false, forceMasked: forceMasked)
                    .screenshotProtected()
            }
            .buttonStyle(.plain)

            // Instant Checkout Copy Bar (Never renders raw expiry digits outside `.screenshotProtected()`)
            HStack(spacing: 8) {
                QuickCopyPillButton(
                    icon: "doc.on.doc.fill",
                    title: "复制卡号",
                    action: onCopyNumber
                )

                if !card.formattedExpiry.isEmpty {
                    QuickCopyPillButton(
                        icon: "calendar",
                        title: "复制有效期",
                        action: onCopyExpiry
                    )
                }

                if !card.cvv.isEmpty {
                    QuickCopyPillButton(
                        icon: "lock.rectangle.fill",
                        title: "复制 CVV",
                        action: onCopyCVV
                    )
                }
            }
        }
    }
}

private struct QuickCopyPillButton: View {
    let icon: String
    let title: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Image(systemName: icon)
                    .font(.caption2.weight(.semibold))
                Text(title)
                    .font(.caption.weight(.semibold))
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 9)
            .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 11, style: .continuous))
        }
        .buttonStyle(.plain)
    }
}
