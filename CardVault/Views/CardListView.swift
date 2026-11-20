import SwiftUI

enum CardFilterCategory: String, CaseIterable, Identifiable {
    case all
    case favorites
    case international
    case unionPay
    case credit
    case debit

    var id: String { rawValue }

    var title: String {
        switch self {
        case .all: return tr("全部", "All")
        case .favorites: return tr("收藏", "Favorites")
        case .international: return tr("外币/海淘卡", "Global")
        case .unionPay: return tr("银联", "UnionPay")
        case .credit: return tr("信用卡", "Credit")
        case .debit: return tr("借记卡", "Debit")
        }
    }
}

struct CardListView: View {
    @ObservedObject var store: VaultStore

    @State private var navigationPath = NavigationPath()
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
                || card.network.searchKeywords.contains(where: { $0.contains(query) })
                || card.cardholderName.lowercased().contains(query)
        }
    }

    var body: some View {
        NavigationStack(path: $navigationPath) {
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
                                EnkardUnavailableStateView(
                                    icon: "magnifyingglass",
                                    title: tr("无匹配卡片", "No Matching Cards"),
                                    subtitle: searchText.isEmpty
                                        ? tr("当前筛选分类下暂无银行卡", "No cards in this category yet")
                                        : tr("未找到包含「\(searchText)」的银行卡", "No cards matching \"\(searchText)\"")
                                )
                                .padding(.top, 40)
                            } else {
                                LazyVStack(spacing: 20) {
                                    ForEach(filteredCards) { card in
                                        CardDeckItemView(
                                            card: card,
                                            forceMasked: store.isScreenCaptured,
                                            onCopyNumber: {
                                                store.copySecure(card.digitsOnly, label: tr("无空格卡号", "Card Number"))
                                            },
                                            onCopyExpiry: {
                                                store.copySecure(card.formattedExpiry, label: tr("有效期", "Expiry"))
                                            },
                                            onCopyCVV: {
                                                store.copySecure(card.cvv, label: tr("安全码 CVV", "CVV"))
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
            .navigationTitle("Enkard")
            .searchable(text: $searchText, prompt: tr("搜索银行、别名、尾号、卡组织", "Search bank, alias, last 4, or network"))
            .lockdownTextInput()
            .toolbar {
                ToolbarItemGroup(placement: .cardSeLeading) {
                    Button {
                        store.lock(reason: .manual)
                    } label: {
                        Image(systemName: "lock.fill")
                    }
                    .accessibilityLabel(tr("立即锁定", "Lock Now"))

                    if store.biometricsEnabled && store.biometricKind != .none {
                        Button {
                            store.enterEmergencyLockdown()
                        } label: {
                            Image(systemName: "exclamationmark.lock.fill")
                                .foregroundStyle(.orange)
                        }
                        .accessibilityLabel(tr("紧急锁定（禁用生物识别）", "Emergency Lockdown (Disable Biometrics)"))
                    }

                    Button {
                        showingSettings = true
                    } label: {
                        Image(systemName: "shield.lefthalf.filled")
                    }
                    .accessibilityLabel(tr("安全与备份设置", "Security & Backup Settings"))
                }

                ToolbarItem(placement: .cardSeTrailing) {
                    Button {
                        guard !store.isScreenCaptured else {
                            store.securityNotice = tr(
                                "正在录屏或投屏期间，禁止进入添加或编辑银行卡页面。",
                                "Adding or editing cards is blocked during screen recording or mirroring."
                            )
                            return
                        }
                        showingAddCard = true
                    } label: {
                        Label(tr("添加卡片", "Add Card"), systemImage: "plus.circle.fill")
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
            .onValueChange(of: searchText) { newQuery in
                if newQuery.count > 128 {
                    searchText = String(newQuery.prefix(128))
                }
            }
            .onValueChange(of: store.phase) { newPhase in
                if newPhase != .unlocked {
                    navigationPath = NavigationPath()
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
                        Text(category.title)
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

            Text(tr("还没有保存银行卡", "No Cards Stored Yet"))
                .font(.title3.bold())

            Text(tr(
                "卡片信息由本机 Secure Enclave 安全芯片加密，零联网零同步。网购时一键复制，锁屏或到期自动销毁。",
                "Your cards are encrypted locally via Secure Enclave with zero network or cloud sync. Tap to copy at checkout; clipboard clears on lock or timeout."
            ))
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 36)

            Button {
                guard !store.isScreenCaptured else { return }
                showingAddCard = true
            } label: {
                Label(tr("添加第一张银行卡", "Add Your First Card"), systemImage: "plus")
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
                    title: tr("复制卡号", "Copy No."),
                    action: onCopyNumber
                )

                if !card.formattedExpiry.isEmpty {
                    QuickCopyPillButton(
                        icon: "calendar",
                        title: tr("复制有效期", "Expiry"),
                        action: onCopyExpiry
                    )
                }

                if !card.cvv.isEmpty {
                    QuickCopyPillButton(
                        icon: "lock.rectangle.fill",
                        title: tr("复制 CVV", "CVV"),
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
