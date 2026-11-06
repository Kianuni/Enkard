import Combine
import CryptoKit
import Foundation
import UIKit

@MainActor
final class VaultStore: ObservableObject {
    enum Phase: Equatable {
        case loading
        case onboarding
        case locked
        case unlocked
    }

    enum LockReason {
        case manual
        case background
        case idle
        case deviceLocked
        case emergencyLockdown
        case securityAnomaly
    }

    @Published private(set) var phase: Phase = .loading
    @Published private(set) var cards: [BankCard] = []
    @Published private(set) var isBusy: Bool = false
    @Published var errorMessage: String?
    /// High-priority security alerts surfaced as a modal (rollback, prior failed attempts, screenshot, iCloud folder warning…).
    @Published var securityNotice: String?

    @Published private(set) var isAppInactive: Bool = false
    @Published private(set) var isScreenCaptured: Bool = false
    /// Incremented on every screenshot; views observe it to hide plaintext immediately.
    @Published private(set) var screenshotEventCount: Int = 0
    @Published private(set) var runtimeIntegrity: RuntimeIntegrityReport

    let clipboard = SecureClipboard()
    private var clipboardCancellable: AnyCancellable?
    private lazy var lockout = LockoutGuard()
    private let hardwareKeys: any HardwareKeyProvider

    // MARK: - Device-local non-synced preferences (stored in Keychain `WhenUnlockedThisDeviceOnly`, never backed up)

    @Published var biometricsEnabled: Bool {
        didSet { savePreferences() }
    }

    @Published var autoLockTimeout: AutoLockTimeout {
        didSet { savePreferences() }
    }

    @Published var idleLockTimeout: IdleLockTimeout {
        didSet { savePreferences() }
    }

    @Published var clipboardClearDuration: ClipboardClearDuration {
        didSet { savePreferences() }
    }

    @Published var wipeAfterFailedAttempts: Bool {
        didSet { savePreferences() }
    }

    // MARK: - Session state

    private var currentEnvelope: VaultEnvelope?
    /// DEK held as a CryptoKit key: its storage is zeroed on deallocation.
    private var activeKey: SymmetricKey?
    private var currentGeneration: UInt64 = 0
    private var needsReloadWhenProtectedDataAvailable = false
    private var hasBootstrapped = false
    private var isLoadingPreferences = false
    private var backgroundEnteredAt: Date?
    private var lastActivityAt = Date()
    private var backgroundLockTask: Task<Void, Never>?
    private var backgroundTaskID: UIBackgroundTaskIdentifier = .invalid

    init(hardwareKeys: any HardwareKeyProvider = DeviceHardwareKeyManager()) {
        self.hardwareKeys = hardwareKeys
        self.runtimeIntegrity = .cleanInitial
        self.biometricsEnabled = false
        self.autoLockTimeout = .immediately
        self.idleLockTimeout = .minutes3
        self.clipboardClearDuration = .seconds15
        self.wipeAfterFailedAttempts = false
        self.clipboardCancellable = clipboard.objectWillChange.sink { [weak self] _ in
            self?.objectWillChange.send()
        }
    }

    /// Synchronous 0ms anti-debug check at entry of every key derivation, unlock, rotation, or backup operation.
    private func rejectIfDebuggerAttached() -> Bool {
        #if !DEBUG
        if RuntimeSecurity.isDebuggerAttached() {
            clipboard.clearIfOwned()
            KeychainBiometrics.deleteBiometricDEK()
            lock(reason: .securityAnomaly)
            let msg = "检测到外部调试器附加，已立即销毁内存会话并拒绝执行敏感密钥操作。"
            errorMessage = msg
            securityNotice = msg
            return true
        }
        #endif
        return false
    }

    /// Runs once after `UIApplicationMain` and the active `UIWindowScene` are alive.
    func bootstrapIfNeeded() {
        guard !hasBootstrapped else { return }
        hasBootstrapped = true

        isLoadingPreferences = true
        let prefs = VaultPreferencesStore.load()
        biometricsEnabled = prefs.biometricsEnabled
        autoLockTimeout = AutoLockTimeout(rawValue: prefs.autoLockTimeoutRaw) ?? .immediately
        idleLockTimeout = IdleLockTimeout(rawValue: prefs.idleLockTimeoutRaw) ?? .minutes3
        clipboardClearDuration = ClipboardClearDuration(rawValue: prefs.clipboardClearDurationRaw) ?? .seconds15
        wipeAfterFailedAttempts = prefs.wipeAfterFailedAttempts
        isLoadingPreferences = false

        runtimeIntegrity = RuntimeSecurity.auditEnvironment(
            antiDebugActive: AppDelegate.antiDebugEnabledAtLaunch
        )
        migrateLegacyStorageDirectoryIfNeeded()
        refreshScreenCaptureState()
        loadVaultStateFromDisk()
    }

    private func savePreferences() {
        guard !isLoadingPreferences else { return }
        let prefs = VaultPreferences(
            biometricsEnabled: biometricsEnabled,
            autoLockTimeoutRaw: autoLockTimeout.rawValue,
            idleLockTimeoutRaw: idleLockTimeout.rawValue,
            clipboardClearDurationRaw: clipboardClearDuration.rawValue,
            wipeAfterFailedAttempts: wipeAfterFailedAttempts
        )
        VaultPreferencesStore.save(prefs)
    }

    var storageDirectoryURL: URL {
        let supportDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let folder = supportDir.appendingPathComponent("CardSeStorage", isDirectory: true)
        if !FileManager.default.fileExists(atPath: folder.path) {
            try? FileManager.default.createDirectory(
                at: folder,
                withIntermediateDirectories: true,
                attributes: [.protectionKey: FileProtectionType.complete]
            )
            excludeFromAllBackups(folder)
        }
        return folder
    }

    var vaultFileURL: URL {
        storageDirectoryURL.appendingPathComponent("vault.cardse", isDirectory: false)
    }

    private func migrateLegacyStorageDirectoryIfNeeded() {
        let supportDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let legacyFolder = supportDir.appendingPathComponent("CardVaultStorage", isDirectory: true)
        let legacyFile = legacyFolder.appendingPathComponent("vault.cardvault", isDirectory: false)
        let targetFile = vaultFileURL

        if FileManager.default.fileExists(atPath: legacyFile.path),
           !FileManager.default.fileExists(atPath: targetFile.path) {
            try? FileManager.default.moveItem(at: legacyFile, to: targetFile)
            excludeFromAllBackups(targetFile)
        }
        if FileManager.default.fileExists(atPath: legacyFolder.path),
           !FileManager.default.fileExists(atPath: legacyFile.path) {
            try? FileManager.default.removeItem(at: legacyFolder)
        }
    }

    private func excludeFromAllBackups(_ url: URL) {
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        var mutableURL = url
        try? mutableURL.setResourceValues(resourceValues)
    }

    var biometricKind: BiometricKind {
        KeychainBiometrics.availableBiometricKind()
    }

    var isBiometricSuspendedBySecurityPolicy: Bool {
        lockout.isBiometricSuspended || runtimeIntegrity.isCompromised
    }

    var isLockdownModeActive: Bool {
        lockout.isLockdownActive
    }

    var canUseBiometricUnlock: Bool {
        biometricsEnabled
            && biometricKind != .none
            && !isBiometricSuspendedBySecurityPolicy
            && KeychainBiometrics.hasStoredBiometricKey()
    }

    var hardwareProtectionDescription: String {
        hardwareKeys.currentProtectionTier?.displayTitle ?? "创建保险库时自动绑定 Secure Enclave"
    }

    var kdfIterations: Int {
        currentEnvelope?.kdfIterations ?? 0
    }

    var failedAttemptCount: Int {
        lockout.failures
    }

    var sortedCards: [BankCard] {
        cards.sorted { lhs, rhs in
            if lhs.isFavorite != rhs.isFavorite {
                return lhs.isFavorite && !rhs.isFavorite
            }
            return lhs.updatedAt > rhs.updatedAt
        }
    }

    func loadVaultStateFromDisk() {
        let url = vaultFileURL
        let fileExists = FileManager.default.fileExists(atPath: url.path)

        guard fileExists else {
            // Distinguish genuine first install from unexpected disappearance of an existing vault!
            let identity = VaultIdentityStore.readResult()
            if identity.isUnavailable {
                // Device is still locked and Keychain cannot be queried yet — stay safely on `.locked`!
                phase = .locked
                needsReloadWhenProtectedDataAvailable = true
                wipeSensitiveMemory()
                return
            }
            if let existingRecord = identity.record {
                securityNotice = "安全警告：系统钥匙串中存在第 \(existingRecord.generation) 版卡包记录，但本地加密文件已不存在。若非您本人卸载重装，请注意设备安全，并仅从可信备份恢复。"
            }
            phase = .onboarding
            currentEnvelope = nil
            needsReloadWhenProtectedDataAvailable = false
            wipeSensitiveMemory()
            return
        }

        // File exists on disk: NEVER enter `.onboarding` if NSFileProtectionComplete blocks reading while locked!
        guard let data = try? Data(contentsOf: url) else {
            phase = .locked
            currentEnvelope = nil
            needsReloadWhenProtectedDataAvailable = true
            wipeSensitiveMemory()
            return
        }

        needsReloadWhenProtectedDataAvailable = false
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        if let envelope = try? decoder.decode(VaultEnvelope.self, from: data) {
            currentEnvelope = envelope
            if phase != .unlocked {
                phase = .locked
            }
        } else {
            currentEnvelope = nil
            phase = .locked
            errorMessage = "检测到本地加密库文件损坏或格式异常"
        }
    }

    // MARK: - Onboarding & Unlock

    func setupNewVault(
        masterPassword: String,
        enableBiometrics: Bool,
        initialCards: [BankCard] = []
    ) async -> Bool {
        if rejectIfDebuggerAttached() { return false }
        guard !isBusy else { return false }
        errorMessage = nil
        if let message = PasswordPolicy.validationMessage(masterPassword, for: .master) {
            errorMessage = message
            return false
        }

        isBusy = true
        defer { isBusy = false }

        return await performSetupNewVault(
            masterPassword: masterPassword,
            enableBiometrics: enableBiometrics,
            initialCards: initialCards
        )
    }

    private func performSetupNewVault(
        masterPassword: String,
        enableBiometrics: Bool,
        initialCards: [BankCard]
    ) async -> Bool {
        // Hard overwrite guard: NEVER rotate Secure Enclave keys or overwrite an existing vault file on disk.
        if FileManager.default.fileExists(atPath: vaultFileURL.path) {
            errorMessage = "检测到本机已存在加密卡包文件，已拒绝覆盖初始化。请先解锁现有卡包。"
            loadVaultStateFromDisk()
            return false
        }

        let keys = hardwareKeys
        let vaultID = UUID()

        do {
            let result = try await Task.detached(priority: .userInitiated) {
                try VaultCrypto.createNewLocalVault(
                    masterPassword: masterPassword,
                    initialCards: initialCards,
                    vaultID: vaultID,
                    generation: 1,
                    iterations: VaultCrypto.calibratedIterations(),
                    hardwareKeys: keys,
                    rotateHardwareKey: true,
                    deferKeyCommit: true
                )
            }.value

            guard VaultIdentityStore.write(
                VaultIdentityRecord(vaultID: vaultID, generation: 1, envelopeVersion: VaultEnvelope.currentVersion)
            ) else {
                throw VaultCryptoError.hardwareKeyUnavailable("无法向本机钥匙串写入防回滚身份标识，请确认设备处于解锁状态")
            }

            try persistEnvelope(result.envelope)
            keys.commitRotatedKey()
            currentEnvelope = result.envelope
            lockout.reset()

            if enableBiometrics && biometricKind != .none && !runtimeIntegrity.isCompromised {
                do {
                    try KeychainBiometrics.saveBiometricDEK(result.key)
                    biometricsEnabled = true
                } catch {
                    biometricsEnabled = false
                }
            } else {
                KeychainBiometrics.deleteBiometricDEK()
                biometricsEnabled = false
            }

            activateSession(
                payload: VaultPlaintextPayload(vaultID: vaultID, generation: 1, cards: initialCards),
                envelope: result.envelope,
                key: result.key,
                priorFailedAttempts: 0
            )
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            return true
        } catch {
            keys.discardPendingKey()
            errorMessage = error.localizedDescription
            return false
        }
    }

    func unlockWithMasterPassword(_ password: String) async -> Bool {
        if rejectIfDebuggerAttached() { return false }
        guard !isBusy else { return false }

        let remaining = lockout.remainingSeconds()
        if remaining > 0 {
            errorMessage = Self.lockoutMessage(remaining)
            return false
        }

        if currentEnvelope == nil {
            loadVaultStateFromDisk()
        }
        guard let envelope = currentEnvelope else {
            errorMessage = needsReloadWhenProtectedDataAvailable
                ? "设备数据保护尚未就绪，请先解锁手机屏幕后再试"
                : "未找到可解锁的本地加密库"
            return false
        }

        errorMessage = nil
        isBusy = true
        defer { isBusy = false }

        let priorFailures = lockout.failures

        // Fail-Closed: persist the incremented attempt counter to Keychain BEFORE running PBKDF2!
        guard lockout.beginAttempt() else {
            errorMessage = "安全计数器无法写入系统钥匙串，已中止密码验证（请确认手机已解锁）"
            return false
        }

        // Prevent v2 -> v1 downgrade: if Keychain already recorded a v2 vault, reject v1 envelopes!
        let existingIdentity = VaultIdentityStore.read()
        let allowLegacyV1 = (existingIdentity?.envelopeVersion ?? 1) < VaultEnvelope.currentVersion
        let keys = hardwareKeys

        do {
            let unlocked = try await Task.detached(priority: .userInitiated) {
                try VaultCrypto.unlockLocalVaultWithPassword(
                    envelope: envelope,
                    masterPassword: password,
                    hardwareKeys: keys,
                    allowLegacyV1: allowLegacyV1
                )
            }.value

            lockout.reset()

            var finalEnvelope = envelope
            var finalKey = unlocked.key
            var finalPayload = unlocked.payload

            // Upgrade legacy v1 or sub-threshold KDF vaults to v2 + Secure Enclave + fresh DEK!
            if unlocked.needsUpgradeToV2 {
                let upgradedVaultID = envelope.vaultID ?? UUID()
                let nextGen = max(unlocked.payload.generation, 1)
                let shouldRotateHW = envelope.version < VaultEnvelope.currentVersion
                do {
                    let upgraded = try await Task.detached(priority: .userInitiated) {
                        try VaultCrypto.createNewLocalVault(
                            masterPassword: password,
                            initialCards: unlocked.payload.cards,
                            vaultID: upgradedVaultID,
                            generation: nextGen,
                            iterations: VaultCrypto.calibratedIterations(),
                            hardwareKeys: keys,
                            rotateHardwareKey: shouldRotateHW,
                            deferKeyCommit: true
                        )
                    }.value
                    try persistEnvelope(upgraded.envelope)
                    if shouldRotateHW {
                        keys.commitRotatedKey()
                    }
                    finalEnvelope = upgraded.envelope
                    finalKey = upgraded.key
                    finalPayload = VaultPlaintextPayload(
                        vaultID: upgradedVaultID,
                        generation: nextGen,
                        cards: unlocked.payload.cards
                    )
                    currentEnvelope = finalEnvelope
                } catch {
                    keys.discardPendingKey()
                }
            }

            if biometricsEnabled && biometricKind != .none && !runtimeIntegrity.isCompromised {
                try? KeychainBiometrics.saveBiometricDEK(finalKey)
            }

            activateSession(
                payload: finalPayload,
                envelope: finalEnvelope,
                key: finalKey,
                priorFailedAttempts: priorFailures
            )
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            return true
        } catch {
            let failures = lockout.failures
            UINotificationFeedbackGenerator().notificationOccurred(.error)

            if failures >= LockoutPolicy.biometricSuspensionThreshold {
                // Suspend biometric shortcut until a valid master password is entered.
                KeychainBiometrics.deleteBiometricDEK()
            }

            if wipeAfterFailedAttempts && failures >= LockoutPolicy.wipeThreshold {
                destroyVaultCompletely()
                errorMessage = "主密码已连续输错 \(failures) 次，已按设置触发硬件密钥销毁并擦除本机卡包。"
                return false
            }

            var message = error.localizedDescription
            let wait = lockout.remainingSeconds()
            if wait > 0 {
                message += "\n" + Self.lockoutMessage(wait)
            } else if failures >= 3 {
                message += "\n已连续输错 \(failures) 次，第 \(LockoutPolicy.biometricSuspensionThreshold) 次起将禁用生物识别并递增锁定时间"
            }
            if wipeAfterFailedAttempts && failures >= LockoutPolicy.wipeThreshold - 5 {
                message += "\n⚠️ 再错 \(LockoutPolicy.wipeThreshold - failures) 次将永久销毁本机安全密钥与卡包"
            }
            errorMessage = message
            return false
        }
    }

    func unlockWithBiometrics() async -> Bool {
        if rejectIfDebuggerAttached() { return false }
        guard !isBusy else { return false }
        guard !isBiometricSuspendedBySecurityPolicy else {
            errorMessage = "当前安全策略要求输入主密码解锁"
            return false
        }

        if currentEnvelope == nil {
            loadVaultStateFromDisk()
        }
        guard canUseBiometricUnlock, let envelope = currentEnvelope else {
            return false
        }

        // Prevent v2 -> v1 downgrade on biometric path too.
        if let recorded = VaultIdentityStore.read(),
           recorded.envelopeVersion >= VaultEnvelope.currentVersion,
           envelope.magic != VaultEnvelope.localMagicV2 {
            errorMessage = "检测到本地加密库版本异常降级，已阻止快捷解锁，请核查安全状态"
            return false
        }

        errorMessage = nil
        isBusy = true
        defer { isBusy = false }

        let priorFailures = lockout.failures

        do {
            let key = try await KeychainBiometrics.loadBiometricDEK()
            let payload = try await Task.detached(priority: .userInitiated) {
                try VaultCrypto.decryptPayload(envelope: envelope, key: key, expectedDomain: .localVault)
            }.value

            lockout.reset()
            activateSession(
                payload: payload,
                envelope: envelope,
                key: key,
                priorFailedAttempts: priorFailures
            )
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            return true
        } catch let bioError as KeychainBiometricError {
            if let message = bioError.errorDescription {
                errorMessage = message
            }
            return false
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    /// 1-Tap Emergency Lockdown ("紧急锁定"): purges biometric DEK from Keychain and requires Master Password next time.
    func enterEmergencyLockdown() {
        cancelBackgroundLock()
        clipboard.clearIfOwned()
        KeychainBiometrics.deleteBiometricDEK()
        lockout.setLockdownActive(true)
        wipeSensitiveMemory()
        phase = .locked
        errorMessage = "已进入紧急锁定模式：生物识别已临时移除，下次必须输入主密码才能解锁"
        UINotificationFeedbackGenerator().notificationOccurred(.warning)
    }

    func lock(reason: LockReason = .manual) {
        cancelBackgroundLock()
        if reason != .background {
            // Unconditionally clear clipboard on manual, idle, deviceLocked, emergencyLockdown, or anomaly!
            clipboard.clearIfOwned()
        }
        guard phase == .unlocked else { return }

        wipeSensitiveMemory()
        phase = .locked
        errorMessage = nil
    }

    private func activateSession(
        payload: VaultPlaintextPayload,
        envelope: VaultEnvelope,
        key: SymmetricKey,
        priorFailedAttempts: Int
    ) {
        activeKey = key
        cards = payload.cards
        currentGeneration = payload.generation

        var notices: [String] = []

        if runtimeIntegrity.isCompromised {
            notices.append("运行时完整性告警：\(runtimeIntegrity.summaryText)。请勿在被注入插件或越狱的环境中保存银行卡！")
        }

        if priorFailedAttempts > 0 {
            notices.append("在本次解锁前曾发生 \(priorFailedAttempts) 次主密码验证失败。如非您本人误输，请警惕他人曾接触您的手机。")
        }

        // Anti-replacement & anti-rollback verification against Keychain VaultIdentityStore.
        if let recorded = VaultIdentityStore.read() {
            if let expectedID = recorded.vaultID, let actualID = envelope.vaultID, expectedID != actualID {
                notices.append("严重警告：本地加密文件的唯一标识（Vault ID）与本机钥匙串记录不符，文件可能曾被整体替换！")
            } else if payload.generation < recorded.generation {
                notices.append("严重警告：本地加密文件版本（第 \(payload.generation) 版）旧于本机钥匙串记录（第 \(recorded.generation) 版），疑似遭遇文件回滚攻击！")
            } else {
                VaultIdentityStore.write(
                    VaultIdentityRecord(
                        vaultID: envelope.vaultID ?? recorded.vaultID,
                        generation: payload.generation,
                        envelopeVersion: envelope.version
                    )
                )
            }
        } else {
            VaultIdentityStore.write(
                VaultIdentityRecord(
                    vaultID: envelope.vaultID,
                    generation: payload.generation,
                    envelopeVersion: envelope.version
                )
            )
        }

        if !notices.isEmpty {
            securityNotice = notices.joined(separator: "\n\n")
        }

        lastActivityAt = Date()
        phase = .unlocked
    }

    private static func lockoutMessage(_ seconds: Int) -> String {
        if seconds >= 60 {
            return "密码错误次数过多，面容/触控 ID 已挂起，请在 \(Int(ceil(Double(seconds) / 60))) 分钟后用主密码重试"
        }
        return "密码错误次数过多，面容/触控 ID 已挂起，请在 \(seconds) 秒后用主密码重试"
    }

    // MARK: - Card CRUD

    func addCard(_ card: BankCard) throws {
        var updated = cards
        updated.append(card)
        try saveCards(updated)
    }

    func updateCard(_ card: BankCard) throws {
        var updated = cards
        guard let idx = updated.firstIndex(where: { $0.id == card.id }) else { return }
        var modified = card
        modified.updatedAt = Date()
        updated[idx] = modified
        try saveCards(updated)
    }

    func toggleFavorite(for cardID: UUID) throws {
        var updated = cards
        guard let idx = updated.firstIndex(where: { $0.id == cardID }) else { return }
        updated[idx].isFavorite.toggle()
        updated[idx].updatedAt = Date()
        try saveCards(updated)
    }

    func deleteCard(id: UUID) throws {
        let updated = cards.filter { $0.id != id }
        try saveCards(updated)
    }

    private func saveCards(_ updatedCards: [BankCard]) throws {
        guard phase == .unlocked,
              let envelope = currentEnvelope,
              let key = activeKey else {
            throw VaultCryptoError.authenticationFailed
        }

        let nextGeneration = currentGeneration + 1
        let newEnvelope = try VaultCrypto.resealLocalPayload(
            existingEnvelope: envelope,
            key: key,
            cards: updatedCards,
            generation: nextGeneration
        )
        // Crash-safe order: write encrypted file atomically first, then advance Keychain counter.
        try persistEnvelope(newEnvelope)
        currentEnvelope = newEnvelope
        currentGeneration = nextGeneration
        VaultIdentityStore.write(
            VaultIdentityRecord(
                vaultID: newEnvelope.vaultID,
                generation: nextGeneration,
                envelopeVersion: newEnvelope.version
            )
        )
        cards = updatedCards
        noteActivity()
    }

    // MARK: - Biometric & Password Settings

    func setBiometricUnlock(enabled: Bool) -> Bool {
        if enabled {
            guard !runtimeIntegrity.isCompromised else {
                errorMessage = "当前运行环境存在注入或调试风险，已禁止启用生物识别解锁"
                biometricsEnabled = false
                return false
            }
            guard biometricKind != .none else {
                errorMessage = "当前设备未开启或不支持面容/触控 ID"
                biometricsEnabled = false
                return false
            }
            guard let key = activeKey else {
                errorMessage = "请先解锁卡包后再开启生物识别"
                biometricsEnabled = false
                return false
            }
            do {
                try KeychainBiometrics.saveBiometricDEK(key)
                lockout.setLockdownActive(false)
                biometricsEnabled = true
                return true
            } catch {
                errorMessage = error.localizedDescription
                biometricsEnabled = false
                return false
            }
        } else {
            KeychainBiometrics.deleteBiometricDEK()
            biometricsEnabled = false
            return true
        }
    }

    func changeMasterPassword(currentPassword: String, newPassword: String) async -> Bool {
        if rejectIfDebuggerAttached() { return false }
        guard !isBusy else { return false }
        errorMessage = nil
        if let message = PasswordPolicy.validationMessage(newPassword, for: .master) {
            errorMessage = message
            return false
        }
        guard let envelope = currentEnvelope else { return false }

        isBusy = true
        defer { isBusy = false }

        let snapshotCards = cards
        let nextGeneration = currentGeneration + 1
        let vaultID = envelope.vaultID ?? UUID()
        let keys = hardwareKeys

        do {
            let rotated = try await Task.detached(priority: .userInitiated) {
                guard VaultCrypto.verifyLocalPassword(currentPassword, against: envelope, hardwareKeys: keys) else {
                    throw VaultCryptoError.authenticationFailed
                }
                // Rotate salt, Secure Enclave hardware key, DEK, and KEK simultaneously (2-phase crash-safe commit).
                return try VaultCrypto.createNewLocalVault(
                    masterPassword: newPassword,
                    initialCards: snapshotCards,
                    vaultID: vaultID,
                    generation: nextGeneration,
                    iterations: VaultCrypto.calibratedIterations(),
                    hardwareKeys: keys,
                    rotateHardwareKey: true,
                    deferKeyCommit: true
                )
            }.value

            try persistEnvelope(rotated.envelope)
            keys.commitRotatedKey()
            currentEnvelope = rotated.envelope
            activeKey = rotated.key
            currentGeneration = nextGeneration
            VaultIdentityStore.write(
                VaultIdentityRecord(
                    vaultID: vaultID,
                    generation: nextGeneration,
                    envelopeVersion: rotated.envelope.version
                )
            )

            if biometricsEnabled && biometricKind != .none && !runtimeIntegrity.isCompromised {
                do {
                    try KeychainBiometrics.saveBiometricDEK(rotated.key)
                } catch {
                    biometricsEnabled = false
                    securityNotice = "主密码已更新，但重新绑定生物识别密钥失败，已自动关闭快捷解锁，您可在安全设置中重新开启。"
                }
            }
            return true
        } catch {
            keys.discardPendingKey()
            errorMessage = error.localizedDescription
            return false
        }
    }

    // MARK: - Encrypted Offline Backup Export / Import

    func createEncryptedBackupData(password: String) async throws -> Data {
        if rejectIfDebuggerAttached() {
            throw VaultCryptoError.authenticationFailed
        }
        guard !isBusy else {
            throw VaultCryptoError.authenticationFailed
        }
        if let message = PasswordPolicy.validationMessage(password, for: .backup) {
            throw VaultCryptoError.weakPassword(message)
        }
        guard phase == .unlocked, let envelope = currentEnvelope else {
            throw VaultCryptoError.authenticationFailed
        }

        isBusy = true
        defer { isBusy = false }

        let snapshotCards = cards
        let keys = hardwareKeys
        return try await Task.detached(priority: .userInitiated) {
            if VaultCrypto.verifyLocalPassword(password, against: envelope, hardwareKeys: keys) {
                throw VaultCryptoError.weakPassword("备份密码不能与本机主密码相同：备份文件一旦外泄被破解，本机主密码也会随之暴露。")
            }
            return try VaultCrypto.exportEncryptedBackup(
                cards: snapshotCards,
                backupPassword: password,
                iterations: VaultCrypto.calibratedIterations()
            )
        }.value
    }

    func importEncryptedBackup(
        data: Data,
        backupPassword: String,
        mode: BackupImportMode
    ) async throws -> Int {
        if rejectIfDebuggerAttached() {
            throw VaultCryptoError.authenticationFailed
        }
        guard !isBusy, phase == .unlocked else {
            throw VaultCryptoError.authenticationFailed
        }
        isBusy = true
        defer { isBusy = false }

        let importedCards = try await Task.detached(priority: .userInitiated) {
            try VaultCrypto.importEncryptedBackup(data: data, backupPassword: backupPassword)
        }.value

        switch mode {
        case .replace:
            try saveCards(importedCards)
            return importedCards.count
        case .merge:
            var merged = cards
            let existingNumbers = Set(merged.map(\.digitsOnly))
            var addedCount = 0
            for var card in importedCards where !existingNumbers.contains(card.digitsOnly) {
                if merged.contains(where: { $0.id == card.id }) {
                    card.id = UUID()
                }
                merged.append(card)
                addedCount += 1
            }
            try saveCards(merged)
            return addedCount
        }
    }

    func restoreOnboardingFromBackup(
        data: Data,
        backupPassword: String,
        newMasterPassword: String,
        enableBiometrics: Bool
    ) async -> Bool {
        if rejectIfDebuggerAttached() { return false }
        guard !isBusy else { return false }
        errorMessage = nil

        if VaultCrypto.normalizePassword(backupPassword) == VaultCrypto.normalizePassword(newMasterPassword) {
            errorMessage = "新主密码不能与备份文件的密码相同，请设置一个独立的主密码"
            return false
        }
        if let message = PasswordPolicy.validationMessage(newMasterPassword, for: .master) {
            errorMessage = message
            return false
        }

        isBusy = true
        defer { isBusy = false }

        let restoredCards: [BankCard]
        do {
            restoredCards = try await Task.detached(priority: .userInitiated) {
                try VaultCrypto.importEncryptedBackup(data: data, backupPassword: backupPassword)
            }.value
        } catch {
            errorMessage = error.localizedDescription
            return false
        }

        return await performSetupNewVault(
            masterPassword: newMasterPassword,
            enableBiometrics: enableBiometrics,
            initialCards: restoredCards
        )
    }

    /// Inspects a user-picked/exported URL and warns immediately if it resides inside iCloud Drive / Ubiquity sync!
    func warnIfCloudSyncedURL(_ url: URL) {
        let values = try? url.resourceValues(forKeys: [.isUbiquitousItemKey])
        let pathLower = url.path.lowercased()
        if values?.isUbiquitousItem == true || pathLower.contains("mobile documents") || pathLower.contains("icloud") {
            securityNotice = "离线安全提醒：您刚刚选择的路径位于 iCloud 云同步目录中，系统可能会在后台将其同步到云端服务器。为确保零云端同步，强烈建议将备份移至「我的 iPhone」本地目录或离线硬件 U 盘，并彻底删除云端副本。"
        }
    }

    /// Cryptographically shreds the Secure Enclave hardware key, biometric key, counters, preferences, and ciphertext file.
    func destroyVaultCompletely() {
        cancelBackgroundLock()
        clipboard.clearIfOwned()
        hardwareKeys.destroyKey() // Hardware-level Crypto-Shredding!
        KeychainBiometrics.deleteBiometricDEK()
        VaultIdentityStore.clear()
        VaultPreferencesStore.clear()
        lockout.reset()

        let url = vaultFileURL
        if let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size]) as? Int, size > 0 {
            // Best-effort zero overwrite before unlink (primary guarantee on CoW APFS is Secure Enclave key destruction above).
            let zeroes = Data(count: min(size, 1024 * 1024))
            try? zeroes.write(to: url, options: [.completeFileProtection])
        }
        try? FileManager.default.removeItem(at: url)
        try? FileManager.default.removeItem(at: storageDirectoryURL)

        wipeSensitiveMemory()
        currentEnvelope = nil
        biometricsEnabled = false
        phase = .onboarding
    }

    // MARK: - Copy Helpers

    func copySecure(_ value: String, label: String) {
        clipboard.copy(value, label: label, ttlSeconds: clipboardClearDuration.rawValue)
        noteActivity()
    }

    // MARK: - App Lifecycle, Idle Lock, Debugger Watchdog & Privacy

    func handleWillResignActive() {
        isAppInactive = true
    }

    func handleDidEnterBackground() {
        isAppInactive = true
        backgroundEnteredAt = Date()
        guard phase == .unlocked else { return }

        if autoLockTimeout == .immediately {
            lock(reason: .background)
        } else {
            scheduleBackgroundLock(after: autoLockTimeout.rawValue)
        }
    }

    func handleDidBecomeActive() {
        bootstrapIfNeeded()
        cancelBackgroundLock()
        refreshScreenCaptureState()
        runtimeIntegrity = RuntimeSecurity.auditEnvironment(
            antiDebugActive: AppDelegate.antiDebugEnabledAtLaunch
        )
        if needsReloadWhenProtectedDataAvailable {
            loadVaultStateFromDisk()
        }
        if let entered = backgroundEnteredAt,
           Date().timeIntervalSince(entered) >= TimeInterval(autoLockTimeout.rawValue) {
            lock(reason: .background)
        }
        backgroundEnteredAt = nil
        isAppInactive = false
        noteActivity()
    }

    /// Device screen locked (data protection keys about to be evicted):
    /// ALWAYS clear the clipboard even if `phase` already transitioned to `.locked` on background entry!
    func handleProtectedDataWillBecomeUnavailable() {
        clipboard.clearIfOwned()
        lock(reason: .deviceLocked)
    }

    func handleProtectedDataDidBecomeAvailable() {
        if needsReloadWhenProtectedDataAvailable {
            loadVaultStateFromDisk()
        }
    }

    func noteActivity() {
        lastActivityAt = Date()
    }

    func periodicSecurityTick() {
        #if !DEBUG
        if RuntimeSecurity.isDebuggerAttached() {
            clipboard.clearIfOwned()
            KeychainBiometrics.deleteBiometricDEK()
            lock(reason: .securityAnomaly)
            securityNotice = "检测到外部调试器附加，已立即销毁内存会话并锁定 CardSe。"
            return
        }
        #endif

        guard phase == .unlocked, !isBusy, !isAppInactive else { return }
        if Date().timeIntervalSince(lastActivityAt) >= TimeInterval(idleLockTimeout.rawValue) {
            lock(reason: .idle)
        }
    }

    func handleScreenshot() {
        screenshotEventCount += 1
        guard phase == .unlocked else { return }
        if SecureCanvasSupport.isAvailable {
            securityNotice = "检测到截屏。卡面、卡号、CVV、有效期与备注区域已由安全图层渲染为空白，明文状态也已立即收起。仍建议前往「照片」删除该截图并清空「最近删除」（防止相册云同步）。"
        } else {
            securityNotice = "检测到截屏，明文已自动隐藏。当前系统版本不支持安全图层遮挡，请立即前往「照片」删除该截图并清空「最近删除」。"
        }
    }

    func refreshScreenCaptureState() {
        isScreenCaptured = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .contains { $0.screen.isCaptured }
    }

    private func scheduleBackgroundLock(after seconds: Int) {
        cancelBackgroundLock()
        backgroundTaskID = UIApplication.shared.beginBackgroundTask(withName: "CardSeAutoLock") { [weak self] in
            if Thread.isMainThread {
                MainActor.assumeIsolated {
                    self?.lock(reason: .background)
                }
            } else {
                DispatchQueue.main.async { [weak self] in
                    self?.lock(reason: .background)
                }
            }
        }
        backgroundLockTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(seconds))
            guard !Task.isCancelled else { return }
            self?.lock(reason: .background)
        }
    }

    private func cancelBackgroundLock() {
        backgroundLockTask?.cancel()
        backgroundLockTask = nil
        if backgroundTaskID != .invalid {
            UIApplication.shared.endBackgroundTask(backgroundTaskID)
            backgroundTaskID = .invalid
        }
    }

    private func persistEnvelope(_ envelope: VaultEnvelope) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(envelope)

        let url = vaultFileURL
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        excludeFromAllBackups(url)
    }

    /// Releases decrypted state. `SymmetricKey` zeroes its storage on deallocation.
    private func wipeSensitiveMemory() {
        cards = []
        activeKey = nil
        currentGeneration = 0
    }
}
