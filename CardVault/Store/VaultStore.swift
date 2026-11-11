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
    private let stateBackend: any KeychainStateBackend
    private lazy var lockout = LockoutGuard(backend: stateBackend)
    private let hardwareKeys: any HardwareKeyProvider
    private let customVaultFileURL: URL?
    private var periodicTickCounter: UInt64 = 0

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
    /// Incremented on every lock / background / device-lock / wipe. Async unlock, rotation, export and import
    /// operations capture it before their first `await` and abort if it changed, so an operation that finishes
    /// after the user locked the phone can never re-populate plaintext or keys into memory.
    private var sessionEpoch: UInt64 = 0
    static let maximumImportedCardCount = 1000

    private func bumpSessionEpoch() {
        sessionEpoch &+= 1
    }

    private func isSessionStillValid(since epoch: UInt64) -> Bool {
        sessionEpoch == epoch
            && UIApplication.shared.applicationState != .background
            && UIApplication.shared.isProtectedDataAvailable
    }

    init(
        hardwareKeys: any HardwareKeyProvider = DeviceHardwareKeyManager(),
        stateBackend: any KeychainStateBackend = SystemKeychainBackend(),
        customVaultFileURL: URL? = nil
    ) {
        self.hardwareKeys = hardwareKeys
        self.stateBackend = stateBackend
        self.customVaultFileURL = customVaultFileURL
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

    private static func nextSafeGeneration(current: UInt64, recorded: UInt64) throws -> UInt64 {
        let highWater = max(current, recorded)
        guard highWater < VaultPlaintextPayload.maximumValidGeneration else {
            throw VaultCryptoError.corruptedPayload
        }
        return highWater + 1
    }

    private func resignActiveInputFocus() {
        UIApplication.shared.sendAction(
            #selector(UIResponder.resignFirstResponder),
            to: nil,
            from: nil,
            for: nil
        )
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
        let prefs = VaultPreferencesStore.load(using: stateBackend)
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
        refreshStorageDirectoryProtection()
        refreshScreenCaptureState()
        loadVaultStateFromDisk()
    }

    private var verifiedAncestorDirectories: [URL] {
        guard customVaultFileURL == nil else { return [] }
        let libraryDir = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)[0]
        let supportDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return [libraryDir, supportDir]
    }

    private func refreshStorageDirectoryProtection() {
        try? SafeVaultFileIO.ensureSafeDirectory(
            at: storageDirectoryURL,
            ancestorDirectoriesToVerify: verifiedAncestorDirectories
        )
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
        VaultPreferencesStore.save(prefs, using: stateBackend)
    }

    var storageDirectoryURL: URL {
        if let customVaultFileURL {
            return customVaultFileURL.deletingLastPathComponent()
        }
        let supportDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return supportDir.appendingPathComponent("CardSeStorage", isDirectory: true)
    }

    var vaultFileURL: URL {
        if let customVaultFileURL {
            return customVaultFileURL
        }
        return storageDirectoryURL.appendingPathComponent("vault.cardse", isDirectory: false)
    }

    private func migrateLegacyStorageDirectoryIfNeeded() {
        guard customVaultFileURL == nil else { return }
        let supportDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let legacyFolder = supportDir.appendingPathComponent("CardVaultStorage", isDirectory: true)
        SafeVaultFileIO.migrateLegacyVaultIfPresent(
            legacyFolderURL: legacyFolder,
            legacyFileName: "vault.cardvault",
            targetFileURL: vaultFileURL,
            ancestorDirectoriesToVerify: verifiedAncestorDirectories
        )
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
        let data: Data
        switch SafeVaultFileIO.readLocalVaultFile(
            at: vaultFileURL,
            ancestorDirectoriesToVerify: verifiedAncestorDirectories
        ) {
        case .notFound:
            // Distinguish genuine first install from unexpected disappearance of an existing vault!
            let identityState = VaultIdentityStore.readState(using: stateBackend)
            switch identityState {
            case .unavailable, .corrupted:
                // Device is still locked or Keychain state is unreadable — stay safely on `.locked`!
                phase = .locked
                needsReloadWhenProtectedDataAvailable = true
                wipeSensitiveMemory()
                return
            case .found(let existingRecord):
                securityNotice = "安全警告：系统钥匙串中存在第 \(existingRecord.generation) 版卡包记录，但本地加密文件已不存在。若非您本人卸载重装，请注意设备安全，并仅从可信备份恢复。"
            case .notFound:
                break
            }
            phase = .onboarding
            currentEnvelope = nil
            needsReloadWhenProtectedDataAvailable = false
            wipeSensitiveMemory()
            return

        case .protectedDataUnavailable:
            // File exists on disk: NEVER enter `.onboarding` if NSFileProtectionComplete blocks reading while locked!
            phase = .locked
            currentEnvelope = nil
            needsReloadWhenProtectedDataAvailable = true
            wipeSensitiveMemory()
            return

        case .tampered(let reason):
            currentEnvelope = nil
            needsReloadWhenProtectedDataAvailable = false
            phase = .locked
            errorMessage = reason
            securityNotice = reason
            wipeSensitiveMemory()
            return

        case .data(let loaded):
            data = loaded
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
            initialCards: initialCards,
            startedEpoch: sessionEpoch
        )
    }

    private func performSetupNewVault(
        masterPassword: String,
        enableBiometrics: Bool,
        initialCards: [BankCard],
        startedEpoch: UInt64
    ) async -> Bool {
        // Hard overwrite & non-symlink guard: NEVER rotate Secure Enclave keys or write through a planted symlink!
        switch SafeVaultFileIO.inspectExistingVaultNode(
            at: vaultFileURL,
            ancestorDirectoriesToVerify: verifiedAncestorDirectories
        ) {
        case .absent:
            break
        case .regularFileExists:
            errorMessage = "检测到本机已存在加密卡包文件，已拒绝覆盖初始化。请先解锁现有卡包。"
            loadVaultStateFromDisk()
            return false
        case .protectedDataUnavailable:
            errorMessage = "本机受保护存储暂不可访问，请确认设备处于解锁状态后再试。"
            loadVaultStateFromDisk()
            return false
        case .tampered(let reason):
            errorMessage = reason
            securityNotice = reason
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
                VaultIdentityRecord(vaultID: vaultID, generation: 1, envelopeVersion: VaultEnvelope.currentVersion),
                using: stateBackend
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

            guard activateSession(
                payload: VaultPlaintextPayload(vaultID: vaultID, generation: 1, cards: initialCards),
                envelope: result.envelope,
                key: result.key,
                priorFailedAttempts: 0,
                startedEpoch: startedEpoch
            ) else {
                return false
            }
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

        // Pre-validate empty / oversized inputs BEFORE incrementing the persistent failure counter so
        // accidental blank submits or paste-bombs never advance toward the 15-attempt self-destruct threshold.
        guard password.utf8.count <= VaultCrypto.maximumPasswordUTF8Bytes * 4 else {
            errorMessage = VaultCryptoError.passwordTooLong(maximum: VaultCrypto.maximumPasswordLength).localizedDescription
            return false
        }
        let normalizedInput = VaultCrypto.normalizePassword(password)
        guard !normalizedInput.isEmpty else {
            errorMessage = VaultCryptoError.emptyPassword.localizedDescription
            return false
        }
        guard normalizedInput.count <= VaultCrypto.maximumPasswordLength,
              normalizedInput.utf8.count <= VaultCrypto.maximumPasswordUTF8Bytes else {
            errorMessage = VaultCryptoError.passwordTooLong(maximum: VaultCrypto.maximumPasswordLength).localizedDescription
            return false
        }

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

        // Fail-Closed on Keychain identity availability & prevent v2 -> v1 downgrade!
        let identityState = VaultIdentityStore.readState(using: stateBackend)
        let allowLegacyV1: Bool
        var recordedGeneration: UInt64 = 0
        switch identityState {
        case .unavailable:
            errorMessage = "系统钥匙串防回滚状态暂不可读，请先解锁手机屏幕后再试"
            return false
        case .corrupted:
            allowLegacyV1 = false
        case .found(let existingIdentity):
            allowLegacyV1 = existingIdentity.envelopeVersion < VaultEnvelope.currentVersion
            recordedGeneration = existingIdentity.generation
        case .notFound:
            allowLegacyV1 = true
        }

        let priorRecord = lockout.record
        let priorFailures = priorRecord.failures
        let startedEpoch = sessionEpoch

        // Fail-Closed: persist the incremented attempt counter to Keychain BEFORE running PBKDF2!
        guard lockout.beginAttempt() else {
            errorMessage = "安全计数器无法写入系统钥匙串，已中止密码验证（请确认手机已解锁）"
            return false
        }

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
                let shouldRotateHW = envelope.version < VaultEnvelope.currentVersion
                do {
                    // Always advance past the recorded watermark so the weaker pre-upgrade file can never be replayed.
                    let nextGen = try Self.nextSafeGeneration(
                        current: unlocked.payload.generation,
                        recorded: recordedGeneration
                    )
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

            guard activateSession(
                payload: finalPayload,
                envelope: finalEnvelope,
                key: finalKey,
                priorFailedAttempts: priorFailures,
                startedEpoch: startedEpoch
            ) else {
                return false
            }
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            return true
        } catch {
            UINotificationFeedbackGenerator().notificationOccurred(.error)

            let isGenuineAuthMismatch = (error as? VaultCryptoError) == .authenticationFailed
            if !isGenuineAuthMismatch {
                // Environmental / hardware / format fault (e.g. transient SEP unavailability while screen locked):
                // roll back the pre-KDF increment and NEVER trigger permanent 15-attempt crypto-shredding!
                lockout.rollbackNonAuthenticationFault(restoring: priorRecord)
                errorMessage = error.localizedDescription
                return false
            }

            let failures = lockout.failures
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

        // Fail-Closed anti-downgrade & anti-rollback verification on biometric quick unlock!
        let recordedIdentity: VaultIdentityRecord
        switch VaultIdentityStore.readState(using: stateBackend) {
        case .unavailable, .corrupted:
            errorMessage = "系统钥匙串防回滚状态异常，已暂停快捷解锁，请输入主密码验证"
            return false
        case .notFound:
            KeychainBiometrics.deleteBiometricDEK()
            errorMessage = "未找到本机防回滚身份记录，已暂停快捷解锁，请输入主密码核验"
            return false
        case .found(let record):
            if record.envelopeVersion >= VaultEnvelope.currentVersion,
               envelope.magic != VaultEnvelope.localMagicV2 {
                KeychainBiometrics.deleteBiometricDEK()
                errorMessage = "检测到本地加密库版本异常降级，已阻止快捷解锁，请使用主密码核查安全状态"
                return false
            }
            if let expectedID = record.vaultID, expectedID != envelope.vaultID {
                KeychainBiometrics.deleteBiometricDEK()
                errorMessage = "严重警告：检测到本地加密库文件标识异常替换，已禁用快捷解锁，请使用主密码核验"
                return false
            }
            recordedIdentity = record
        }

        errorMessage = nil
        isBusy = true
        defer { isBusy = false }

        let priorFailures = lockout.failures
        let startedEpoch = sessionEpoch

        do {
            let key = try await KeychainBiometrics.loadBiometricDEK()
            let payload = try await Task.detached(priority: .userInitiated) {
                try VaultCrypto.decryptPayload(envelope: envelope, key: key, expectedDomain: .localVault)
            }.value

            // Block biometric auto-unlock if ciphertext generation was rolled back!
            if payload.generation < recordedIdentity.generation {
                KeychainBiometrics.deleteBiometricDEK()
                errorMessage = "严重警告：检测到加密文件版本回滚（第 \(payload.generation) 版旧于钥匙串第 \(recordedIdentity.generation) 版），已禁用快捷解锁，请使用主密码核验"
                return false
            }

            lockout.reset()
            guard activateSession(
                payload: payload,
                envelope: envelope,
                key: key,
                priorFailedAttempts: priorFailures,
                startedEpoch: startedEpoch
            ) else {
                return false
            }
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
        bumpSessionEpoch()
        cancelBackgroundLock()
        resignActiveInputFocus()
        clipboard.clearIfOwned()
        KeychainBiometrics.deleteBiometricDEK()
        lockout.setLockdownActive(true)
        wipeSensitiveMemory()
        phase = .locked
        errorMessage = "已进入紧急锁定模式：生物识别已临时移除，下次必须输入主密码才能解锁"
        UINotificationFeedbackGenerator().notificationOccurred(.warning)
    }

    func lock(reason: LockReason = .manual) {
        bumpSessionEpoch()
        cancelBackgroundLock()
        resignActiveInputFocus()
        if reason != .background {
            // Unconditionally clear clipboard on manual, idle, deviceLocked, emergencyLockdown, or anomaly!
            clipboard.clearIfOwned()
        }
        guard phase == .unlocked else { return }

        wipeSensitiveMemory()
        phase = .locked
        errorMessage = nil
    }

    /// Activates a decrypted session ONLY if no lock / background / device-lock event happened while the
    /// caller was awaiting key derivation or Face ID. Returns `false` (and keeps everything wiped) otherwise.
    private func activateSession(
        payload: VaultPlaintextPayload,
        envelope: VaultEnvelope,
        key: SymmetricKey,
        priorFailedAttempts: Int,
        startedEpoch: UInt64
    ) -> Bool {
        guard isSessionStillValid(since: startedEpoch) else {
            wipeSensitiveMemory()
            currentEnvelope = envelope
            phase = .locked
            errorMessage = "验证期间应用进入后台或设备已锁屏，已自动中止本次解锁，请重新验证"
            return false
        }

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
        // Never allow `currentGeneration` or Keychain watermark to regress below recorded high-water mark!
        switch VaultIdentityStore.readState(using: stateBackend) {
        case .found(let recorded):
            currentGeneration = max(payload.generation, recorded.generation)
            if let expectedID = recorded.vaultID, let actualID = envelope.vaultID, expectedID != actualID {
                notices.append("严重警告：本地加密文件的唯一标识（Vault ID）与本机钥匙串记录不符，文件可能曾被整体替换！")
            } else if payload.generation < recorded.generation {
                notices.append("严重警告：本地加密文件版本（第 \(payload.generation) 版）旧于本机钥匙串记录（第 \(recorded.generation) 版），疑似遭遇文件回滚攻击！")
            } else {
                VaultIdentityStore.advanceWatermark(
                    VaultIdentityRecord(
                        vaultID: envelope.vaultID ?? recorded.vaultID,
                        generation: payload.generation,
                        envelopeVersion: envelope.version
                    ),
                    using: stateBackend
                )
            }
        case .notFound:
            VaultIdentityStore.write(
                VaultIdentityRecord(
                    vaultID: envelope.vaultID,
                    generation: payload.generation,
                    envelopeVersion: envelope.version
                ),
                using: stateBackend
            )
        case .corrupted:
            notices.append("严重警告：系统钥匙串中的防回滚身份记录格式异常，疑似曾遭篡改！")
        case .unavailable:
            notices.append("安全提醒：系统钥匙串防回滚状态在激活瞬间暂不可读。")
        }

        if !notices.isEmpty {
            securityNotice = notices.joined(separator: "\n\n")
        }

        lastActivityAt = Date()
        phase = .unlocked
        return true
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

        let recordedGen: UInt64
        if case .found(let rec) = VaultIdentityStore.readState(using: stateBackend) {
            recordedGen = rec.generation
        } else {
            recordedGen = 0
        }
        let nextGeneration = try Self.nextSafeGeneration(current: currentGeneration, recorded: recordedGen)
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
        if !VaultIdentityStore.advanceWatermark(
            VaultIdentityRecord(
                vaultID: newEnvelope.vaultID,
                generation: nextGeneration,
                envelopeVersion: newEnvelope.version
            ),
            using: stateBackend
        ) {
            securityNotice = "安全提醒：卡片已保存，但防回滚版本水位写入系统钥匙串失败，将在下次保存时自动重试。"
        }
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

    /// Throttled, fail-closed Master Password re-authentication for sensitive unlocked-session operations
    /// (password rotation & Secure-Enclave-stripping offline backup export).
    /// Prevents unthrottled password guessing or Face ID opportunistic vault export.
    private func verifyMasterPasswordReauth(_ candidatePassword: String, against envelope: VaultEnvelope) async -> Bool {
        guard candidatePassword.utf8.count <= VaultCrypto.maximumPasswordUTF8Bytes * 4 else {
            errorMessage = VaultCryptoError.passwordTooLong(maximum: VaultCrypto.maximumPasswordLength).localizedDescription
            return false
        }
        let normalizedInput = VaultCrypto.normalizePassword(candidatePassword)
        guard !normalizedInput.isEmpty else {
            errorMessage = VaultCryptoError.emptyPassword.localizedDescription
            return false
        }
        guard normalizedInput.count <= VaultCrypto.maximumPasswordLength,
              normalizedInput.utf8.count <= VaultCrypto.maximumPasswordUTF8Bytes else {
            errorMessage = VaultCryptoError.passwordTooLong(maximum: VaultCrypto.maximumPasswordLength).localizedDescription
            return false
        }

        let remaining = lockout.remainingSeconds()
        if remaining > 0 {
            let msg = Self.lockoutMessage(remaining)
            lock(reason: .securityAnomaly)
            errorMessage = msg
            return false
        }

        let priorRecord = lockout.record
        guard lockout.beginAttempt() else {
            errorMessage = "安全计数器无法写入系统钥匙串，已中止敏感操作验证"
            return false
        }

        let keys = hardwareKeys
        do {
            try await Task.detached(priority: .userInitiated) {
                try VaultCrypto.verifyLocalPasswordThrowing(candidatePassword, against: envelope, hardwareKeys: keys)
            }.value
            lockout.reset()
            return true
        } catch {
            UINotificationFeedbackGenerator().notificationOccurred(.error)

            let isGenuineAuthMismatch = (error as? VaultCryptoError) == .authenticationFailed
            if !isGenuineAuthMismatch {
                // Transient Secure Enclave / Keychain unavailability must NEVER advance toward permanent vault wipe!
                lockout.rollbackNonAuthenticationFault(restoring: priorRecord)
                errorMessage = error.localizedDescription
                return false
            }

            let failures = lockout.failures
            if failures >= LockoutPolicy.biometricSuspensionThreshold {
                KeychainBiometrics.deleteBiometricDEK()
            }

            if wipeAfterFailedAttempts && failures >= LockoutPolicy.wipeThreshold {
                destroyVaultCompletely()
                errorMessage = "主密码已连续输错 \(failures) 次，已按设置触发硬件密钥销毁并擦除本机卡包。"
                return false
            }

            let wait = lockout.remainingSeconds()
            var message = VaultCryptoError.authenticationFailed.localizedDescription
            if wait > 0 {
                message += "\n" + Self.lockoutMessage(wait)
            } else if failures >= 3 {
                message += "\n已连续输错 \(failures) 次，第 \(LockoutPolicy.biometricSuspensionThreshold) 次起将强制锁定会话并递增冷却时间"
            }

            // Kick opportunistic attacker out of unlocked session once brute-force threshold engages!
            if failures >= LockoutPolicy.biometricSuspensionThreshold || wait > 0 {
                lock(reason: .securityAnomaly)
            }
            errorMessage = message
            return false
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
        guard phase == .unlocked, let envelope = currentEnvelope else { return false }

        isBusy = true
        defer { isBusy = false }

        let startedEpoch = sessionEpoch
        guard await verifyMasterPasswordReauth(currentPassword, against: envelope) else {
            return false
        }
        guard isSessionStillValid(since: startedEpoch), phase == .unlocked else {
            errorMessage = "验证期间会话已锁定，主密码未修改"
            return false
        }

        let snapshotCards = cards
        let recordedGen: UInt64
        if case .found(let rec) = VaultIdentityStore.readState(using: stateBackend) {
            recordedGen = rec.generation
        } else {
            recordedGen = 0
        }
        let nextGeneration: UInt64
        do {
            nextGeneration = try Self.nextSafeGeneration(current: currentGeneration, recorded: recordedGen)
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
        let vaultID = envelope.vaultID ?? UUID()
        let keys = hardwareKeys

        do {
            let rotated = try await Task.detached(priority: .userInitiated) {
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

            // M2: if the session was locked while re-encrypting, discard the staged key and keep the old vault intact
            // (nothing has been written yet), so a fresh DEK is never left resident in memory after a lock.
            guard isSessionStillValid(since: startedEpoch), phase == .unlocked else {
                keys.discardPendingKey()
                errorMessage = "重加密期间会话已锁定，已安全中止，主密码未修改"
                return false
            }

            try persistEnvelope(rotated.envelope)
            keys.commitRotatedKey()
            currentEnvelope = rotated.envelope
            activeKey = rotated.key
            currentGeneration = nextGeneration
            if !VaultIdentityStore.advanceWatermark(
                VaultIdentityRecord(
                    vaultID: vaultID,
                    generation: nextGeneration,
                    envelopeVersion: rotated.envelope.version
                ),
                using: stateBackend
            ) {
                securityNotice = "安全提醒：主密码已更新，但防回滚版本水位写入系统钥匙串失败，将在下次保存时自动重试。"
            }

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

    func createEncryptedBackupData(currentMasterPassword: String, backupPassword: String) async throws -> Data {
        if rejectIfDebuggerAttached() {
            throw VaultCryptoError.authenticationFailed
        }
        guard !isBusy else {
            throw VaultCryptoError.authenticationFailed
        }
        if currentMasterPassword.isEmpty {
            throw VaultCryptoError.weakPassword("请先输入当前本机主密码以授权导出离线备份")
        }
        if let message = PasswordPolicy.validationMessage(backupPassword, for: .backup) {
            throw VaultCryptoError.weakPassword(message)
        }
        if VaultCrypto.normalizePassword(currentMasterPassword) == VaultCrypto.normalizePassword(backupPassword) {
            throw VaultCryptoError.weakPassword("备份密码不能与本机主密码相同：备份文件一旦外泄被破解，本机主密码也会随之暴露。")
        }
        guard phase == .unlocked, let envelope = currentEnvelope else {
            throw VaultCryptoError.authenticationFailed
        }

        isBusy = true
        defer { isBusy = false }

        let startedEpoch = sessionEpoch
        guard await verifyMasterPasswordReauth(currentMasterPassword, against: envelope) else {
            throw VaultCryptoError.weakPassword(errorMessage ?? VaultCryptoError.authenticationFailed.localizedDescription)
        }
        guard isSessionStillValid(since: startedEpoch), phase == .unlocked else {
            throw VaultCryptoError.authenticationFailed
        }

        let snapshotCards = cards
        let exported = try await Task.detached(priority: .userInitiated) {
            try VaultCrypto.exportEncryptedBackup(
                cards: snapshotCards,
                backupPassword: backupPassword,
                iterations: VaultCrypto.calibratedIterations()
            )
        }.value
        guard isSessionStillValid(since: startedEpoch), phase == .unlocked else {
            throw VaultCryptoError.authenticationFailed
        }
        return exported
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
        let startedEpoch = sessionEpoch

        let decrypted = try await Task.detached(priority: .userInitiated) {
            try VaultCrypto.importEncryptedBackup(data: data, backupPassword: backupPassword)
        }.value
        let importedCards = try Self.sanitizeImportedCards(decrypted)

        // The session may have been locked while decrypting: never write a vault built from a wiped `cards` array.
        guard isSessionStillValid(since: startedEpoch), phase == .unlocked else {
            throw VaultCryptoError.authenticationFailed
        }

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
            guard merged.count <= Self.maximumImportedCardCount * 2 else {
                throw VaultCryptoError.weakPassword("合并后卡片数量超过安全上限，已拒绝导入")
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
        let startedEpoch = sessionEpoch

        let restoredCards: [BankCard]
        do {
            let decrypted = try await Task.detached(priority: .userInitiated) {
                try VaultCrypto.importEncryptedBackup(data: data, backupPassword: backupPassword)
            }.value
            restoredCards = try Self.sanitizeImportedCards(decrypted)
        } catch {
            errorMessage = error.localizedDescription
            return false
        }

        return await performSetupNewVault(
            masterPassword: newMasterPassword,
            enableBiometrics: enableBiometrics,
            initialCards: restoredCards,
            startedEpoch: startedEpoch
        )
    }

    /// Re-validates every imported card through `BankCard.init` (digit filtering / trimming), enforces field
    /// length caps and a card-count cap, and de-duplicates IDs. Prevents crafted or legacy backups from
    /// freezing the UI or exhausting memory with oversized fields.
    static func sanitizeImportedCards(_ input: [BankCard]) throws -> [BankCard] {
        guard input.count <= maximumImportedCardCount else {
            throw VaultCryptoError.weakPassword("备份内卡片数量超过 \(maximumImportedCardCount) 张安全上限，已拒绝导入")
        }
        func cap(_ value: String, _ limit: Int) -> String {
            value.count > limit ? String(value.prefix(limit)) : value
        }
        func validDay(_ day: Int?) -> Int? {
            guard let day, (1...31).contains(day) else { return nil }
            return day
        }
        var seenIDs = Set<UUID>()
        return input.map { raw in
            var id = raw.id
            if !seenIDs.insert(id).inserted {
                id = UUID()
                seenIDs.insert(id)
            }
            return BankCard(
                id: id,
                bankName: cap(raw.bankName, 64),
                nickname: cap(raw.nickname, 64),
                cardType: raw.cardType,
                network: raw.network,
                cardNumber: String(raw.cardNumber.filter(\.isWholeNumber).prefix(19)),
                cardholderName: cap(raw.cardholderName, 64),
                expiryMonth: String(raw.expiryMonth.filter(\.isWholeNumber).prefix(2)),
                expiryYear: String(raw.expiryYear.filter(\.isWholeNumber).prefix(4)),
                cvv: String(raw.cvv.filter(\.isWholeNumber).prefix(4)),
                pin: cap(raw.pin, 12),
                billingAddress: cap(raw.billingAddress, 256),
                postalCode: cap(raw.postalCode, 16),
                phoneLast4: raw.phoneLast4,
                statementDay: validDay(raw.statementDay),
                dueDay: validDay(raw.dueDay),
                creditLimit: cap(raw.creditLimit, 32),
                notes: cap(raw.notes, 2000),
                theme: raw.theme,
                isFavorite: raw.isFavorite,
                createdAt: raw.createdAt,
                updatedAt: raw.updatedAt
            )
        }
    }

    /// Inspects a user-picked/exported URL and warns immediately if it resides inside iCloud Drive / Ubiquity sync!
    func warnIfCloudSyncedURL(_ url: URL) {
        let values = try? url.resourceValues(forKeys: [.isUbiquitousItemKey])
        let pathLower = url.path.lowercased()
        if values?.isUbiquitousItem == true || pathLower.contains("mobile documents") || pathLower.contains("icloud") {
            securityNotice = "离线安全提醒：您刚刚选择的路径位于 iCloud 云同步目录中，系统可能会在后台将其同步到云端服务器。为确保零云端同步，强烈建议将备份移至「我的 iPhone」本地目录或离线硬件 U 盘，并彻底删除云端副本。"
        }
    }

    /// User-initiated destruction from an unlocked session requires throttled master-password re-authentication,
    /// so a coerced Face ID unlock cannot be used to shred the vault and its Secure Enclave key.
    func destroyVaultAfterReauth(masterPassword: String) async -> Bool {
        if rejectIfDebuggerAttached() { return false }
        guard !isBusy, phase == .unlocked, let envelope = currentEnvelope else { return false }
        guard !masterPassword.isEmpty else {
            errorMessage = "请输入当前主密码授权销毁"
            return false
        }
        errorMessage = nil
        isBusy = true
        let verified = await verifyMasterPasswordReauth(masterPassword, against: envelope)
        isBusy = false
        guard verified, phase == .unlocked else { return false }
        destroyVaultCompletely()
        return true
    }

    /// Cryptographically shreds the Secure Enclave hardware key, biometric key, counters, preferences, and ciphertext file.
    func destroyVaultCompletely() {
        bumpSessionEpoch()
        cancelBackgroundLock()
        resignActiveInputFocus()
        clipboard.clearIfOwned()
        hardwareKeys.destroyKey() // Hardware-level Crypto-Shredding!
        KeychainBiometrics.deleteBiometricDEK()
        VaultIdentityStore.clear(using: stateBackend)
        VaultPreferencesStore.clear(using: stateBackend)
        lockout.reset()
        KeychainStateAuthenticator.clearKey(using: stateBackend)

        SafeVaultFileIO.shredAndRemoveLocalVault(
            fileURL: vaultFileURL,
            storageDirectoryURL: storageDirectoryURL,
            ancestorDirectoriesToVerify: verifiedAncestorDirectories
        )

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
        resignActiveInputFocus()
    }

    func handleDidEnterBackground() {
        isAppInactive = true
        backgroundEnteredAt = Date()
        bumpSessionEpoch()
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
        periodicTickCounter &+= 1
        #if !DEBUG
        if RuntimeSecurity.isDebuggerAttached() {
            clipboard.clearIfOwned()
            KeychainBiometrics.deleteBiometricDEK()
            lock(reason: .securityAnomaly)
            securityNotice = "检测到外部调试器附加，已立即销毁内存会话并锁定 Enkard。"
            return
        }
        #endif

        // Re-audit Mach-O images & GOT bindings every 30s (6 ticks) while foregrounded to catch post-launch `dlopen` hooks.
        if periodicTickCounter % 6 == 0, !isAppInactive {
            let latestIntegrity = RuntimeSecurity.auditEnvironment(
                antiDebugActive: AppDelegate.antiDebugEnabledAtLaunch
            )
            let newlyCompromised = latestIntegrity.isCompromised && !runtimeIntegrity.isCompromised
            runtimeIntegrity = latestIntegrity
            if newlyCompromised {
                KeychainBiometrics.deleteBiometricDEK()
                securityNotice = "运行时完整性告警：\(latestIntegrity.summaryText)。已立即撤销生物识别快捷解锁！"
            }
        }

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
        backgroundTaskID = UIApplication.shared.beginBackgroundTask(withName: "EnkardAutoLock") { [weak self] in
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

        try SafeVaultFileIO.writeLocalVaultFileAtomically(
            data,
            to: vaultFileURL,
            ancestorDirectoriesToVerify: verifiedAncestorDirectories
        )
    }

    /// Releases decrypted state and scrubs inline SSO slots before freeing buffer capacity.
    /// `SymmetricKey` zeroes its storage on deallocation.
    private func wipeSensitiveMemory() {
        for index in cards.indices {
            cards[index].scrubInPlace()
        }
        cards.removeAll(keepingCapacity: false)
        activeKey = nil
        currentGeneration = 0
    }
}
