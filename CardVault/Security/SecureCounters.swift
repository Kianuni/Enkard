import CryptoKit
import Darwin
import Foundation
import Security

enum KeychainReadResult: Equatable, Sendable {
    case found(Data)
    case notFound
    case unavailable(OSStatus)
}

protocol KeychainStateBackend: Sendable {
    func readResult(_ account: String) -> KeychainReadResult
    func write(_ data: Data, account: String) -> Bool
    func delete(_ account: String)
}

struct SystemKeychainBackend: KeychainStateBackend {
    func readResult(_ account: String) -> KeychainReadResult {
        KeychainStateStore.readResult(account)
    }

    func write(_ data: Data, account: String) -> Bool {
        KeychainStateStore.write(data, account: account)
    }

    func delete(_ account: String) {
        KeychainStateStore.delete(account)
    }
}

/// Device-bound, non-synchronizable Keychain state store (`WhenUnlockedThisDeviceOnly`, `Synchronizable = false`).
/// Never backed up to iCloud Keychain or transferable across devices.
enum KeychainStateStore {
    private static let service = "com.local.cardse.state.v2"
    private static let legacyServiceV1 = "com.local.cardvault.state.v1"

    static func readResult(_ account: String) -> KeychainReadResult {
        switch queryAccount(account, inService: service) {
        case .found(let data):
            return .found(data)
        case .unavailable(let status):
            return .unavailable(status)
        case .notFound:
            // Transparent one-way migration from v1 service if present.
            if case .found(let legacyData) = queryAccount(account, inService: legacyServiceV1) {
                if write(legacyData, account: account) {
                    deleteLegacy(account)
                }
                return .found(legacyData)
            }
            return .notFound
        }
    }

    static func read(_ account: String) -> Data? {
        if case .found(let data) = readResult(account) {
            return data
        }
        return nil
    }

    @discardableResult
    static func write(_ data: Data, account: String) -> Bool {
        let baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse!
        ]
        let attributesToUpdate: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, attributesToUpdate as CFDictionary)
        if updateStatus == errSecSuccess {
            return true
        }
        // Fail-closed: never delete the existing record (lockout counter / anti-rollback watermark) on a transient
        // failure such as a locked device — a delete-then-failed-add would silently reset security state.
        if updateStatus == errSecInteractionNotAllowed
            || updateStatus == errSecAuthFailed
            || updateStatus == errSecNotAvailable {
            return false
        }

        if updateStatus != errSecItemNotFound {
            // Delete a stale entry (e.g. legacy attribute mismatch) and re-create with strict attributes.
            SecItemDelete(baseQuery as CFDictionary)
        }

        var addQuery = baseQuery
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        return SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess
    }

    static func delete(_ account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse!
        ]
        SecItemDelete(query as CFDictionary)
        deleteLegacy(account)
    }

    private static func queryAccount(_ account: String, inService targetService: String) -> KeychainReadResult {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: targetService,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse!,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { return .notFound }
            return .found(data)
        case errSecItemNotFound:
            return .notFound
        default:
            return .unavailable(status)
        }
    }

    private static func deleteLegacy(_ account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: legacyServiceV1,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - Device-Bound HMAC Authenticator for Keychain Security State (v2.3+)

enum AuthenticatedKeychainStateRead: Equatable, Sendable {
    case found(Data)
    case notFound
    case unavailable
    case corrupted
}

/// Cryptographically authenticates Keychain security state (`vault_identity_v2`, `unlock_lockout`, `local_preferences_v2`)
/// using a 256-bit `WhenUnlockedThisDeviceOnly` HMAC-SHA256 key (`state_hmac_key_v2`), binding each record to its exact
/// account name (`"ENKARD_STATE_HMAC_V1"`). Defeats Keychain JSON tampering, cross-account swapping, and MAC stripping,
/// while performing a crash-safe one-time migration of existing `v2.2` plain-JSON records on first launch.
enum KeychainStateAuthenticator {
    static let hmacKeyAccount = "state_hmac_key_v2"
    private static let envelopeMagic = Data("EKM1".utf8) // 4 bytes
    private static let domainPrefix = Data("ENKARD_STATE_HMAC_V1|".utf8)
    private static let tagByteCount = 32
    private static let managedAccounts = [
        "vault_identity_v2",
        "local_preferences_v2",
        "unlock_lockout"
    ]

    private enum KeyBootstrapState {
        case ready(SymmetricKey)
        case noKeyAndStoreEmpty
        case unavailable
        case corrupted
    }

    static func readAuthenticated(
        account: String,
        using backend: any KeychainStateBackend = SystemKeychainBackend()
    ) -> AuthenticatedKeychainStateRead {
        switch bootstrapKeyIfNeeded(createWhenEmpty: false, using: backend) {
        case .unavailable:
            return .unavailable
        case .corrupted:
            return .corrupted
        case .noKeyAndStoreEmpty:
            return .notFound
        case .ready(let hmacKey):
            switch backend.readResult(account) {
            case .notFound:
                return .notFound
            case .unavailable:
                return .unavailable
            case .found(let blob):
                guard let verified = openAuthenticatedBlob(blob, account: account, using: hmacKey) else {
                    return .corrupted
                }
                return .found(verified)
            }
        }
    }

    @discardableResult
    static func writeAuthenticated(
        _ payload: Data,
        account: String,
        using backend: any KeychainStateBackend = SystemKeychainBackend()
    ) -> Bool {
        guard case .ready(let hmacKey) = bootstrapKeyIfNeeded(createWhenEmpty: true, using: backend) else {
            return false
        }
        let sealed = sealAuthenticatedBlob(payload, account: account, using: hmacKey)
        return backend.write(sealed, account: account)
    }

    static func clearKey(using backend: any KeychainStateBackend = SystemKeychainBackend()) {
        backend.delete(hmacKeyAccount)
    }

    private static func bootstrapKeyIfNeeded(
        createWhenEmpty: Bool,
        using backend: any KeychainStateBackend
    ) -> KeyBootstrapState {
        switch backend.readResult(hmacKeyAccount) {
        case .unavailable:
            return .unavailable
        case .found(var keyData):
            defer { SecureZero.wipe(&keyData) }
            guard keyData.count == 32 else {
                return .corrupted
            }
            return .ready(SymmetricKey(data: keyData))
        case .notFound:
            // Inspect all managed state accounts before creating a key:
            // 1) If any is `.unavailable`, fail closed without creating a key.
            // 2) If any already carries `"EKM1"`, the HMAC key was maliciously deleted — fail closed (`.corrupted`)!
            // 3) Upgrade any valid pre-v2.3 plain JSON records atomically before persisting the new HMAC key.
            var legacyPayloads: [(account: String, data: Data)] = []
            var anyAccountPresent = false
            for acct in managedAccounts {
                switch backend.readResult(acct) {
                case .unavailable:
                    return .unavailable
                case .notFound:
                    continue
                case .found(let existingBlob):
                    anyAccountPresent = true
                    if existingBlob.starts(with: envelopeMagic) {
                        return .corrupted
                    }
                    if isValidLegacyPlainRecord(existingBlob, forAccount: acct) {
                        legacyPayloads.append((acct, existingBlob))
                    }
                }
            }

            if !anyAccountPresent && !createWhenEmpty {
                return .noKeyAndStoreEmpty
            }

            var keyBytes = [UInt8](repeating: 0, count: 32)
            defer { SecureZero.wipe(&keyBytes) }
            guard SecRandomCopyBytes(kSecRandomDefault, 32, &keyBytes) == errSecSuccess else {
                return .unavailable
            }
            var keyData = Data(keyBytes)
            defer { SecureZero.wipe(&keyData) }
            let hmacKey = SymmetricKey(data: keyData)

            // Re-wrap all valid pre-v2.3 plain JSON records first, then persist `state_hmac_key_v2`.
            for item in legacyPayloads {
                let wrapped = sealAuthenticatedBlob(item.data, account: item.account, using: hmacKey)
                guard backend.write(wrapped, account: item.account) else {
                    return .unavailable
                }
            }
            guard backend.write(keyData, account: hmacKeyAccount) else {
                return .unavailable
            }
            return .ready(hmacKey)
        }
    }

    private static func isValidLegacyPlainRecord(_ data: Data, forAccount account: String) -> Bool {
        switch account {
        case "vault_identity_v2":
            guard let rec = try? JSONDecoder().decode(VaultIdentityRecord.self, from: data) else { return false }
            return rec.isValid
        case "local_preferences_v2":
            return (try? JSONDecoder().decode(VaultPreferences.self, from: data)) != nil
        case "unlock_lockout":
            guard let rec = try? JSONDecoder().decode(LockoutRecord.self, from: data) else { return false }
            return rec.isValid
        default:
            return false
        }
    }

    private static func makeMACInput(account: String, payload: Data) -> Data {
        let acctBytes = Data(account.utf8)
        var msg = Data(capacity: domainPrefix.count + 4 + acctBytes.count + payload.count)
        msg.append(domainPrefix)
        var acctLenBE = UInt32(acctBytes.count).bigEndian
        withUnsafeBytes(of: &acctLenBE) { msg.append(contentsOf: $0) }
        msg.append(acctBytes)
        msg.append(payload)
        return msg
    }

    private static func sealAuthenticatedBlob(_ payload: Data, account: String, using key: SymmetricKey) -> Data {
        let macInput = makeMACInput(account: account, payload: payload)
        let tag = HMAC<SHA256>.authenticationCode(for: macInput, using: key)
        var out = Data(capacity: envelopeMagic.count + tagByteCount + payload.count)
        out.append(envelopeMagic)
        out.append(contentsOf: tag)
        out.append(payload)
        return out
    }

    private static func openAuthenticatedBlob(_ blob: Data, account: String, using key: SymmetricKey) -> Data? {
        let headerLen = envelopeMagic.count + tagByteCount
        guard blob.count > headerLen, blob.starts(with: envelopeMagic) else {
            return nil
        }
        let tagSlice = Data(blob[envelopeMagic.count..<headerLen])
        let payload = Data(blob[headerLen..<blob.count])
        let macInput = makeMACInput(account: account, payload: payload)
        guard HMAC<SHA256>.isValidAuthenticationCode(tagSlice, authenticating: macInput, using: key) else {
            return nil
        }
        return payload
    }
}

// MARK: - Anti-rollback & anti-replacement vault identity store

struct VaultIdentityRecord: Codable, Equatable, Sendable {
    var vaultID: UUID?
    var generation: UInt64
    var envelopeVersion: Int

    var isValid: Bool {
        envelopeVersion >= 1
            && envelopeVersion <= 100
            && generation < VaultPlaintextPayload.maximumValidGeneration
    }
}

enum VaultIdentityState: Equatable, Sendable {
    case found(VaultIdentityRecord)
    case notFound
    case unavailable
    case corrupted
}

enum VaultIdentityStore {
    private static let account = "vault_identity_v2"
    private static let legacyAccount = "vault_generation"

    static func readState(using backend: any KeychainStateBackend = SystemKeychainBackend()) -> VaultIdentityState {
        switch KeychainStateAuthenticator.readAuthenticated(account: account, using: backend) {
        case .found(let data):
            if let decoded = try? JSONDecoder().decode(VaultIdentityRecord.self, from: data), decoded.isValid {
                return .found(decoded)
            }
            return .corrupted
        case .unavailable:
            return .unavailable
        case .corrupted:
            return .corrupted
        case .notFound:
            // Migrate v1 generation integer if present, failing closed on transient unavailability.
            switch backend.readResult(legacyAccount) {
            case .unavailable:
                return .unavailable
            case .found(let legacyData):
                if let text = String(data: legacyData, encoding: .utf8),
                   let gen = UInt64(text),
                   gen < VaultPlaintextPayload.maximumValidGeneration {
                    let migrated = VaultIdentityRecord(vaultID: nil, generation: gen, envelopeVersion: 1)
                    if write(migrated, using: backend) {
                        backend.delete(legacyAccount)
                    }
                    return .found(migrated)
                }
                return .corrupted
            case .notFound:
                return .notFound
            }
        }
    }

    static func readResult() -> (record: VaultIdentityRecord?, isUnavailable: Bool) {
        switch readState() {
        case .found(let record):
            return (record, false)
        case .notFound:
            return (nil, false)
        case .unavailable, .corrupted:
            return (nil, true)
        }
    }

    static func read() -> VaultIdentityRecord? {
        if case .found(let record) = readState() {
            return record
        }
        return nil
    }

    @discardableResult
    static func write(_ record: VaultIdentityRecord, using backend: any KeychainStateBackend = SystemKeychainBackend()) -> Bool {
        guard record.isValid, let data = try? JSONEncoder().encode(record) else { return false }
        return KeychainStateAuthenticator.writeAuthenticated(data, account: account, using: backend)
    }

    /// Monotonically advances `(generation, envelopeVersion)` without ever regressing an existing watermark
    /// or overwriting an already-established `vaultID` with a foreign vault's ID.
    @discardableResult
    static func advanceWatermark(
        _ candidate: VaultIdentityRecord,
        using backend: any KeychainStateBackend = SystemKeychainBackend()
    ) -> Bool {
        guard candidate.isValid else { return false }
        switch readState(using: backend) {
        case .unavailable, .corrupted:
            return false
        case .notFound:
            return write(candidate, using: backend)
        case .found(let existing):
            if let existingID = existing.vaultID,
               let candidateID = candidate.vaultID,
               existingID != candidateID {
                return false
            }
            let merged = VaultIdentityRecord(
                vaultID: existing.vaultID ?? candidate.vaultID,
                generation: max(existing.generation, candidate.generation),
                envelopeVersion: max(existing.envelopeVersion, candidate.envelopeVersion)
            )
            return write(merged, using: backend)
        }
    }

    static func clear(using backend: any KeychainStateBackend = SystemKeychainBackend()) {
        backend.delete(account)
        backend.delete(legacyAccount)
    }
}

// MARK: - Non-synced local preferences (never stored in backed-up UserDefaults)

struct VaultPreferences: Codable, Equatable, Sendable {
    var biometricsEnabled: Bool = false
    var autoLockTimeoutRaw: Int = 0       // AutoLockTimeout.immediately
    var idleLockTimeoutRaw: Int = 180     // IdleLockTimeout.minutes3
    var clipboardClearDurationRaw: Int = 15 // ClipboardClearDuration.seconds15
    var wipeAfterFailedAttempts: Bool = false
}

enum VaultPreferencesStore {
    private static let account = "local_preferences_v2"
    private static let legacyKeys = [
        "cardvault.pref.biometricsEnabled",
        "cardvault.pref.autoLockTimeout",
        "cardvault.pref.idleLockTimeout",
        "cardvault.pref.clipboardClearDuration",
        "cardvault.pref.wipeAfterFailedAttempts"
    ]

    static func load(using backend: any KeychainStateBackend = SystemKeychainBackend()) -> VaultPreferences {
        if case .found(let data) = KeychainStateAuthenticator.readAuthenticated(account: account, using: backend),
           let decoded = try? JSONDecoder().decode(VaultPreferences.self, from: data) {
            purgeLegacyUserDefaults()
            return decoded
        }

        // One-time migration from v1 UserDefaults (then scrub UserDefaults so nothing enters backups).
        let defaults = UserDefaults.standard
        let hasLegacy = legacyKeys.contains { defaults.object(forKey: $0) != nil }
        var prefs = VaultPreferences()
        if hasLegacy {
            prefs.biometricsEnabled = defaults.bool(forKey: "cardvault.pref.biometricsEnabled")
            if let v = defaults.object(forKey: "cardvault.pref.autoLockTimeout") as? Int {
                prefs.autoLockTimeoutRaw = v
            }
            if let v = defaults.object(forKey: "cardvault.pref.idleLockTimeout") as? Int {
                prefs.idleLockTimeoutRaw = v
            }
            if let v = defaults.object(forKey: "cardvault.pref.clipboardClearDuration") as? Int {
                prefs.clipboardClearDurationRaw = v
            }
            prefs.wipeAfterFailedAttempts = defaults.bool(forKey: "cardvault.pref.wipeAfterFailedAttempts")
            save(prefs, using: backend)
            purgeLegacyUserDefaults()
        }
        return prefs
    }

    @discardableResult
    static func save(
        _ prefs: VaultPreferences,
        using backend: any KeychainStateBackend = SystemKeychainBackend()
    ) -> Bool {
        guard let data = try? JSONEncoder().encode(prefs) else { return false }
        return KeychainStateAuthenticator.writeAuthenticated(data, account: account, using: backend)
    }

    static func clear(using backend: any KeychainStateBackend = SystemKeychainBackend()) {
        backend.delete(account)
        purgeLegacyUserDefaults()
    }

    private static func purgeLegacyUserDefaults() {
        let defaults = UserDefaults.standard
        for key in legacyKeys {
            defaults.removeObject(forKey: key)
        }
    }
}

// MARK: - Persistent brute-force throttling & emergency lockdown state

struct LockoutRecord: Codable, Equatable, Sendable {
    var failures: Int = 0
    var lockStartMonotonicNs: UInt64?
    var lockDurationSeconds: Int = 0
    var bootSession: String?
    /// True when the user activated Emergency Lockdown ("紧急锁定") to force master-password-only entry.
    var isLockdownActive: Bool = false

    var isValid: Bool {
        guard failures >= 0,
              lockDurationSeconds >= 0,
              lockDurationSeconds <= 86_400 else {
            return false
        }
        if failures >= LockoutPolicy.biometricSuspensionThreshold {
            let expectedMin = LockoutPolicy.lockoutSeconds(forFailures: failures)
            if lockDurationSeconds < expectedMin {
                return false
            }
        }
        return true
    }
}

enum LockoutPolicy {
    static let freeAttempts = 4
    static let biometricSuspensionThreshold = 5
    static let wipeThreshold = 15

    static func lockoutSeconds(forFailures failures: Int) -> Int {
        switch failures {
        case ..<5: return 0
        case 5: return 30
        case 6: return 60
        case 7: return 5 * 60
        case 8: return 15 * 60
        default: return 60 * 60
        }
    }

    /// Pure function so it can be unit tested.
    /// Uses a monotonic clock (immune to changing the system date). After a reboot the
    /// monotonic baseline is lost, so the full lockout restarts (conservative).
    static func remainingSeconds(
        record: LockoutRecord,
        nowMonotonicNs: UInt64,
        currentBootSession: String
    ) -> (remaining: Int, needsRestart: Bool) {
        let boundedDuration = min(86_400, max(0, record.lockDurationSeconds))
        guard let start = record.lockStartMonotonicNs, boundedDuration > 0 else {
            return (0, false)
        }
        guard record.bootSession == currentBootSession, nowMonotonicNs >= start else {
            return (boundedDuration, true)
        }
        let elapsedSecondsU64 = (nowMonotonicNs - start) / 1_000_000_000
        let durationU64 = UInt64(boundedDuration)
        if elapsedSecondsU64 >= durationU64 {
            return (0, false)
        }
        return (Int(durationU64 - elapsedSecondsU64), false)
    }
}

@MainActor
final class LockoutGuard {
    private static let account = "unlock_lockout"
    private let backend: any KeychainStateBackend
    private(set) var record: LockoutRecord = LockoutRecord()
    private var hasLoadedAuthoritativeState = false
    private var isStateUnreadable = false

    init(backend: any KeychainStateBackend = SystemKeychainBackend()) {
        self.backend = backend
        reloadIfNeeded()
    }

    /// Ensures we never overwrite an existing Keychain lockout/lockdown record if `init()` ran while
    /// Keychain was momentarily locked (`errSecInteractionNotAllowed`), and fails closed on corruption/tampering.
    private func reloadIfNeeded() {
        guard !hasLoadedAuthoritativeState else { return }
        switch KeychainStateAuthenticator.readAuthenticated(account: Self.account, using: backend) {
        case .found(let data):
            if let decoded = try? JSONDecoder().decode(LockoutRecord.self, from: data), decoded.isValid {
                record = decoded
                hasLoadedAuthoritativeState = true
                isStateUnreadable = false
            } else {
                isStateUnreadable = true
            }
        case .notFound:
            record = LockoutRecord()
            hasLoadedAuthoritativeState = true
            isStateUnreadable = false
        case .unavailable, .corrupted:
            isStateUnreadable = true
        }
    }

    var failures: Int {
        reloadIfNeeded()
        return record.failures
    }

    var isLockdownActive: Bool {
        reloadIfNeeded()
        return record.isLockdownActive
    }

    /// Biometrics must be suspended once password brute-force throttling engages, Emergency Lockdown is active,
    /// or Keychain lockout state cannot be authoritatively verified (Fail-Closed).
    var isBiometricSuspended: Bool {
        reloadIfNeeded()
        return isStateUnreadable
            || record.isLockdownActive
            || record.failures >= LockoutPolicy.biometricSuspensionThreshold
            || remainingSeconds() > 0
    }

    func remainingSeconds() -> Int {
        reloadIfNeeded()
        let now = Self.monotonicNow()
        let boot = Self.bootSession()
        let result = LockoutPolicy.remainingSeconds(record: record, nowMonotonicNs: now, currentBootSession: boot)
        if result.needsRestart && hasLoadedAuthoritativeState {
            var restarted = record
            restarted.lockStartMonotonicNs = now
            restarted.bootSession = boot
            if persist(restarted) {
                record = restarted
            }
        }
        return result.remaining
    }

    /// Counted and persisted *before* the KDF runs (Fail-Closed: returns false if Keychain read/write fails,
    /// and never overwrites an unreadable Keychain record or mutates memory before Keychain commits).
    func beginAttempt() -> Bool {
        reloadIfNeeded()
        guard hasLoadedAuthoritativeState, !isStateUnreadable else {
            return false
        }
        var updated = record
        updated.failures = record.failures == Int.max ? Int.max : record.failures + 1
        let seconds = LockoutPolicy.lockoutSeconds(forFailures: updated.failures)
        if seconds > 0 {
            updated.lockStartMonotonicNs = Self.monotonicNow()
            updated.lockDurationSeconds = seconds
            updated.bootSession = Self.bootSession()
        }
        guard persist(updated) else {
            return false
        }
        record = updated
        return true
    }

    /// Rolls back the pre-KDF increment ONLY when an operation aborted due to a non-authentication environmental fault
    /// (e.g. transient Secure Enclave / Keychain unavailability), preventing hardware glitches from triggering wipe.
    func rollbackNonAuthenticationFault(restoring previous: LockoutRecord) {
        guard hasLoadedAuthoritativeState, !isStateUnreadable, previous.isValid else { return }
        if previous.failures == 0 && !previous.isLockdownActive {
            backend.delete(Self.account)
            record = previous
        } else if persist(previous) {
            record = previous
        }
    }

    @discardableResult
    func setLockdownActive(_ active: Bool) -> Bool {
        reloadIfNeeded()
        if !active {
            guard hasLoadedAuthoritativeState, !isStateUnreadable else { return false }
            if record.failures == 0 {
                backend.delete(Self.account)
                record.isLockdownActive = false
                return true
            }
        }
        var updated = record
        updated.isLockdownActive = active
        guard persist(updated) else { return false }
        record = updated
        hasLoadedAuthoritativeState = true
        isStateUnreadable = false
        return true
    }

    func reset() {
        record = LockoutRecord()
        hasLoadedAuthoritativeState = true
        isStateUnreadable = false
        backend.delete(Self.account)
    }

    @discardableResult
    private func persist(_ candidate: LockoutRecord) -> Bool {
        guard candidate.isValid, let data = try? JSONEncoder().encode(candidate) else { return false }
        return KeychainStateAuthenticator.writeAuthenticated(data, account: Self.account, using: backend)
    }

    /// CLOCK_MONOTONIC on Darwin keeps counting during sleep and ignores wall-clock changes.
    static func monotonicNow() -> UInt64 {
        clock_gettime_nsec_np(CLOCK_MONOTONIC)
    }

    static func bootSession() -> String {
        var size = 0
        if sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 0 {
            var buffer = [CChar](repeating: 0, count: size)
            if sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0) == 0 {
                return String(cString: buffer)
            }
        }
        var bootTime = timeval()
        var length = MemoryLayout<timeval>.size
        var mib: [Int32] = [CTL_KERN, KERN_BOOTTIME]
        if sysctl(&mib, 2, &bootTime, &length, nil, 0) == 0 {
            return "boottime-\(bootTime.tv_sec)"
        }
        return "unknown"
    }
}
