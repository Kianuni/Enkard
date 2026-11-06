import Darwin
import Foundation
import Security

enum KeychainReadResult: Equatable, Sendable {
    case found(Data)
    case notFound
    case unavailable(OSStatus)
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
            kSecValueData as String: data
        ]
        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, attributesToUpdate as CFDictionary)
        if updateStatus == errSecSuccess {
            return true
        }

        // Delete any stale entry (e.g. attribute mismatch) and re-create with strict attributes.
        SecItemDelete(baseQuery as CFDictionary)

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

// MARK: - Anti-rollback & anti-replacement vault identity store

struct VaultIdentityRecord: Codable, Equatable, Sendable {
    var vaultID: UUID?
    var generation: UInt64
    var envelopeVersion: Int
}

enum VaultIdentityStore {
    private static let account = "vault_identity_v2"
    private static let legacyAccount = "vault_generation"

    static func readResult() -> (record: VaultIdentityRecord?, isUnavailable: Bool) {
        switch KeychainStateStore.readResult(account) {
        case .found(let data):
            if let decoded = try? JSONDecoder().decode(VaultIdentityRecord.self, from: data) {
                return (decoded, false)
            }
            return (nil, false)
        case .unavailable:
            return (nil, true)
        case .notFound:
            // Migrate v1 generation integer if present.
            if let legacyData = KeychainStateStore.read(legacyAccount),
               let text = String(data: legacyData, encoding: .utf8),
               let gen = UInt64(text) {
                let migrated = VaultIdentityRecord(vaultID: nil, generation: gen, envelopeVersion: 1)
                _ = write(migrated)
                KeychainStateStore.delete(legacyAccount)
                return (migrated, false)
            }
            return (nil, false)
        }
    }

    static func read() -> VaultIdentityRecord? {
        readResult().record
    }

    @discardableResult
    static func write(_ record: VaultIdentityRecord) -> Bool {
        guard let data = try? JSONEncoder().encode(record) else { return false }
        return KeychainStateStore.write(data, account: account)
    }

    static func clear() {
        KeychainStateStore.delete(account)
        KeychainStateStore.delete(legacyAccount)
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

    static func load() -> VaultPreferences {
        if let data = KeychainStateStore.read(account),
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
            save(prefs)
            purgeLegacyUserDefaults()
        }
        return prefs
    }

    @discardableResult
    static func save(_ prefs: VaultPreferences) -> Bool {
        guard let data = try? JSONEncoder().encode(prefs) else { return false }
        return KeychainStateStore.write(data, account: account)
    }

    static func clear() {
        KeychainStateStore.delete(account)
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
        guard let start = record.lockStartMonotonicNs, record.lockDurationSeconds > 0 else {
            return (0, false)
        }
        guard record.bootSession == currentBootSession, nowMonotonicNs >= start else {
            return (record.lockDurationSeconds, true)
        }
        let elapsed = Int((nowMonotonicNs - start) / 1_000_000_000)
        return (max(0, record.lockDurationSeconds - elapsed), false)
    }
}

@MainActor
final class LockoutGuard {
    private static let account = "unlock_lockout"
    private(set) var record: LockoutRecord

    init() {
        if let data = KeychainStateStore.read(Self.account),
           let decoded = try? JSONDecoder().decode(LockoutRecord.self, from: data) {
            record = decoded
        } else {
            record = LockoutRecord()
        }
    }

    var failures: Int { record.failures }
    var isLockdownActive: Bool { record.isLockdownActive }

    /// Biometrics must be suspended once password brute-force throttling engages or Emergency Lockdown is active.
    var isBiometricSuspended: Bool {
        record.isLockdownActive
            || record.failures >= LockoutPolicy.biometricSuspensionThreshold
            || remainingSeconds() > 0
    }

    func remainingSeconds() -> Int {
        let now = Self.monotonicNow()
        let boot = Self.bootSession()
        let result = LockoutPolicy.remainingSeconds(record: record, nowMonotonicNs: now, currentBootSession: boot)
        if result.needsRestart {
            record.lockStartMonotonicNs = now
            record.bootSession = boot
            _ = persist()
        }
        return result.remaining
    }

    /// Counted and persisted *before* the KDF runs (Fail-Closed: returns false if Keychain write fails).
    func beginAttempt() -> Bool {
        var updated = record
        updated.failures = record.failures == Int.max ? Int.max : record.failures + 1
        let seconds = LockoutPolicy.lockoutSeconds(forFailures: updated.failures)
        if seconds > 0 {
            updated.lockStartMonotonicNs = Self.monotonicNow()
            updated.lockDurationSeconds = seconds
            updated.bootSession = Self.bootSession()
        }
        record = updated
        return persist()
    }

    @discardableResult
    func setLockdownActive(_ active: Bool) -> Bool {
        record.isLockdownActive = active
        if !active && record.failures == 0 {
            KeychainStateStore.delete(Self.account)
            return true
        }
        return persist()
    }

    func reset() {
        record = LockoutRecord()
        KeychainStateStore.delete(Self.account)
    }

    @discardableResult
    private func persist() -> Bool {
        guard let data = try? JSONEncoder().encode(record) else { return false }
        return KeychainStateStore.write(data, account: Self.account)
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
