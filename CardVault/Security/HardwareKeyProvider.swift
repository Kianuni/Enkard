import CryptoKit
import Foundation
import Security

enum HardwareProtectionTier: String, Codable, Equatable, Sendable {
    /// Private key lives inside Apple Silicon / iPhone Secure Enclave (non-exportable hardware silicon).
    case secureEnclavePasscodeBound = "secure_enclave_passcode"
    case secureEnclaveUnlockedBound = "secure_enclave_unlocked"
    /// Used only if the host hardware lacks an accessible Secure Enclave (e.g. headless test host).
    case keychainDeviceBoundFallback = "keychain_device_bound"

    var displayTitle: String {
        switch self {
        case .secureEnclavePasscodeBound:
            return tr("Secure Enclave 安全芯片（已绑定锁屏密码）", "Secure Enclave (Passcode-Bound)")
        case .secureEnclaveUnlockedBound:
            return tr("Secure Enclave 安全芯片（仅解锁态可用）", "Secure Enclave (Unlocked Only)")
        case .keychainDeviceBoundFallback:
            return tr("本机专属钥匙串密钥（当前环境无可用 SE）", "Device Keychain Key (No SE Available)")
        }
    }
}

enum HardwareKeyError: LocalizedError, Equatable {
    case keyNotFound
    case temporarilyUnavailable
    case keyCreationFailed
    case keyAgreementFailed
    case invalidEphemeralPublicKey

    var errorDescription: String? {
        switch self {
        case .keyNotFound:
            return tr(
                "未找到本机安全芯片绑定密钥（该加密库可能来自其他设备，或本机密钥已被安全销毁；跨设备请使用加密备份恢复）",
                "Device Secure Enclave key not found (this vault may belong to another device, or its key was securely wiped; use an encrypted backup to restore across devices)."
            )
        case .temporarilyUnavailable:
            return tr(
                "系统钥匙串或安全芯片当前暂不可访问，请先解锁手机屏幕后再试",
                "Keychain or Secure Enclave is temporarily unavailable. Please unlock your iPhone and try again."
            )
        case .keyCreationFailed:
            return tr(
                "创建本机安全芯片密钥失败，请确认设备已解锁并开启锁屏密码",
                "Failed to create Secure Enclave hardware key. Make sure your device is unlocked with a passcode set."
            )
        case .keyAgreementFailed:
            return tr(
                "本机安全芯片密钥协商失败",
                "Secure Enclave hardware key agreement failed."
            )
        case .invalidEphemeralPublicKey:
            return tr(
                "加密信封中的硬件协商公钥无效或已损坏",
                "Invalid or corrupted hardware ephemeral public key in vault envelope."
            )
        }
    }
}

/// Abstracts P-256 ECDH hardware key operations so `VaultCrypto` can bind local vaults to
/// the iPhone Secure Enclave in production while remaining deterministically testable.
protocol HardwareKeyProvider: Sendable {
    /// Stages a brand-new device-bound key in the pending slot and returns an ephemeral public key
    /// plus a 256-bit hardware secret derived for `salt`. Call `commitRotatedKey()` after disk persistence succeeds.
    func sealNewVaultFactor(salt: Data) throws -> (ephemeralPublicKey: Data, hardwareSecret: SymmetricKey)

    /// Re-wraps for the *existing* active device-bound key using a fresh ephemeral keypair.
    func sealExistingVaultFactor(salt: Data) throws -> (ephemeralPublicKey: Data, hardwareSecret: SymmetricKey)

    /// Recovers the 256-bit hardware secret from `ephemeralPublicKey` using the active non-exportable device private key.
    func unsealVaultFactor(ephemeralPublicKey: Data, salt: Data) throws -> SymmetricKey

    /// Recovers the 256-bit hardware secret using a staged pending key (for crash-recovery if interrupted mid-rotation).
    func unsealPendingVaultFactor(ephemeralPublicKey: Data, salt: Data) throws -> SymmetricKey

    /// Atomically promotes a staged pending key to active, crypto-shredding the previous active key.
    func commitRotatedKey()

    /// Discards an uncommitted pending key while preserving the current active key.
    func discardPendingKey()

    var hasPendingKey: Bool { get }

    /// Cryptographically shreds all active and pending device-bound keys so leftover ciphertext blocks become permanently undecryptable.
    func destroyKey()

    var currentProtectionTier: HardwareProtectionTier? { get }
}

struct DeviceHardwareKeyManager: HardwareKeyProvider {
    private static let tokenAccount = "se_vault_key_token_v2"
    private static let tierAccount = "se_vault_key_tier_v2"
    private static let pendingTokenAccount = "se_vault_key_pending_token_v2"
    private static let pendingTierAccount = "se_vault_key_pending_tier_v2"
    private static let sharedInfo = Data("CARDSE_HARDWARE_ECDH_FACTOR_V2".utf8)

    var currentProtectionTier: HardwareProtectionTier? {
        guard let data = KeychainStateStore.read(Self.tierAccount),
              let raw = String(data: data, encoding: .utf8) else {
            return nil
        }
        return HardwareProtectionTier(rawValue: raw)
    }

    var hasPendingKey: Bool {
        KeychainStateStore.read(Self.pendingTokenAccount) != nil
    }

    func sealNewVaultFactor(salt: Data) throws -> (ephemeralPublicKey: Data, hardwareSecret: SymmetricKey) {
        discardPendingKey()
        try provisionDeviceKey(tokenAccount: Self.pendingTokenAccount, tierAccount: Self.pendingTierAccount)
        let ephemeralPrivate = P256.KeyAgreement.PrivateKey()
        let ephemeralPublicX963 = ephemeralPrivate.publicKey.x963Representation
        // Verify ECDH round-trip through the newly staged key before writing any vault file.
        let secret = try unsealPendingVaultFactor(ephemeralPublicKey: ephemeralPublicX963, salt: salt)
        return (ephemeralPublicX963, secret)
    }

    func sealExistingVaultFactor(salt: Data) throws -> (ephemeralPublicKey: Data, hardwareSecret: SymmetricKey) {
        switch KeychainStateStore.readResult(Self.tokenAccount) {
        case .found:
            break
        case .notFound:
            try provisionDeviceKey(tokenAccount: Self.tokenAccount, tierAccount: Self.tierAccount)
        case .unavailable:
            // Fail-Closed: NEVER overwrite an active Secure Enclave key token during transient Keychain unavailability!
            throw HardwareKeyError.temporarilyUnavailable
        }
        let ephemeralPrivate = P256.KeyAgreement.PrivateKey()
        let ephemeralPublicX963 = ephemeralPrivate.publicKey.x963Representation
        // Run key agreement through our stored private key right away to guarantee round-trip viability before persisting!
        let secret = try unsealVaultFactor(ephemeralPublicKey: ephemeralPublicX963, salt: salt)
        return (ephemeralPublicX963, secret)
    }

    func unsealVaultFactor(ephemeralPublicKey: Data, salt: Data) throws -> SymmetricKey {
        try unsealFactor(
            ephemeralPublicKey: ephemeralPublicKey,
            salt: salt,
            tokenAccount: Self.tokenAccount,
            tierAccount: Self.tierAccount
        )
    }

    func unsealPendingVaultFactor(ephemeralPublicKey: Data, salt: Data) throws -> SymmetricKey {
        try unsealFactor(
            ephemeralPublicKey: ephemeralPublicKey,
            salt: salt,
            tokenAccount: Self.pendingTokenAccount,
            tierAccount: Self.pendingTierAccount
        )
    }

    func commitRotatedKey() {
        guard let pendingToken = KeychainStateStore.read(Self.pendingTokenAccount),
              let pendingTier = KeychainStateStore.read(Self.pendingTierAccount) else {
            return
        }
        if KeychainStateStore.write(pendingToken, account: Self.tokenAccount),
           KeychainStateStore.write(pendingTier, account: Self.tierAccount) {
            discardPendingKey()
        }
    }

    func discardPendingKey() {
        KeychainStateStore.delete(Self.pendingTokenAccount)
        KeychainStateStore.delete(Self.pendingTierAccount)
    }

    func destroyKey() {
        KeychainStateStore.delete(Self.tokenAccount)
        KeychainStateStore.delete(Self.tierAccount)
        discardPendingKey()
    }

    // MARK: - Private provisioning & ECDH

    private func unsealFactor(
        ephemeralPublicKey: Data,
        salt: Data,
        tokenAccount: String,
        tierAccount: String
    ) throws -> SymmetricKey {
        guard ephemeralPublicKey.count == 65 else {
            throw HardwareKeyError.invalidEphemeralPublicKey
        }
        let peerPublicKey: P256.KeyAgreement.PublicKey
        do {
            peerPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey)
        } catch {
            throw HardwareKeyError.invalidEphemeralPublicKey
        }

        let tokenResult = KeychainStateStore.readResult(tokenAccount)
        let tierResult = KeychainStateStore.readResult(tierAccount)
        if case .unavailable = tokenResult {
            throw HardwareKeyError.temporarilyUnavailable
        }
        if case .unavailable = tierResult {
            throw HardwareKeyError.temporarilyUnavailable
        }
        guard case .found(var tokenData) = tokenResult,
              case .found(let tierData) = tierResult,
              let tierRaw = String(data: tierData, encoding: .utf8),
              let tier = HardwareProtectionTier(rawValue: tierRaw) else {
            throw HardwareKeyError.keyNotFound
        }
        defer { SecureZero.wipe(&tokenData) }

        let sharedSecret: SharedSecret
        do {
            switch tier {
            case .secureEnclavePasscodeBound, .secureEnclaveUnlockedBound:
                let sePrivate = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: tokenData)
                sharedSecret = try sePrivate.sharedSecretFromKeyAgreement(with: peerPublicKey)
            case .keychainDeviceBoundFallback:
                let swPrivate = try P256.KeyAgreement.PrivateKey(rawRepresentation: tokenData)
                sharedSecret = try swPrivate.sharedSecretFromKeyAgreement(with: peerPublicKey)
            }
        } catch {
            throw HardwareKeyError.keyAgreementFailed
        }

        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Self.sharedInfo,
            outputByteCount: 32
        )
    }

    private func provisionDeviceKey(tokenAccount: String, tierAccount: String) throws {
        if SecureEnclave.isAvailable {
            // Prefer WhenPasscodeSetThisDeviceOnly so removing the device passcode invalidates the SE key.
            if let passcodeAC = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                [.privateKeyUsage],
                nil
            ), let seKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: passcodeAC) {
                guard persistToken(
                    seKey.dataRepresentation,
                    tier: .secureEnclavePasscodeBound,
                    tokenAccount: tokenAccount,
                    tierAccount: tierAccount
                ) else {
                    throw HardwareKeyError.keyCreationFailed
                }
                return
            }

            if let unlockedAC = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage],
                nil
            ), let seKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: unlockedAC) {
                guard persistToken(
                    seKey.dataRepresentation,
                    tier: .secureEnclaveUnlockedBound,
                    tokenAccount: tokenAccount,
                    tierAccount: tierAccount
                ) else {
                    throw HardwareKeyError.keyCreationFailed
                }
                return
            }
        }

        #if os(iOS) && !targetEnvironment(simulator)
        // Fail-Closed on physical iPhones/iPads: NEVER silently downgrade from Secure Enclave silicon to software keys.
        throw HardwareKeyError.keyCreationFailed
        #else
        // Software Keychain fallback strictly for Simulator or unsigned macOS CLI test runners without SEP entitlement.
        let fallbackKey = P256.KeyAgreement.PrivateKey()
        var raw = fallbackKey.rawRepresentation
        defer { SecureZero.wipe(&raw) }
        guard persistToken(
            raw,
            tier: .keychainDeviceBoundFallback,
            tokenAccount: tokenAccount,
            tierAccount: tierAccount
        ) else {
            throw HardwareKeyError.keyCreationFailed
        }
        #endif
    }

    private func persistToken(
        _ token: Data,
        tier: HardwareProtectionTier,
        tokenAccount: String,
        tierAccount: String
    ) -> Bool {
        guard KeychainStateStore.write(token, account: tokenAccount),
              KeychainStateStore.write(Data(tier.rawValue.utf8), account: tierAccount) else {
            KeychainStateStore.delete(tokenAccount)
            KeychainStateStore.delete(tierAccount)
            return false
        }
        return true
    }
}

/// Deterministic in-memory P-256 hardware key simulator for unit tests (verifies SE binding, 2-phase rotation & crypto-shredding).
final class InMemoryHardwareKeyProvider: HardwareKeyProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var storedKey: P256.KeyAgreement.PrivateKey?
    private var pendingKey: P256.KeyAgreement.PrivateKey?
    private static let sharedInfo = Data("CARDSE_HARDWARE_ECDH_FACTOR_V2".utf8)

    init(preprovisioned: Bool = false) {
        if preprovisioned {
            storedKey = P256.KeyAgreement.PrivateKey()
        }
    }

    var currentProtectionTier: HardwareProtectionTier? {
        lock.lock()
        defer { lock.unlock() }
        return storedKey == nil ? nil : .secureEnclavePasscodeBound
    }

    var hasPendingKey: Bool {
        lock.lock()
        defer { lock.unlock() }
        return pendingKey != nil
    }

    func sealNewVaultFactor(salt: Data) throws -> (ephemeralPublicKey: Data, hardwareSecret: SymmetricKey) {
        lock.lock()
        pendingKey = P256.KeyAgreement.PrivateKey()
        lock.unlock()
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let x963 = ephemeral.publicKey.x963Representation
        let secret = try unsealPendingVaultFactor(ephemeralPublicKey: x963, salt: salt)
        return (x963, secret)
    }

    func sealExistingVaultFactor(salt: Data) throws -> (ephemeralPublicKey: Data, hardwareSecret: SymmetricKey) {
        lock.lock()
        if storedKey == nil {
            storedKey = P256.KeyAgreement.PrivateKey()
        }
        lock.unlock()
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let x963 = ephemeral.publicKey.x963Representation
        let secret = try unsealVaultFactor(ephemeralPublicKey: x963, salt: salt)
        return (x963, secret)
    }

    func unsealVaultFactor(ephemeralPublicKey: Data, salt: Data) throws -> SymmetricKey {
        lock.lock()
        let current = storedKey
        lock.unlock()
        return try deriveSecret(privateKey: current, ephemeralPublicKey: ephemeralPublicKey, salt: salt)
    }

    func unsealPendingVaultFactor(ephemeralPublicKey: Data, salt: Data) throws -> SymmetricKey {
        lock.lock()
        let staged = pendingKey
        lock.unlock()
        return try deriveSecret(privateKey: staged, ephemeralPublicKey: ephemeralPublicKey, salt: salt)
    }

    func commitRotatedKey() {
        lock.lock()
        if let pendingKey {
            storedKey = pendingKey
            self.pendingKey = nil
        }
        lock.unlock()
    }

    func discardPendingKey() {
        lock.lock()
        pendingKey = nil
        lock.unlock()
    }

    func destroyKey() {
        lock.lock()
        storedKey = nil
        pendingKey = nil
        lock.unlock()
    }

    private func deriveSecret(
        privateKey: P256.KeyAgreement.PrivateKey?,
        ephemeralPublicKey: Data,
        salt: Data
    ) throws -> SymmetricKey {
        guard ephemeralPublicKey.count == 65,
              let peer = try? P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey) else {
            throw HardwareKeyError.invalidEphemeralPublicKey
        }
        guard let privateKey else {
            throw HardwareKeyError.keyNotFound
        }
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: peer)
        return shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Self.sharedInfo,
            outputByteCount: 32
        )
    }
}
