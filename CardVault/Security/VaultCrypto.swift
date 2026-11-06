import CommonCrypto
import CryptoKit
import Darwin
import Foundation
import Security

enum VaultCryptoError: LocalizedError, Equatable {
    case emptyPassword
    case passwordTooShort(minimum: Int)
    case weakPassword(String)
    case randomGenerationFailed
    case keyDerivationFailed
    case invalidEnvelopeFormat
    case domainMismatch
    case hardwareKeyUnavailable(String)
    case authenticationFailed
    case corruptedPayload

    var errorDescription: String? {
        switch self {
        case .emptyPassword:
            return "请输入密码"
        case .passwordTooShort(let minimum):
            return "密码长度至少需要 \(minimum) 位"
        case .weakPassword(let message):
            return message
        case .randomGenerationFailed:
            return "安全随机数生成失败"
        case .keyDerivationFailed:
            return "密钥派生失败"
        case .invalidEnvelopeFormat:
            return "加密文件格式无效、参数超出安全范围或版本不受支持"
        case .domainMismatch:
            return "文件用途不匹配：本地硬件绑定库与跨设备备份文件禁止混用"
        case .hardwareKeyUnavailable(let reason):
            return reason
        case .authenticationFailed:
            return "密码错误，或加密数据已被篡改"
        case .corruptedPayload:
            return "保险库数据解析失败"
        }
    }
}

enum VaultCrypto {
    /// Lowest iteration count accepted when *reading* legacy files.
    static let minimumAcceptedIterations = 100_000
    /// Floor for every *newly written* vault or backup (OWASP 2023: PBKDF2-HMAC-SHA256 ≥ 600k).
    static let minimumNewIterations = 600_000
    /// Upper bound for files we read — guards against crafted files that crash or hang the app.
    static let maximumAcceptedIterations = 10_000_000
    /// Upper bound for device calibration.
    static let maximumCalibratedIterations = 5_000_000
    /// Target derivation time on the current device.
    static let calibrationTargetSeconds = 0.35

    static let saltByteCount = 32
    static let keyByteCount = 32 // 256-bit
    static let ephemeralPublicKeyByteCount = 65 // Uncompressed X9.63 P-256
    static let payloadPaddingBlockSize = 4096   // 4 KB size buckets hide card count
    static let minimumVaultPasswordLength = 8
    static let minimumBackupPasswordLength = 12

    private static let wrappedDEKByteCount = 12 + 32 + 16 // nonce + key + tag
    private static let minimumPayloadByteCount = 12 + 16
    private static let maximumPayloadByteCount = 20 * 1024 * 1024
    private static let legacyPayloadAADV1 = Data("CARDVAULT_PAYLOAD_AAD_V1".utf8)
    private static let kekCombineInfoV2 = Data("CARDSE_DUAL_KEK_COMBINE_V2".utf8)
    private static let backupKEKInfoV2 = Data("CARDSE_PORTABLE_BACKUP_KEK_V2".utf8)

    // MARK: - Primitives

    static func normalizePassword(_ raw: String) -> String {
        raw.precomposedStringWithCanonicalMapping
    }

    static func generateSecureRandomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else {
            throw VaultCryptoError.randomGenerationFailed
        }
        return Data(bytes)
    }

    /// Measures PBKDF2 CPU time across 3 probes (median) so thread preemption jitter cannot skew calibration.
    static func calibratedIterations(targetSeconds: Double = calibrationTargetSeconds) -> Int {
        let probeIterations = minimumAcceptedIterations
        guard let salt = try? generateSecureRandomBytes(count: saltByteCount) else {
            return minimumNewIterations
        }

        var samples: [Double] = []
        for _ in 0..<3 {
            let start = threadCPUTimeNanoseconds()
            guard (try? derivePasswordKey(
                password: "cardse-calibration-probe",
                salt: salt,
                iterations: probeIterations,
                normalize: true
            )) != nil else {
                return minimumNewIterations
            }
            let end = threadCPUTimeNanoseconds()
            let elapsed = Double(end >= start ? (end - start) : 0) / 1_000_000_000
            if elapsed > 0 {
                samples.append(elapsed)
            }
        }
        guard !samples.isEmpty else { return minimumNewIterations }
        samples.sort()
        let median = samples[samples.count / 2]
        guard median > 0 else { return minimumNewIterations }

        let scaled = Int(Double(probeIterations) * targetSeconds / median)
        let rounded = (scaled / 10_000) * 10_000
        return min(maximumCalibratedIterations, max(minimumNewIterations, rounded))
    }

    private static func threadCPUTimeNanoseconds() -> UInt64 {
        let cpuNs = clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID)
        if cpuNs > 0 { return cpuNs }
        return DispatchTime.now().uptimeNanoseconds
    }

    static func deriveKEK(
        password: String,
        salt: Data,
        iterations: Int
    ) throws -> SymmetricKey {
        try derivePasswordKey(password: password, salt: salt, iterations: iterations, normalize: true)
    }

    private static func derivePasswordKey(
        password: String,
        salt: Data,
        iterations: Int,
        normalize: Bool
    ) throws -> SymmetricKey {
        let effective = normalize ? normalizePassword(password) : password
        guard !effective.isEmpty else {
            throw VaultCryptoError.emptyPassword
        }
        guard (minimumAcceptedIterations...maximumAcceptedIterations).contains(iterations),
              (16...64).contains(salt.count) else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }

        var passwordBytes = Array(effective.utf8)
        var derivedBytes = [UInt8](repeating: 0, count: keyByteCount)
        defer {
            // Best-effort hygiene for owned byte buffers. (Swift `String`s cannot be reliably wiped.)
            for i in passwordBytes.indices { passwordBytes[i] = 0 }
            for i in derivedBytes.indices { derivedBytes[i] = 0 }
        }

        let passwordCount = passwordBytes.count
        let saltCount = salt.count
        let derivedCount = keyByteCount
        let status: Int32 = passwordBytes.withUnsafeBufferPointer { passwordBuffer in
            salt.withUnsafeBytes { saltRaw in
                derivedBytes.withUnsafeMutableBufferPointer { outBuffer in
                    guard let passwordBase = passwordBuffer.baseAddress,
                          let saltBase = saltRaw.bindMemory(to: UInt8.self).baseAddress,
                          let outBase = outBuffer.baseAddress else {
                        return Int32(kCCParamError)
                    }
                    return passwordBase.withMemoryRebound(to: CChar.self, capacity: passwordCount) { passwordChars in
                        CCKeyDerivationPBKDF(
                            CCPBKDFAlgorithm(kCCPBKDF2),
                            passwordChars,
                            passwordCount,
                            saltBase,
                            saltCount,
                            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                            UInt32(iterations),
                            outBase,
                            derivedCount
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw VaultCryptoError.keyDerivationFailed
        }
        return SymmetricKey(data: derivedBytes)
    }

    // MARK: - Local Hardware-Bound Vault Lifecycle (v2: PBKDF2 + Secure Enclave ECDH)

    static func createNewLocalVault(
        masterPassword: String,
        initialCards: [BankCard] = [],
        vaultID: UUID = UUID(),
        generation: UInt64 = 1,
        iterations: Int,
        hardwareKeys: any HardwareKeyProvider,
        rotateHardwareKey: Bool = true,
        deferKeyCommit: Bool = false
    ) throws -> (envelope: VaultEnvelope, key: SymmetricKey) {
        let normalized = normalizePassword(masterPassword)
        guard normalized.count >= minimumVaultPasswordLength else {
            throw VaultCryptoError.passwordTooShort(minimum: minimumVaultPasswordLength)
        }
        guard (minimumNewIterations...maximumAcceptedIterations).contains(iterations) else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }

        let salt = try generateSecureRandomBytes(count: saltByteCount)
        let hwFactor: (ephemeralPublicKey: Data, hardwareSecret: SymmetricKey)
        do {
            hwFactor = rotateHardwareKey
                ? try hardwareKeys.sealNewVaultFactor(salt: salt)
                : try hardwareKeys.sealExistingVaultFactor(salt: salt)
        } catch let hwErr as HardwareKeyError {
            throw VaultCryptoError.hardwareKeyUnavailable(hwErr.localizedDescription)
        }

        do {
            let dek = SymmetricKey(size: .bits256)
            let wrappedDEK = try wrapDEKV2(
                dek,
                magic: VaultEnvelope.localMagicV2,
                vaultID: vaultID,
                password: normalized,
                salt: salt,
                iterations: iterations,
                ephemeralPublicKey: hwFactor.ephemeralPublicKey,
                hardwareSecret: hwFactor.hardwareSecret
            )

            let encryptedPayload = try encryptPayloadV2(
                cards: initialCards,
                vaultID: vaultID,
                generation: generation,
                magic: VaultEnvelope.localMagicV2,
                iterations: iterations,
                salt: salt,
                ephemeralPublicKey: hwFactor.ephemeralPublicKey,
                wrappedDEK: wrappedDEK,
                using: dek
            )

            let envelope = VaultEnvelope(
                magic: VaultEnvelope.localMagicV2,
                version: VaultEnvelope.currentVersion,
                vaultID: vaultID,
                kdfIterations: iterations,
                salt: salt,
                ephemeralPublicKey: hwFactor.ephemeralPublicKey,
                wrappedDEK: wrappedDEK,
                encryptedPayload: encryptedPayload,
                updatedAt: Date()
            )
            if rotateHardwareKey && !deferKeyCommit {
                hardwareKeys.commitRotatedKey()
            }
            return (envelope, dek)
        } catch {
            if rotateHardwareKey {
                hardwareKeys.discardPendingKey()
            }
            throw error
        }
    }

    /// Unlocks a local vault (supports v2 Secure-Enclave-bound vaults and legacy v1 vaults for automatic upgrade).
    static func unlockLocalVaultWithPassword(
        envelope: VaultEnvelope,
        masterPassword: String,
        hardwareKeys: any HardwareKeyProvider,
        allowLegacyV1: Bool = true
    ) throws -> (payload: VaultPlaintextPayload, key: SymmetricKey, needsUpgradeToV2: Bool) {
        if envelope.magic == VaultEnvelope.backupMagicV2 {
            throw VaultCryptoError.domainMismatch
        }

        if envelope.magic == VaultEnvelope.legacyMagicV1 && envelope.version == VaultEnvelope.legacyVersionV1 {
            guard allowLegacyV1 else {
                throw VaultCryptoError.domainMismatch
            }
            let legacyUnlocked = try unlockLegacyV1(envelope: envelope, password: masterPassword)
            let needsUpgrade = true
            return (legacyUnlocked.payload, legacyUnlocked.key, needsUpgrade)
        }

        try validateV2Header(envelope, expectedDomain: .localVault)
        let dek = try unwrapLocalDEKV2(envelope: envelope, password: masterPassword, hardwareKeys: hardwareKeys)
        let payload = try decryptPayload(envelope: envelope, key: dek, expectedDomain: .localVault)
        let needsUpgrade = envelope.kdfIterations < minimumNewIterations
        return (payload, dek, needsUpgrade)
    }

    static func verifyLocalPassword(
        _ password: String,
        against envelope: VaultEnvelope,
        hardwareKeys: any HardwareKeyProvider
    ) -> Bool {
        if envelope.magic == VaultEnvelope.legacyMagicV1 && envelope.version == VaultEnvelope.legacyVersionV1 {
            return (try? unwrapLegacyDEKV1(envelope: envelope, password: password)) != nil
        }
        guard (try? validateV2Header(envelope, expectedDomain: .localVault)) != nil else {
            return false
        }
        return (try? unwrapLocalDEKV2(envelope: envelope, password: password, hardwareKeys: hardwareKeys)) != nil
    }

    /// Decrypts the payload using an already-unwrapped DEK (e.g. from Biometric Keychain).
    /// Authenticates the full v2 header AAD (including `SHA256(wrappedDEK)` and `vaultID`), defeating header/payload splicing!
    static func decryptPayload(
        envelope: VaultEnvelope,
        key: SymmetricKey,
        expectedDomain: VaultEnvelopeDomain = .localVault
    ) throws -> VaultPlaintextPayload {
        guard key.bitCount == keyByteCount * 8 else {
            throw VaultCryptoError.authenticationFailed
        }

        if envelope.magic == VaultEnvelope.legacyMagicV1 && envelope.version == VaultEnvelope.legacyVersionV1 {
            return try decryptLegacyPayloadV1(envelope: envelope, key: key)
        }

        try validateV2Header(envelope, expectedDomain: expectedDomain)
        guard let expectedVaultID = envelope.vaultID else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }

        let aad = makePayloadAADV2(
            magic: envelope.magic,
            version: envelope.version,
            vaultID: expectedVaultID,
            iterations: envelope.kdfIterations,
            salt: envelope.salt,
            ephemeralPublicKey: envelope.ephemeralPublicKey,
            wrappedDEK: envelope.wrappedDEK
        )

        var paddedPlaintext: Data
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: envelope.encryptedPayload)
            paddedPlaintext = try AES.GCM.open(sealedBox, using: key, authenticating: aad)
        } catch {
            throw VaultCryptoError.authenticationFailed
        }
        defer { paddedPlaintext.resetBytes(in: 0..<paddedPlaintext.count) }

        var unpaddedJSON = try unframePaddedPayloadV2(paddedPlaintext)
        defer { unpaddedJSON.resetBytes(in: 0..<unpaddedJSON.count) }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded: VaultPlaintextPayload
        do {
            decoded = try decoder.decode(VaultPlaintextPayload.self, from: unpaddedJSON)
        } catch {
            throw VaultCryptoError.corruptedPayload
        }

        guard decoded.vaultID == expectedVaultID else {
            throw VaultCryptoError.authenticationFailed
        }
        return decoded
    }

    static func resealLocalPayload(
        existingEnvelope: VaultEnvelope,
        key: SymmetricKey,
        cards: [BankCard],
        generation: UInt64
    ) throws -> VaultEnvelope {
        try validateV2Header(existingEnvelope, expectedDomain: .localVault)
        guard key.bitCount == keyByteCount * 8,
              let vaultID = existingEnvelope.vaultID,
              let ephPub = existingEnvelope.ephemeralPublicKey else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }

        let encryptedPayload = try encryptPayloadV2(
            cards: cards,
            vaultID: vaultID,
            generation: generation,
            magic: existingEnvelope.magic,
            iterations: existingEnvelope.kdfIterations,
            salt: existingEnvelope.salt,
            ephemeralPublicKey: ephPub,
            wrappedDEK: existingEnvelope.wrappedDEK,
            using: key
        )

        return VaultEnvelope(
            magic: existingEnvelope.magic,
            version: existingEnvelope.version,
            vaultID: vaultID,
            kdfIterations: existingEnvelope.kdfIterations,
            salt: existingEnvelope.salt,
            ephemeralPublicKey: ephPub,
            wrappedDEK: existingEnvelope.wrappedDEK,
            encryptedPayload: encryptedPayload,
            updatedAt: Date()
        )
    }

    // MARK: - Portable Encrypted Backups (v2: Domain-Separated, 4 KB Padded, Recovery-Passphrase Protected)

    static func exportEncryptedBackup(
        cards: [BankCard],
        backupPassword: String,
        iterations: Int
    ) throws -> Data {
        let normalized = normalizePassword(backupPassword)
        guard normalized.count >= minimumBackupPasswordLength else {
            throw VaultCryptoError.passwordTooShort(minimum: minimumBackupPasswordLength)
        }
        guard (minimumNewIterations...maximumAcceptedIterations).contains(iterations) else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }

        let backupID = UUID()
        let salt = try generateSecureRandomBytes(count: saltByteCount)
        let dek = SymmetricKey(size: .bits256)
        let wrappedDEK = try wrapDEKV2(
            dek,
            magic: VaultEnvelope.backupMagicV2,
            vaultID: backupID,
            password: normalized,
            salt: salt,
            iterations: iterations,
            ephemeralPublicKey: nil,
            hardwareSecret: nil
        )
        let encryptedPayload = try encryptPayloadV2(
            cards: cards,
            vaultID: backupID,
            generation: 1,
            magic: VaultEnvelope.backupMagicV2,
            iterations: iterations,
            salt: salt,
            ephemeralPublicKey: nil,
            wrappedDEK: wrappedDEK,
            using: dek
        )

        let envelope = VaultEnvelope(
            magic: VaultEnvelope.backupMagicV2,
            version: VaultEnvelope.currentVersion,
            vaultID: backupID,
            kdfIterations: iterations,
            salt: salt,
            ephemeralPublicKey: nil,
            wrappedDEK: wrappedDEK,
            encryptedPayload: encryptedPayload,
            updatedAt: Date()
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(envelope)
    }

    static func importEncryptedBackup(
        data: Data,
        backupPassword: String
    ) throws -> [BankCard] {
        guard data.count <= maximumPayloadByteCount * 2 else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let envelope: VaultEnvelope
        do {
            envelope = try decoder.decode(VaultEnvelope.self, from: data)
        } catch {
            throw VaultCryptoError.invalidEnvelopeFormat
        }

        // Strict domain separation: reject local vault files disguised as backups.
        if envelope.magic == VaultEnvelope.localMagicV2 {
            throw VaultCryptoError.domainMismatch
        }

        // Backward compatibility for v1 `.cardvault` backups exported before v2.0.
        if envelope.magic == VaultEnvelope.legacyMagicV1 && envelope.version == VaultEnvelope.legacyVersionV1 {
            let unlocked = try unlockLegacyV1(envelope: envelope, password: backupPassword)
            return unlocked.payload.cards
        }

        try validateV2Header(envelope, expectedDomain: .exportedBackup)
        let dek = try unwrapBackupDEKV2(envelope: envelope, password: backupPassword)
        let payload = try decryptPayload(envelope: envelope, key: dek, expectedDomain: .exportedBackup)
        return payload.cards
    }

    // MARK: - V2 Cryptographic Internals (Length-Prefixed AAD + Dual-Factor HKDF + 4 KB Padding)

    private static func wrapDEKV2(
        _ dek: SymmetricKey,
        magic: String,
        vaultID: UUID,
        password: String,
        salt: Data,
        iterations: Int,
        ephemeralPublicKey: Data?,
        hardwareSecret: SymmetricKey?
    ) throws -> Data {
        let wrapAAD = makeWrapAADV2(
            magic: magic,
            version: VaultEnvelope.currentVersion,
            vaultID: vaultID,
            iterations: iterations,
            salt: salt,
            ephemeralPublicKey: ephemeralPublicKey
        )
        let kek = try deriveCompositeKEKV2(
            password: password,
            salt: salt,
            iterations: iterations,
            hardwareSecret: hardwareSecret,
            wrapAAD: wrapAAD
        )

        var dekBytes = dek.withUnsafeBytes { Data($0) }
        defer { dekBytes.resetBytes(in: 0..<dekBytes.count) }

        let sealed = try AES.GCM.seal(dekBytes, using: kek, nonce: AES.GCM.Nonce(), authenticating: wrapAAD)
        guard let combined = sealed.combined else {
            throw VaultCryptoError.keyDerivationFailed
        }
        return combined
    }

    private static func unwrapLocalDEKV2(
        envelope: VaultEnvelope,
        password: String,
        hardwareKeys: any HardwareKeyProvider
    ) throws -> SymmetricKey {
        guard let vaultID = envelope.vaultID,
              let ephPub = envelope.ephemeralPublicKey else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }
        let normalized = normalizePassword(password)
        guard !normalized.isEmpty else {
            throw VaultCryptoError.emptyPassword
        }

        // Always run PBKDF2 even if hardware key lookup would fail, preventing timing side-channels on password length.
        let wrapAAD = makeWrapAADV2(
            magic: envelope.magic,
            version: envelope.version,
            vaultID: vaultID,
            iterations: envelope.kdfIterations,
            salt: envelope.salt,
            ephemeralPublicKey: ephPub
        )
        let pwdKey = try derivePasswordKey(
            password: normalized,
            salt: envelope.salt,
            iterations: envelope.kdfIterations,
            normalize: false
        )

        var primaryHardwareError: HardwareKeyError?
        if let activeSecret = try? hardwareKeys.unsealVaultFactor(ephemeralPublicKey: ephPub, salt: envelope.salt) {
            let activeKEK = combinePasswordAndHardwareKey(
                passwordKey: pwdKey,
                hardwareSecret: activeSecret,
                salt: envelope.salt,
                wrapAAD: wrapAAD
            )
            if let dek = try? openWrappedDEK(envelope.wrappedDEK, using: activeKEK, authenticating: wrapAAD) {
                if hardwareKeys.hasPendingKey {
                    hardwareKeys.discardPendingKey()
                }
                return dek
            }
        } else {
            do {
                _ = try hardwareKeys.unsealVaultFactor(ephemeralPublicKey: ephPub, salt: envelope.salt)
            } catch let hwErr as HardwareKeyError {
                primaryHardwareError = hwErr
            }
        }

        // Two-phase commit crash recovery: if power failed after atomic file write but before key commit, try staged pending key.
        if hardwareKeys.hasPendingKey,
           let pendingSecret = try? hardwareKeys.unsealPendingVaultFactor(ephemeralPublicKey: ephPub, salt: envelope.salt) {
            let pendingKEK = combinePasswordAndHardwareKey(
                passwordKey: pwdKey,
                hardwareSecret: pendingSecret,
                salt: envelope.salt,
                wrapAAD: wrapAAD
            )
            if let dek = try? openWrappedDEK(envelope.wrappedDEK, using: pendingKEK, authenticating: wrapAAD) {
                hardwareKeys.commitRotatedKey()
                return dek
            }
        }

        if let hwErr = primaryHardwareError {
            throw VaultCryptoError.hardwareKeyUnavailable(hwErr.localizedDescription)
        }
        throw VaultCryptoError.authenticationFailed
    }

    private static func unwrapBackupDEKV2(
        envelope: VaultEnvelope,
        password: String
    ) throws -> SymmetricKey {
        guard let vaultID = envelope.vaultID else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }
        let normalized = normalizePassword(password)
        guard !normalized.isEmpty else {
            throw VaultCryptoError.emptyPassword
        }
        let wrapAAD = makeWrapAADV2(
            magic: envelope.magic,
            version: envelope.version,
            vaultID: vaultID,
            iterations: envelope.kdfIterations,
            salt: envelope.salt,
            ephemeralPublicKey: nil
        )
        let kek = try deriveCompositeKEKV2(
            password: normalized,
            salt: envelope.salt,
            iterations: envelope.kdfIterations,
            hardwareSecret: nil,
            wrapAAD: wrapAAD
        )
        return try openWrappedDEK(envelope.wrappedDEK, using: kek, authenticating: wrapAAD)
    }

    private static func deriveCompositeKEKV2(
        password: String,
        salt: Data,
        iterations: Int,
        hardwareSecret: SymmetricKey?,
        wrapAAD: Data
    ) throws -> SymmetricKey {
        let pwdKey = try derivePasswordKey(password: password, salt: salt, iterations: iterations, normalize: true)
        if let hardwareSecret {
            return combinePasswordAndHardwareKey(
                passwordKey: pwdKey,
                hardwareSecret: hardwareSecret,
                salt: salt,
                wrapAAD: wrapAAD
            )
        } else {
            var info = Data()
            info.append(backupKEKInfoV2)
            info.append(wrapAAD)
            return HKDF<SHA256>.deriveKey(
                inputKeyMaterial: pwdKey,
                salt: salt,
                info: info,
                outputByteCount: keyByteCount
            )
        }
    }

    private static func combinePasswordAndHardwareKey(
        passwordKey: SymmetricKey,
        hardwareSecret: SymmetricKey,
        salt: Data,
        wrapAAD: Data
    ) -> SymmetricKey {
        var combinedIKM = Data(capacity: keyByteCount * 2)
        passwordKey.withUnsafeBytes { combinedIKM.append(contentsOf: $0) }
        hardwareSecret.withUnsafeBytes { combinedIKM.append(contentsOf: $0) }
        defer { combinedIKM.resetBytes(in: 0..<combinedIKM.count) }

        var info = Data()
        info.append(kekCombineInfoV2)
        info.append(wrapAAD)

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: combinedIKM),
            salt: salt,
            info: info,
            outputByteCount: keyByteCount
        )
    }

    private static func openWrappedDEK(
        _ wrappedDEK: Data,
        using kek: SymmetricKey,
        authenticating wrapAAD: Data
    ) throws -> SymmetricKey {
        var dekBytes: Data
        do {
            let box = try AES.GCM.SealedBox(combined: wrappedDEK)
            dekBytes = try AES.GCM.open(box, using: kek, authenticating: wrapAAD)
        } catch {
            throw VaultCryptoError.authenticationFailed
        }
        defer { dekBytes.resetBytes(in: 0..<dekBytes.count) }

        guard dekBytes.count == keyByteCount else {
            throw VaultCryptoError.authenticationFailed
        }
        return SymmetricKey(data: dekBytes)
    }

    private static func encryptPayloadV2(
        cards: [BankCard],
        vaultID: UUID,
        generation: UInt64,
        magic: String,
        iterations: Int,
        salt: Data,
        ephemeralPublicKey: Data?,
        wrappedDEK: Data,
        using key: SymmetricKey
    ) throws -> Data {
        let payload = VaultPlaintextPayload(
            vaultID: vaultID,
            generation: generation,
            cards: cards,
            updatedAt: Date()
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        var jsonData = try encoder.encode(payload)
        defer { jsonData.resetBytes(in: 0..<jsonData.count) }

        var framedData = try frameAndPadPayloadV2(jsonData)
        defer { framedData.resetBytes(in: 0..<framedData.count) }

        let aad = makePayloadAADV2(
            magic: magic,
            version: VaultEnvelope.currentVersion,
            vaultID: vaultID,
            iterations: iterations,
            salt: salt,
            ephemeralPublicKey: ephemeralPublicKey,
            wrappedDEK: wrappedDEK
        )

        let sealedBox = try AES.GCM.seal(
            framedData,
            using: key,
            nonce: AES.GCM.Nonce(),
            authenticating: aad
        )
        guard let combined = sealedBox.combined else {
            throw VaultCryptoError.keyDerivationFailed
        }
        return combined
    }

    /// Binary frame: `[4-byte big-endian JSON byte length][JSON bytes][0x00 padding to 4096-byte multiple]`.
    private static func frameAndPadPayloadV2(_ json: Data) throws -> Data {
        guard json.count <= maximumPayloadByteCount - payloadPaddingBlockSize else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }
        let headerAndBody = 4 + json.count
        let remainder = headerAndBody % payloadPaddingBlockSize
        let totalLength = remainder == 0 ? headerAndBody : (headerAndBody + (payloadPaddingBlockSize - remainder))

        var buffer = Data(count: totalLength)
        var bigEndianLen = UInt32(json.count).bigEndian
        withUnsafeBytes(of: &bigEndianLen) { lenBytes in
            buffer.replaceSubrange(0..<4, with: lenBytes)
        }
        buffer.replaceSubrange(4..<(4 + json.count), with: json)
        return buffer
    }

    private static func unframePaddedPayloadV2(_ padded: Data) throws -> Data {
        guard padded.count >= payloadPaddingBlockSize,
              padded.count % payloadPaddingBlockSize == 0 else {
            throw VaultCryptoError.corruptedPayload
        }
        let length: UInt32 = padded.prefix(4).withUnsafeBytes { raw in
            var value: UInt32 = 0
            _ = withUnsafeMutableBytes(of: &value) { dst in
                raw.copyBytes(to: dst)
            }
            return UInt32(bigEndian: value)
        }
        let jsonCount = Int(length)
        guard jsonCount >= 2, 4 + jsonCount <= padded.count else {
            throw VaultCryptoError.corruptedPayload
        }
        // Verify zero padding integrity so trailing padding bytes cannot be used as covert channels.
        for padByte in padded[(4 + jsonCount)..<padded.count] where padByte != 0 {
            throw VaultCryptoError.corruptedPayload
        }
        return Data(padded[4..<(4 + jsonCount)])
    }

    /// Canonical length-prefixed AAD (impossible to forge collisions across field boundaries).
    private static func makeWrapAADV2(
        magic: String,
        version: Int,
        vaultID: UUID,
        iterations: Int,
        salt: Data,
        ephemeralPublicKey: Data?
    ) -> Data {
        var out = Data("CARDSE_WRAP_AAD_V2".utf8)
        appendLengthPrefixed(&out, Data(magic.utf8))
        appendUInt64(&out, UInt64(version))
        var uuidBytes = vaultID.uuid
        withUnsafeBytes(of: &uuidBytes) { appendLengthPrefixed(&out, Data($0)) }
        appendUInt64(&out, UInt64(iterations))
        appendLengthPrefixed(&out, salt)
        appendLengthPrefixed(&out, ephemeralPublicKey ?? Data())
        return out
    }

    private static func makePayloadAADV2(
        magic: String,
        version: Int,
        vaultID: UUID,
        iterations: Int,
        salt: Data,
        ephemeralPublicKey: Data?,
        wrappedDEK: Data
    ) -> Data {
        var out = Data("CARDSE_PAYLOAD_AAD_V2".utf8)
        appendLengthPrefixed(&out, Data(magic.utf8))
        appendUInt64(&out, UInt64(version))
        var uuidBytes = vaultID.uuid
        withUnsafeBytes(of: &uuidBytes) { appendLengthPrefixed(&out, Data($0)) }
        appendUInt64(&out, UInt64(iterations))
        appendLengthPrefixed(&out, salt)
        appendLengthPrefixed(&out, ephemeralPublicKey ?? Data())
        let wrappedHash = Data(SHA256.hash(data: wrappedDEK))
        appendLengthPrefixed(&out, wrappedHash)
        return out
    }

    private static func appendUInt64(_ target: inout Data, _ value: UInt64) {
        var be = value.bigEndian
        withUnsafeBytes(of: &be) { target.append(contentsOf: $0) }
    }

    private static func appendLengthPrefixed(_ target: inout Data, _ field: Data) {
        appendUInt64(&target, UInt64(field.count))
        target.append(field)
    }

    private static func validateV2Header(
        _ envelope: VaultEnvelope,
        expectedDomain: VaultEnvelopeDomain
    ) throws {
        let expectedMagic: String
        switch expectedDomain {
        case .localVault:
            expectedMagic = VaultEnvelope.localMagicV2
        case .exportedBackup:
            expectedMagic = VaultEnvelope.backupMagicV2
        }

        if (expectedDomain == .localVault && envelope.magic == VaultEnvelope.backupMagicV2)
            || (expectedDomain == .exportedBackup && envelope.magic == VaultEnvelope.localMagicV2) {
            throw VaultCryptoError.domainMismatch
        }

        guard envelope.magic == expectedMagic,
              envelope.version == VaultEnvelope.currentVersion,
              envelope.vaultID != nil,
              (minimumAcceptedIterations...maximumAcceptedIterations).contains(envelope.kdfIterations),
              envelope.salt.count == saltByteCount,
              envelope.wrappedDEK.count == wrappedDEKByteCount,
              (minimumPayloadByteCount + payloadPaddingBlockSize...maximumPayloadByteCount).contains(envelope.encryptedPayload.count) else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }

        switch expectedDomain {
        case .localVault:
            guard envelope.ephemeralPublicKey?.count == ephemeralPublicKeyByteCount else {
                throw VaultCryptoError.invalidEnvelopeFormat
            }
        case .exportedBackup:
            guard envelope.ephemeralPublicKey == nil else {
                throw VaultCryptoError.invalidEnvelopeFormat
            }
        }
    }

    // MARK: - Legacy V1 Read-Only Support (Seamless Migration from CardVault v1.0 / v1.1)

    private static func unlockLegacyV1(
        envelope: VaultEnvelope,
        password: String
    ) throws -> (payload: VaultPlaintextPayload, key: SymmetricKey) {
        let key = try unwrapLegacyDEKV1(envelope: envelope, password: password)
        let payload = try decryptLegacyPayloadV1(envelope: envelope, key: key)
        return (payload, key)
    }

    private static func unwrapLegacyDEKV1(envelope: VaultEnvelope, password: String) throws -> SymmetricKey {
        guard envelope.magic == VaultEnvelope.legacyMagicV1,
              envelope.version == VaultEnvelope.legacyVersionV1,
              (minimumAcceptedIterations...maximumAcceptedIterations).contains(envelope.kdfIterations),
              (16...64).contains(envelope.salt.count),
              envelope.wrappedDEK.count == wrappedDEKByteCount,
              (minimumPayloadByteCount...maximumPayloadByteCount).contains(envelope.encryptedPayload.count) else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }
        guard !password.isEmpty else {
            throw VaultCryptoError.emptyPassword
        }

        var wrapAAD = Data("\(envelope.magic)|v\(envelope.version)|iter=\(envelope.kdfIterations)|".utf8)
        wrapAAD.append(envelope.salt)

        // Try NFC first; if password contained unnormalized NFD in v1, try raw string once.
        let candidates = normalizePassword(password) == password
            ? [password]
            : [normalizePassword(password), password]

        for candidate in candidates {
            let kek = try derivePasswordKey(
                password: candidate,
                salt: envelope.salt,
                iterations: envelope.kdfIterations,
                normalize: false
            )
            if let key = try? openWrappedDEK(envelope.wrappedDEK, using: kek, authenticating: wrapAAD) {
                return key
            }
        }
        throw VaultCryptoError.authenticationFailed
    }

    private static func decryptLegacyPayloadV1(
        envelope: VaultEnvelope,
        key: SymmetricKey
    ) throws -> VaultPlaintextPayload {
        guard envelope.magic == VaultEnvelope.legacyMagicV1,
              envelope.version == VaultEnvelope.legacyVersionV1,
              (minimumPayloadByteCount...maximumPayloadByteCount).contains(envelope.encryptedPayload.count) else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }

        var decryptedJSON: Data
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: envelope.encryptedPayload)
            decryptedJSON = try AES.GCM.open(sealedBox, using: key, authenticating: legacyPayloadAADV1)
        } catch {
            throw VaultCryptoError.authenticationFailed
        }
        defer { decryptedJSON.resetBytes(in: 0..<decryptedJSON.count) }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(VaultPlaintextPayload.self, from: decryptedJSON)
        } catch {
            throw VaultCryptoError.corruptedPayload
        }
    }
}
