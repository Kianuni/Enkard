import CommonCrypto
import CryptoKit
import Darwin
import Foundation
import Security

enum VaultCryptoError: LocalizedError, Equatable {
    case emptyPassword
    case passwordTooShort(minimum: Int)
    case passwordTooLong(maximum: Int)
    case weakPassword(String)
    case randomGenerationFailed
    case keyDerivationFailed
    case invalidEnvelopeFormat
    case domainMismatch
    case hardwareKeyUnavailable(String)
    case storageTampered(String)
    case authenticationFailed
    case corruptedPayload

    var errorDescription: String? {
        switch self {
        case .emptyPassword:
            return tr("请输入密码", "Please enter a password")
        case .passwordTooShort(let minimum):
            return tr(
                "密码长度至少需要 \(minimum) 位",
                "Password must be at least \(minimum) characters"
            )
        case .passwordTooLong(let maximum):
            return tr(
                "密码长度不能超过 \(maximum) 位",
                "Password cannot exceed \(maximum) characters"
            )
        case .weakPassword(let message):
            return message
        case .randomGenerationFailed:
            return tr("安全随机数生成失败", "Secure random number generation failed")
        case .keyDerivationFailed:
            return tr("密钥派生失败", "Key derivation failed")
        case .invalidEnvelopeFormat:
            return tr(
                "加密文件格式无效、参数超出安全范围或版本不受支持",
                "Invalid encrypted file format, unsafe parameters, or unsupported version"
            )
        case .domainMismatch:
            return tr(
                "文件用途不匹配：本地硬件绑定库与跨设备备份文件禁止混用",
                "File domain mismatch: hardware-bound local vaults and portable backups cannot be interchanged"
            )
        case .hardwareKeyUnavailable(let reason):
            return reason
        case .storageTampered(let reason):
            return reason
        case .authenticationFailed:
            return tr("密码错误，或加密数据已被篡改", "Incorrect password or encrypted data has been tampered with")
        case .corruptedPayload:
            return tr("保险库数据解析失败", "Failed to parse vault payload")
        }
    }
}

/// Guaranteed non-elidable memory zeroization backed by Darwin C11 `memset_s`
/// (immune to LLVM `-O` Dead-Store Elimination, unlike manual index loops or sliced `Data.resetBytes`).
enum SecureZero {
    @inline(__always)
    static func wipe(_ bytes: inout [UInt8]) {
        guard !bytes.isEmpty else { return }
        let count = bytes.count
        bytes.withUnsafeMutableBytes { raw in
            if let base = raw.baseAddress {
                _ = memset_s(base, count, 0, count)
            }
        }
    }

    @inline(__always)
    static func wipe(_ data: inout Data) {
        guard !data.isEmpty else { return }
        let count = data.count
        data.withUnsafeMutableBytes { raw in
            if let base = raw.baseAddress {
                _ = memset_s(base, count, 0, count)
            }
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
    static let maximumPasswordLength = 256
    static let maximumPasswordUTF8Bytes = 1024

    private static let wrappedDEKByteCount = 12 + 32 + 16 // nonce + key + tag
    private static let minimumPayloadByteCount = 12 + 16
    private static let maximumPayloadByteCount = 20 * 1024 * 1024
    /// Upper bound for a user-picked backup file (checked BEFORE the file is loaded into memory).
    static let maximumBackupFileByteCount = 2 * maximumPayloadByteCount
    /// Upper bound for the internal `vault.cardse` file (blocks sparse-file OOM bombs from sandbox tampering).
    static let maximumVaultFileByteCount = 2 * maximumPayloadByteCount

    /// Reads a user-selected backup file with strict POSIX non-symlink (`lstat` + `O_NOFOLLOW`),
    /// regular-file (`S_IFREG` + `O_NONBLOCK`), inode-identity, and hard byte-size bounds,
    /// blocking symlink traversal, FIFO hangs, and sparse-file OOM bombs before allocating memory.
    static func readBackupFileBounded(at url: URL) throws -> Data {
        let path = url.path
        var lst = stat()
        guard Darwin.lstat(path, &lst) == 0 else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }
        guard (lst.st_mode & S_IFMT) == S_IFREG,
              lst.st_size > 0,
              lst.st_size <= off_t(maximumBackupFileByteCount) else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }

        let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }
        defer { _ = Darwin.close(fd) }

        switch SafeVaultFileIO.readBoundedFromRegularFD(
            fd: fd,
            expectedStat: lst,
            maxBytes: maximumBackupFileByteCount
        ) {
        case .data(let data):
            return data
        case .protectedDataUnavailable, .tampered, .invalidSize:
            throw VaultCryptoError.invalidEnvelopeFormat
        }
    }
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
        guard password.utf8.count <= maximumPasswordUTF8Bytes * 4 else {
            throw VaultCryptoError.passwordTooLong(maximum: maximumPasswordLength)
        }
        let effective = normalize ? normalizePassword(password) : password
        guard !effective.isEmpty else {
            throw VaultCryptoError.emptyPassword
        }
        guard effective.utf8.count <= maximumPasswordUTF8Bytes else {
            throw VaultCryptoError.passwordTooLong(maximum: maximumPasswordLength)
        }
        guard (minimumAcceptedIterations...maximumAcceptedIterations).contains(iterations),
              (16...64).contains(salt.count) else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }

        var passwordBytes = Array(effective.utf8)
        var derivedBytes = [UInt8](repeating: 0, count: keyByteCount)
        defer {
            // Non-elidable C11 `memset_s` zeroization of owned byte buffers.
            SecureZero.wipe(&passwordBytes)
            SecureZero.wipe(&derivedBytes)
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
        guard masterPassword.utf8.count <= maximumPasswordUTF8Bytes * 4 else {
            throw VaultCryptoError.passwordTooLong(maximum: maximumPasswordLength)
        }
        let normalized = normalizePassword(masterPassword)
        guard normalized.count >= minimumVaultPasswordLength else {
            throw VaultCryptoError.passwordTooShort(minimum: minimumVaultPasswordLength)
        }
        guard normalized.count <= maximumPasswordLength else {
            throw VaultCryptoError.passwordTooLong(maximum: maximumPasswordLength)
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

    /// Distinguishes genuine password mismatch (`authenticationFailed`) from transient Secure Enclave / Keychain
    /// unavailability (`hardwareKeyUnavailable`) so re-auth never counts hardware faults toward permanent vault wipe.
    static func verifyLocalPasswordThrowing(
        _ password: String,
        against envelope: VaultEnvelope,
        hardwareKeys: any HardwareKeyProvider
    ) throws {
        if envelope.magic == VaultEnvelope.legacyMagicV1 && envelope.version == VaultEnvelope.legacyVersionV1 {
            _ = try unwrapLegacyDEKV1(envelope: envelope, password: password)
            return
        }
        try validateV2Header(envelope, expectedDomain: .localVault)
        _ = try unwrapLocalDEKV2(envelope: envelope, password: password, hardwareKeys: hardwareKeys)
    }

    static func verifyLocalPassword(
        _ password: String,
        against envelope: VaultEnvelope,
        hardwareKeys: any HardwareKeyProvider
    ) -> Bool {
        (try? verifyLocalPasswordThrowing(password, against: envelope, hardwareKeys: hardwareKeys)) != nil
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
        defer { SecureZero.wipe(&paddedPlaintext) }

        // Copy into an independent uniquely-owned buffer (`Data(bytes:count:)`) rather than slicing `paddedPlaintext`,
        // avoiding `_DataStorage` `refCount == 2` Copy-on-Write duplication during `defer` zeroization!
        let jsonRange = try unframePaddedPayloadRangeV2(paddedPlaintext)
        var unpaddedJSON: Data = paddedPlaintext.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return Data() }
            return Data(bytes: base.advanced(by: jsonRange.lowerBound), count: jsonRange.count)
        }
        defer { SecureZero.wipe(&unpaddedJSON) }

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
        guard decoded.generation < VaultPlaintextPayload.maximumValidGeneration else {
            throw VaultCryptoError.corruptedPayload
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
        guard backupPassword.utf8.count <= maximumPasswordUTF8Bytes * 4 else {
            throw VaultCryptoError.passwordTooLong(maximum: maximumPasswordLength)
        }
        let normalized = normalizePassword(backupPassword)
        guard normalized.count >= minimumBackupPasswordLength else {
            throw VaultCryptoError.passwordTooShort(minimum: minimumBackupPasswordLength)
        }
        guard normalized.count <= maximumPasswordLength else {
            throw VaultCryptoError.passwordTooLong(maximum: maximumPasswordLength)
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
        guard data.count <= maximumBackupFileByteCount else {
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
        defer { SecureZero.wipe(&dekBytes) }

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
        guard password.utf8.count <= maximumPasswordUTF8Bytes * 4 else {
            throw VaultCryptoError.passwordTooLong(maximum: maximumPasswordLength)
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
        guard password.utf8.count <= maximumPasswordUTF8Bytes * 4 else {
            throw VaultCryptoError.passwordTooLong(maximum: maximumPasswordLength)
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
        defer { SecureZero.wipe(&combinedIKM) }

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
        defer { SecureZero.wipe(&dekBytes) }

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
        guard generation < VaultPlaintextPayload.maximumValidGeneration else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }
        let payload = VaultPlaintextPayload(
            vaultID: vaultID,
            generation: generation,
            cards: cards,
            updatedAt: Date()
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        var jsonData = try encoder.encode(payload)
        defer { SecureZero.wipe(&jsonData) }

        var framedData = try frameAndPadPayloadV2(jsonData)
        defer { SecureZero.wipe(&framedData) }

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

    private static func unframePaddedPayloadRangeV2(_ padded: Data) throws -> Range<Int> {
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
        return 4..<(4 + jsonCount)
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
        guard password.utf8.count <= maximumPasswordUTF8Bytes * 4 else {
            throw VaultCryptoError.passwordTooLong(maximum: maximumPasswordLength)
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
        defer { SecureZero.wipe(&decryptedJSON) }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded: VaultPlaintextPayload
        do {
            decoded = try decoder.decode(VaultPlaintextPayload.self, from: decryptedJSON)
        } catch {
            throw VaultCryptoError.corruptedPayload
        }
        guard decoded.generation < VaultPlaintextPayload.maximumValidGeneration else {
            throw VaultCryptoError.corruptedPayload
        }
        return decoded
    }
}

/// POSIX-hardened filesystem boundary for Enkard's internal container storage (`CardSeStorage` / `vault.cardse`).
/// Defends against cross-container sandbox-token abuse (e.g. `containermanagerd` symlink injection, FIFO blocking
/// pipes, directory-swap TOCTOU races, and multi-GB sparse-file OOM bombs) while preserving iOS `NSFileProtectionComplete`
/// lock-screen semantics (`EPERM` / `EACCES` when Class A keys are evicted).
enum SafeVaultFileIO {
    enum LocalVaultReadResult: Equatable {
        case notFound
        case protectedDataUnavailable
        case tampered(String)
        case data(Data)
    }

    enum ExistingVaultNodeStatus: Equatable {
        case absent
        case regularFileExists
        case protectedDataUnavailable
        case tampered(String)
    }

    enum BoundedFDReadResult {
        case data(Data)
        case protectedDataUnavailable
        case tampered
        case invalidSize
    }

    private static func isValidSinglePathComponent(_ name: String) -> Bool {
        !name.isEmpty && name != "." && name != ".." && !name.contains("/") && !name.contains("\0")
    }

    static func excludeFromAllBackupsIfNonSymlink(_ url: URL) {
        var st = stat()
        guard Darwin.lstat(url.path, &st) == 0,
              (st.st_mode & S_IFMT) != S_IFLNK else {
            return
        }
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        var mutableURL = url
        try? mutableURL.setResourceValues(resourceValues)
    }

    static func readBoundedFromRegularFD(
        fd: Int32,
        expectedStat: stat,
        maxBytes: Int
    ) -> BoundedFDReadResult {
        var fst = stat()
        guard Darwin.fstat(fd, &fst) == 0 else {
            let err = errno
            if err == EPERM || err == EACCES {
                return .protectedDataUnavailable
            }
            return .tampered
        }
        guard (fst.st_mode & S_IFMT) == S_IFREG,
              fst.st_dev == expectedStat.st_dev,
              fst.st_ino == expectedStat.st_ino else {
            return .tampered
        }
        guard fst.st_size > 0, fst.st_size <= off_t(maxBytes) else {
            return .invalidSize
        }

        var data = Data()
        data.reserveCapacity(Int(fst.st_size))
        var chunk = [UInt8](repeating: 0, count: 65_536)

        while true {
            let bytesRead = Darwin.read(fd, &chunk, chunk.count)
            if bytesRead < 0 {
                let err = errno
                if err == EINTR { continue }
                if err == EPERM || err == EACCES {
                    SecureZero.wipe(&data)
                    return .protectedDataUnavailable
                }
                SecureZero.wipe(&data)
                return .tampered
            }
            if bytesRead == 0 {
                break
            }
            data.append(chunk, count: bytesRead)
            if data.count > maxBytes {
                SecureZero.wipe(&data)
                return .invalidSize
            }
        }

        guard !data.isEmpty, data.count <= maxBytes else {
            return .invalidSize
        }
        return .data(data)
    }

    /// Ensures `directoryURL` and any verified container ancestors are genuine directories (`S_IFDIR`, never `S_IFLNK`),
    /// creating missing directories with `FileProtectionType.complete` and backup exclusion.
    static func ensureSafeDirectory(
        at directoryURL: URL,
        ancestorDirectoriesToVerify: [URL]
    ) throws {
        for ancestor in ancestorDirectoriesToVerify {
            var ast = stat()
            if Darwin.lstat(ancestor.path, &ast) == 0 {
                let mode = ast.st_mode & S_IFMT
                if mode == S_IFLNK {
                    throw VaultCryptoError.storageTampered(tr(
                        "安全告警：检测到沙盒存储父目录被植入软链接（Symlink），疑似越界篡改，已立即拒绝访问！",
                        "Security Alert: Symbolic link detected on sandbox parent directory (possible tampering). Access denied."
                    ))
                }
                if mode != S_IFDIR {
                    throw VaultCryptoError.storageTampered(tr(
                        "安全告警：沙盒存储父路径不是合法目录，已立即阻断访问！",
                        "Security Alert: Sandbox parent path is not a valid directory. Access blocked."
                    ))
                }
            } else if errno == ENOENT {
                try FileManager.default.createDirectory(at: ancestor, withIntermediateDirectories: true)
                guard Darwin.lstat(ancestor.path, &ast) == 0,
                      (ast.st_mode & S_IFMT) == S_IFDIR else {
                    throw VaultCryptoError.storageTampered(tr(
                        "安全告警：沙盒父目录创建后校验异常，已立即阻断访问！",
                        "Security Alert: Sandbox parent directory verification failed after creation. Access blocked."
                    ))
                }
            } else {
                let err = errno
                throw VaultCryptoError.hardwareKeyUnavailable(tr(
                    "沙盒存储父目录暂不可访问（POSIX errno \(err)），请确认设备处于解锁状态",
                    "Sandbox parent directory unavailable (POSIX errno \(err)). Unlock your device and try again."
                ))
            }
        }

        let parentURL = directoryURL.deletingLastPathComponent()
        var pst = stat()
        if Darwin.lstat(parentURL.path, &pst) == 0, (pst.st_mode & S_IFMT) != S_IFDIR {
            throw VaultCryptoError.storageTampered(tr(
                "安全告警：检测到加密存储上级路径被替换为软链接或非目录节点，已拒绝访问！",
                "Security Alert: Encrypted storage parent path was replaced by a symlink or non-directory node. Access denied."
            ))
        }

        var dst = stat()
        if Darwin.lstat(directoryURL.path, &dst) == 0 {
            let mode = dst.st_mode & S_IFMT
            if mode == S_IFLNK {
                throw VaultCryptoError.storageTampered(tr(
                    "安全告警：检测到加密存储目录被替换为软链接（Symlink），疑似沙盒越界篡改，已立即拒绝访问！",
                    "Security Alert: Encrypted storage directory was replaced by a symlink (possible tampering). Access denied."
                ))
            }
            if mode != S_IFDIR {
                throw VaultCryptoError.storageTampered(tr(
                    "安全告警：加密存储路径不是合法目录（检测到异常特殊节点），已拒绝访问！",
                    "Security Alert: Encrypted storage path is not a valid directory. Access denied."
                ))
            }
        } else if errno == ENOENT {
            try FileManager.default.createDirectory(
                at: directoryURL,
                withIntermediateDirectories: true,
                attributes: [.protectionKey: FileProtectionType.complete]
            )
            guard Darwin.lstat(directoryURL.path, &dst) == 0,
                  (dst.st_mode & S_IFMT) == S_IFDIR else {
                throw VaultCryptoError.storageTampered(tr(
                    "安全告警：加密存储目录创建后元数据校验失败，已立即阻断！",
                    "Security Alert: Encrypted storage directory metadata verification failed after creation."
                ))
            }
        } else {
            let err = errno
            throw VaultCryptoError.hardwareKeyUnavailable(tr(
                "加密存储目录暂不可访问（POSIX errno \(err)），请确认设备处于解锁状态",
                "Encrypted storage directory unavailable (POSIX errno \(err)). Unlock your device and try again."
            ))
        }

        let dirFD = Darwin.open(directoryURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dirFD >= 0 else {
            let err = errno
            if err == ELOOP || err == ENOTDIR {
                throw VaultCryptoError.storageTampered(tr(
                    "安全告警：检测到加密存储目录软链接或类型异常，已拒绝访问！",
                    "Security Alert: Symlink or invalid node detected on encrypted storage directory. Access denied."
                ))
            }
            throw VaultCryptoError.hardwareKeyUnavailable(tr(
                "加密存储目录暂不可打开（POSIX errno \(err)），请确认设备处于解锁状态",
                "Unable to open encrypted storage directory (POSIX errno \(err)). Unlock your device and try again."
            ))
        }
        defer { _ = Darwin.close(dirFD) }

        var fst = stat()
        guard Darwin.fstat(dirFD, &fst) == 0,
              (fst.st_mode & S_IFMT) == S_IFDIR,
              fst.st_dev == dst.st_dev,
              fst.st_ino == dst.st_ino else {
            throw VaultCryptoError.storageTampered(tr(
                "安全告警：检测到加密存储目录并发替换异常，已阻断访问！",
                "Security Alert: Concurrent replacement of encrypted storage directory detected. Access blocked."
            ))
        }

        try? FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: directoryURL.path
        )
        excludeFromAllBackupsIfNonSymlink(directoryURL)
    }

    /// Inspects whether `fileURL` exists without dereferencing symlinks (`lstat` / `fstatat(AT_SYMLINK_NOFOLLOW)`),
    /// catching even dangling symlinks that `FileManager.fileExists(atPath:)` would miss.
    static func inspectExistingVaultNode(
        at fileURL: URL,
        ancestorDirectoriesToVerify: [URL]
    ) -> ExistingVaultNodeStatus {
        let fileName = fileURL.lastPathComponent
        guard isValidSinglePathComponent(fileName) else {
            return .tampered(tr(
                "安全告警：加密库文件名非法，已阻断操作！",
                "Security Alert: Invalid vault filename. Operation blocked."
            ))
        }

        for ancestor in ancestorDirectoriesToVerify {
            var ast = stat()
            if Darwin.lstat(ancestor.path, &ast) != 0 {
                let err = errno
                if err == ENOENT { continue }
                if err == EPERM || err == EACCES { return .protectedDataUnavailable }
                return .tampered(tr(
                    "安全告警：沙盒存储父目录元数据异常（POSIX errno \(err)），已阻断初始化！",
                    "Security Alert: Sandbox parent directory metadata anomaly (POSIX errno \(err)). Initialization blocked."
                ))
            }
            let mode = ast.st_mode & S_IFMT
            if mode == S_IFLNK {
                return .tampered(tr(
                    "安全告警：检测到沙盒存储父目录被植入软链接（Symlink），已拒绝初始化写入！",
                    "Security Alert: Symlink planted in sandbox parent directory. Initialization write denied."
                ))
            }
            if mode != S_IFDIR {
                return .tampered(tr(
                    "安全告警：沙盒存储父路径不是合法目录，已拒绝初始化写入！",
                    "Security Alert: Sandbox parent path is not a valid directory. Initialization write denied."
                ))
            }
        }

        let storageDirURL = fileURL.deletingLastPathComponent()
        var dst = stat()
        if Darwin.lstat(storageDirURL.path, &dst) != 0 {
            let err = errno
            if err == ENOENT {
                let parentURL = storageDirURL.deletingLastPathComponent()
                var pst = stat()
                if Darwin.lstat(parentURL.path, &pst) == 0, (pst.st_mode & S_IFMT) != S_IFDIR {
                    return .tampered(tr(
                        "安全告警：检测到加密存储上级路径为软链接或非目录节点，已拒绝初始化写入！",
                        "Security Alert: Encrypted storage parent path is a symlink or non-directory node. Initialization denied."
                    ))
                }
                return .absent
            }
            if err == EPERM || err == EACCES {
                return .protectedDataUnavailable
            }
            return .tampered(tr(
                "安全告警：加密存储目录状态异常（POSIX errno \(err)），已阻断初始化！",
                "Security Alert: Encrypted storage directory anomaly (POSIX errno \(err)). Initialization blocked."
            ))
        }

        let dirMode = dst.st_mode & S_IFMT
        if dirMode == S_IFLNK {
            return .tampered(tr(
                "安全告警：检测到加密存储目录被替换为软链接（Symlink），疑似沙盒越界篡改，已立即拒绝访问！",
                "Security Alert: Encrypted storage directory replaced by a symlink (possible tampering). Access denied."
            ))
        }
        if dirMode != S_IFDIR {
            return .tampered(tr(
                "安全告警：加密存储路径不是合法目录（检测到异常特殊节点），已拒绝访问！",
                "Security Alert: Encrypted storage path is not a valid directory. Access denied."
            ))
        }

        let dirFD = Darwin.open(storageDirURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dirFD >= 0 else {
            let err = errno
            if err == ENOENT { return .absent }
            if err == EPERM || err == EACCES { return .protectedDataUnavailable }
            return .tampered(tr(
                "安全告警：检测到加密存储目录软链接或访问异常，已拒绝初始化写入！",
                "Security Alert: Encrypted storage directory symlink or access anomaly. Initialization denied."
            ))
        }
        defer { _ = Darwin.close(dirFD) }

        var leafSt = stat()
        if Darwin.fstatat(dirFD, fileName, &leafSt, AT_SYMLINK_NOFOLLOW) != 0 {
            let err = errno
            if err == ENOENT { return .absent }
            if err == EPERM || err == EACCES { return .protectedDataUnavailable }
            return .tampered(tr(
                "安全告警：检测本地加密库节点时发生异常（POSIX errno \(err)），已拒绝覆盖！",
                "Security Alert: Anomaly inspecting local vault node (POSIX errno \(err)). Overwrite denied."
            ))
        }

        let leafMode = leafSt.st_mode & S_IFMT
        if leafMode == S_IFREG {
            return .regularFileExists
        }
        if leafMode == S_IFLNK {
            return .tampered(tr(
                "安全告警：检测到本地加密库路径存在异常软链接（Symlink），疑似沙盒越界篡改，已拒绝覆盖写入！",
                "Security Alert: Symlink detected at local vault path (possible tampering). Overwrite denied."
            ))
        }
        return .tampered(tr(
            "安全告警：检测到本地加密库路径存在非普通文件节点，已拒绝覆盖写入！",
            "Security Alert: Non-regular file node detected at local vault path. Overwrite denied."
        ))
    }

    /// Reads `vault.cardse` anchored to a verified `O_DIRECTORY | O_NOFOLLOW` descriptor via `openat`,
    /// strictly enforcing non-symlink, regular-file, and bounded-size invariants while distinguishing
    /// `NSFileProtectionComplete` lock-screen `EPERM`/`EACCES` from hostile tampering.
    static func readLocalVaultFile(
        at fileURL: URL,
        ancestorDirectoriesToVerify: [URL],
        maxBytes: Int = VaultCrypto.maximumVaultFileByteCount
    ) -> LocalVaultReadResult {
        let fileName = fileURL.lastPathComponent
        guard isValidSinglePathComponent(fileName) else {
            return .tampered(tr(
                "安全告警：加密库文件名非法，已阻断读取！",
                "Security Alert: Invalid vault filename. Read blocked."
            ))
        }

        for ancestor in ancestorDirectoriesToVerify {
            var ast = stat()
            if Darwin.lstat(ancestor.path, &ast) != 0 {
                let err = errno
                if err == ENOENT { return .notFound }
                if err == EPERM || err == EACCES { return .protectedDataUnavailable }
                return .tampered(tr(
                    "安全告警：沙盒存储父目录状态异常（POSIX errno \(err)），已阻断读取！",
                    "Security Alert: Sandbox parent directory anomaly (POSIX errno \(err)). Read blocked."
                ))
            }
            let mode = ast.st_mode & S_IFMT
            if mode == S_IFLNK {
                return .tampered(tr(
                    "安全告警：检测到沙盒存储父目录被植入软链接（Symlink），疑似越界篡改，已拒绝读取！",
                    "Security Alert: Symlink planted in sandbox parent directory (possible tampering). Read denied."
                ))
            }
            if mode != S_IFDIR {
                return .tampered(tr(
                    "安全告警：沙盒存储父路径不是合法目录，已拒绝读取！",
                    "Security Alert: Sandbox parent path is not a valid directory. Read denied."
                ))
            }
        }

        let storageDirURL = fileURL.deletingLastPathComponent()
        var dst = stat()
        if Darwin.lstat(storageDirURL.path, &dst) != 0 {
            let err = errno
            if err == ENOENT { return .notFound }
            if err == EPERM || err == EACCES { return .protectedDataUnavailable }
            return .tampered(tr(
                "安全告警：加密存储目录状态异常（POSIX errno \(err)），已阻断读取！",
                "Security Alert: Encrypted storage directory anomaly (POSIX errno \(err)). Read blocked."
            ))
        }

        let dirMode = dst.st_mode & S_IFMT
        if dirMode == S_IFLNK {
            return .tampered(tr(
                "安全告警：检测到加密存储目录被替换为软链接（Symlink），疑似沙盒越界篡改，已立即拒绝访问！",
                "Security Alert: Encrypted storage directory replaced by a symlink (possible tampering). Access denied."
            ))
        }
        if dirMode != S_IFDIR {
            return .tampered(tr(
                "安全告警：加密存储路径不是合法目录（检测到异常特殊节点），已拒绝访问！",
                "Security Alert: Encrypted storage path is not a valid directory. Access denied."
            ))
        }

        let dirFD = Darwin.open(storageDirURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dirFD >= 0 else {
            let err = errno
            if err == ENOENT { return .notFound }
            if err == ELOOP || err == ENOTDIR {
                return .tampered(tr(
                    "安全告警：检测到加密存储目录软链接替换竞争攻击，已拒绝访问！",
                    "Security Alert: Symlink race condition detected on encrypted storage directory. Access denied."
                ))
            }
            if err == EPERM || err == EACCES { return .protectedDataUnavailable }
            return .tampered(tr(
                "无法安全打开加密存储目录（POSIX errno \(err)）。",
                "Unable to safely open encrypted storage directory (POSIX errno \(err))."
            ))
        }
        defer { _ = Darwin.close(dirFD) }

        var openedDirSt = stat()
        guard Darwin.fstat(dirFD, &openedDirSt) == 0,
              (openedDirSt.st_mode & S_IFMT) == S_IFDIR,
              openedDirSt.st_dev == dst.st_dev,
              openedDirSt.st_ino == dst.st_ino else {
            return .tampered(tr(
                "安全告警：检测到加密存储目录并发替换异常，已阻断读取！",
                "Security Alert: Concurrent replacement of encrypted storage directory detected. Read blocked."
            ))
        }

        var leafSt = stat()
        if Darwin.fstatat(dirFD, fileName, &leafSt, AT_SYMLINK_NOFOLLOW) != 0 {
            let err = errno
            if err == ENOENT { return .notFound }
            if err == EPERM || err == EACCES { return .protectedDataUnavailable }
            return .tampered(tr(
                "检测本地加密库文件元数据时发生异常（POSIX errno \(err)）。",
                "Anomaly inspecting local vault file metadata (POSIX errno \(err))."
            ))
        }

        let leafMode = leafSt.st_mode & S_IFMT
        if leafMode == S_IFLNK {
            return .tampered(tr(
                "安全告警：检测到本地加密库文件被替换为软链接（Symlink），疑似沙盒越界攻击，已拒绝解引用！",
                "Security Alert: Local vault file replaced by a symlink (possible tampering). Dereference refused."
            ))
        }
        if leafMode != S_IFREG {
            return .tampered(tr(
                "安全告警：检测到本地加密库路径存在异常特殊节点（非普通文件），已拒绝打开！",
                "Security Alert: Non-regular file node detected at local vault path. Open refused."
            ))
        }
        if leafSt.st_size <= 0 {
            return .tampered(tr(
                "检测到本地加密库文件为空（0 字节）或已损坏",
                "Local vault file is empty (0 bytes) or corrupted"
            ))
        }
        if leafSt.st_size > off_t(maxBytes) {
            return .tampered(tr(
                "安全告警：本地加密库文件体积异常超限（超过 \(maxBytes / (1024 * 1024)) MB 安全上限），疑似稀疏文件耗尽攻击，已拒绝加载！",
                "Security Alert: Local vault file exceeds the \(maxBytes / (1024 * 1024)) MB safety limit (possible sparse-file bomb). Load refused."
            ))
        }

        let fd = Darwin.openat(dirFD, fileName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else {
            let err = errno
            if err == EPERM || err == EACCES {
                return .protectedDataUnavailable
            }
            if err == ELOOP {
                return .tampered(tr(
                    "安全告警：检测到本地加密库软链接替换竞争攻击，已拒绝打开！",
                    "Security Alert: Symlink race condition detected on local vault file. Open refused."
                ))
            }
            if err == ENOENT {
                return .notFound
            }
            return .tampered(tr(
                "无法安全读取本地加密库文件（POSIX errno \(err)）。",
                "Unable to safely read local vault file (POSIX errno \(err))."
            ))
        }
        defer { _ = Darwin.close(fd) }

        switch readBoundedFromRegularFD(fd: fd, expectedStat: leafSt, maxBytes: maxBytes) {
        case .data(let data):
            return .data(data)
        case .protectedDataUnavailable:
            return .protectedDataUnavailable
        case .tampered:
            return .tampered(tr(
                "安全告警：读取本地加密库时检测到文件节点异常或并发篡改，已中止加载！",
                "Security Alert: Node anomaly or concurrent tampering detected while reading local vault. Load aborted."
            ))
        case .invalidSize:
            return .tampered(tr(
                "安全告警：本地加密库文件体积超出安全范围，已中止加载！",
                "Security Alert: Local vault file size exceeds safety limit. Load aborted."
            ))
        }
    }

    /// Writes `data` atomically into `fileURL` with `NSFileProtectionComplete` (`PROTECTION_CLASS_A`)
    /// without ever traversing symlinks on ancestors, the storage directory, staging file, or destination leaf.
    static func writeLocalVaultFileAtomically(
        _ data: Data,
        to fileURL: URL,
        ancestorDirectoriesToVerify: [URL]
    ) throws {
        guard !data.isEmpty, data.count <= VaultCrypto.maximumVaultFileByteCount else {
            throw VaultCryptoError.invalidEnvelopeFormat
        }
        let fileName = fileURL.lastPathComponent
        guard isValidSinglePathComponent(fileName) else {
            throw VaultCryptoError.storageTampered(tr(
                "安全告警：加密库文件名非法，已拒绝写入！",
                "Security Alert: Invalid vault filename. Write denied."
            ))
        }

        let storageDirURL = fileURL.deletingLastPathComponent()
        try ensureSafeDirectory(at: storageDirURL, ancestorDirectoriesToVerify: ancestorDirectoriesToVerify)

        var dirLstat = stat()
        guard Darwin.lstat(storageDirURL.path, &dirLstat) == 0,
              (dirLstat.st_mode & S_IFMT) == S_IFDIR else {
            throw VaultCryptoError.storageTampered(tr(
                "安全告警：检测到加密存储目录状态异常，已拒绝写入！",
                "Security Alert: Encrypted storage directory anomaly. Write denied."
            ))
        }

        let dirFD = Darwin.open(storageDirURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dirFD >= 0 else {
            throw VaultCryptoError.storageTampered(tr(
                "安全告警：无法安全锁定加密存储目录，已拒绝写入！",
                "Security Alert: Failed to lock encrypted storage directory descriptor. Write denied."
            ))
        }
        defer { _ = Darwin.close(dirFD) }

        var dirFstat = stat()
        guard Darwin.fstat(dirFD, &dirFstat) == 0,
              (dirFstat.st_mode & S_IFMT) == S_IFDIR,
              dirFstat.st_dev == dirLstat.st_dev,
              dirFstat.st_ino == dirLstat.st_ino else {
            throw VaultCryptoError.storageTampered(tr(
                "安全告警：检测到加密存储目录并发替换异常，已拒绝写入！",
                "Security Alert: Concurrent replacement of encrypted storage directory detected. Write denied."
            ))
        }

        var existingLeaf = stat()
        if Darwin.fstatat(dirFD, fileName, &existingLeaf, AT_SYMLINK_NOFOLLOW) == 0,
           (existingLeaf.st_mode & S_IFMT) != S_IFREG {
            throw VaultCryptoError.storageTampered(tr(
                "安全告警：检测到本地加密库文件被替换为软链接或特殊节点，已拒绝写入！",
                "Security Alert: Local vault file replaced by symlink or special node. Write denied."
            ))
        }

        let stagingName = ".\(fileName).tmp.\(UUID().uuidString)"
        let stagingURL = storageDirURL.appendingPathComponent(stagingName, isDirectory: false)

        // `.withoutOverwriting` maps to POSIX `O_CREAT | O_EXCL` (never follows leaf symlinks),
        // while `.completeFileProtection` assigns Class A SEP protection at inode creation time.
        try data.write(to: stagingURL, options: [.withoutOverwriting, .completeFileProtection])

        var postDirLstat = stat()
        var stageStat = stat()
        guard Darwin.lstat(storageDirURL.path, &postDirLstat) == 0,
              postDirLstat.st_dev == dirFstat.st_dev,
              postDirLstat.st_ino == dirFstat.st_ino,
              Darwin.fstatat(dirFD, stagingName, &stageStat, AT_SYMLINK_NOFOLLOW) == 0,
              (stageStat.st_mode & S_IFMT) == S_IFREG,
              stageStat.st_size == off_t(data.count) else {
            _ = Darwin.unlinkat(dirFD, stagingName, 0)
            throw VaultCryptoError.storageTampered(tr(
                "安全告警：写入暂存加密文件时检测到目录替换或节点篡改，已中止提交！",
                "Security Alert: Directory replacement or node tampering detected while staging vault file. Commit aborted."
            ))
        }

        var preRenameLeaf = stat()
        if Darwin.fstatat(dirFD, fileName, &preRenameLeaf, AT_SYMLINK_NOFOLLOW) == 0,
           (preRenameLeaf.st_mode & S_IFMT) != S_IFREG {
            _ = Darwin.unlinkat(dirFD, stagingName, 0)
            throw VaultCryptoError.storageTampered(tr(
                "安全告警：提交前检测到目标加密库路径被植入异常节点，已中止提交！",
                "Security Alert: Unexpected node planted at target vault path before commit. Commit aborted."
            ))
        }

        guard Darwin.renameat(dirFD, stagingName, dirFD, fileName) == 0 else {
            let err = errno
            _ = Darwin.unlinkat(dirFD, stagingName, 0)
            throw VaultCryptoError.hardwareKeyUnavailable(tr(
                "原子提交加密库文件失败（POSIX errno \(err)）",
                "Atomic commit of encrypted vault file failed (POSIX errno \(err))"
            ))
        }

        _ = Darwin.fsync(dirFD)
        excludeFromAllBackupsIfNonSymlink(fileURL)
    }

    /// Safely migrates legacy `CardVaultStorage/vault.cardvault` to `CardSeStorage/vault.cardse`
    /// using descriptor-anchored `renameat` + `rmdir`, refusing to follow any symlink.
    static func migrateLegacyVaultIfPresent(
        legacyFolderURL: URL,
        legacyFileName: String,
        targetFileURL: URL,
        ancestorDirectoriesToVerify: [URL]
    ) {
        guard isValidSinglePathComponent(legacyFileName),
              isValidSinglePathComponent(targetFileURL.lastPathComponent) else {
            return
        }

        for ancestor in ancestorDirectoriesToVerify {
            var ast = stat()
            guard Darwin.lstat(ancestor.path, &ast) == 0,
                  (ast.st_mode & S_IFMT) == S_IFDIR else {
                return
            }
        }

        var legacyDirStat = stat()
        guard Darwin.lstat(legacyFolderURL.path, &legacyDirStat) == 0,
              (legacyDirStat.st_mode & S_IFMT) == S_IFDIR else {
            return
        }

        let legacyDirFD = Darwin.open(legacyFolderURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard legacyDirFD >= 0 else { return }
        defer { _ = Darwin.close(legacyDirFD) }

        var legacyLeafStat = stat()
        if Darwin.fstatat(legacyDirFD, legacyFileName, &legacyLeafStat, AT_SYMLINK_NOFOLLOW) == 0 {
            guard (legacyLeafStat.st_mode & S_IFMT) == S_IFREG,
                  legacyLeafStat.st_size > 0,
                  legacyLeafStat.st_size <= off_t(VaultCrypto.maximumVaultFileByteCount) else {
                return
            }

            let targetDirURL = targetFileURL.deletingLastPathComponent()
            guard (try? ensureSafeDirectory(at: targetDirURL, ancestorDirectoriesToVerify: ancestorDirectoriesToVerify)) != nil else {
                return
            }

            let targetDirFD = Darwin.open(targetDirURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard targetDirFD >= 0 else { return }
            defer { _ = Darwin.close(targetDirFD) }

            let targetFileName = targetFileURL.lastPathComponent
            var existingTarget = stat()
            if Darwin.fstatat(targetDirFD, targetFileName, &existingTarget, AT_SYMLINK_NOFOLLOW) != 0,
               errno == ENOENT {
                if Darwin.renameat(legacyDirFD, legacyFileName, targetDirFD, targetFileName) == 0 {
                    _ = Darwin.fsync(targetDirFD)
                    excludeFromAllBackupsIfNonSymlink(targetFileURL)
                }
            }
        }

        var postLegacyLeaf = stat()
        if Darwin.fstatat(legacyDirFD, legacyFileName, &postLegacyLeaf, AT_SYMLINK_NOFOLLOW) != 0,
           errno == ENOENT {
            _ = Darwin.rmdir(legacyFolderURL.path)
        }
    }

    /// Best-effort zero-overwrites and unlinks `vault.cardse` and `storageDirectoryURL` WITHOUT following symlinks,
    /// so an attacker-planted symlink at `CardSeStorage` or `vault.cardse` can never trick Enkard into zeroing or
    /// deleting files outside the storage directory.
    static func shredAndRemoveLocalVault(
        fileURL: URL,
        storageDirectoryURL: URL,
        ancestorDirectoriesToVerify: [URL]
    ) {
        for ancestor in ancestorDirectoriesToVerify {
            var ast = stat()
            guard Darwin.lstat(ancestor.path, &ast) == 0,
                  (ast.st_mode & S_IFMT) == S_IFDIR else {
                return
            }
        }

        var dirStat = stat()
        guard Darwin.lstat(storageDirectoryURL.path, &dirStat) == 0 else {
            return
        }

        if (dirStat.st_mode & S_IFMT) != S_IFDIR {
            // `storageDirectoryURL` itself was replaced with a symlink or non-directory node:
            // unlink ONLY that node and NEVER traverse into its target!
            _ = Darwin.unlink(storageDirectoryURL.path)
            return
        }

        let fileName = fileURL.lastPathComponent
        if isValidSinglePathComponent(fileName) {
            let dirFD = Darwin.open(storageDirectoryURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            if dirFD >= 0 {
                var openedDirStat = stat()
                if Darwin.fstat(dirFD, &openedDirStat) == 0,
                   (openedDirStat.st_mode & S_IFMT) == S_IFDIR,
                   openedDirStat.st_dev == dirStat.st_dev,
                   openedDirStat.st_ino == dirStat.st_ino {
                    var leafSt = stat()
                    if Darwin.fstatat(dirFD, fileName, &leafSt, AT_SYMLINK_NOFOLLOW) == 0 {
                        let leafMode = leafSt.st_mode & S_IFMT
                        if leafMode == S_IFREG {
                            if leafSt.st_size > 0 {
                                let wfd = Darwin.openat(dirFD, fileName, O_WRONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
                                if wfd >= 0 {
                                    var wfst = stat()
                                    if Darwin.fstat(wfd, &wfst) == 0,
                                       (wfst.st_mode & S_IFMT) == S_IFREG,
                                       wfst.st_dev == leafSt.st_dev,
                                       wfst.st_ino == leafSt.st_ino {
                                        let wipeCount = min(Int(leafSt.st_size), 1024 * 1024)
                                        let zeroes = [UInt8](repeating: 0, count: min(wipeCount, 65_536))
                                        var remaining = wipeCount
                                        while remaining > 0 {
                                            let chunkLen = min(remaining, zeroes.count)
                                            let written = Darwin.write(wfd, zeroes, chunkLen)
                                            if written <= 0 {
                                                if written < 0 && errno == EINTR { continue }
                                                break
                                            }
                                            remaining -= written
                                        }
                                        _ = Darwin.fsync(wfd)
                                    }
                                    _ = Darwin.close(wfd)
                                }
                            }
                            _ = Darwin.unlinkat(dirFD, fileName, 0)
                        } else if leafMode == S_IFDIR {
                            _ = Darwin.unlinkat(dirFD, fileName, AT_REMOVEDIR)
                        } else {
                            // Symlink, FIFO, socket, etc.: unlink the directory entry directly WITHOUT opening or dereferencing!
                            _ = Darwin.unlinkat(dirFD, fileName, 0)
                        }
                    }
                }
                _ = Darwin.close(dirFD)
            }
        }

        var postDirStat = stat()
        if Darwin.lstat(storageDirectoryURL.path, &postDirStat) == 0,
           (postDirStat.st_mode & S_IFMT) == S_IFDIR,
           postDirStat.st_dev == dirStat.st_dev,
           postDirStat.st_ino == dirStat.st_ino {
            _ = Darwin.rmdir(storageDirectoryURL.path)
        }
    }
}
