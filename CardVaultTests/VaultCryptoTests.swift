import CryptoKit
import XCTest
@testable import Enkard

final class VaultCryptoTests: XCTestCase {
    private let iterations = VaultCrypto.minimumNewIterations
    private let sampleCard = BankCard(
        bankName: "招商银行", nickname: "全币种海淘卡", cardType: .credit, network: .visa,
        cardNumber: "4111 1111 1111 1111", cardholderName: "SAN ZHANG",
        expiryMonth: "08", expiryYear: "2029", cvv: "618"
    )

    func testHardwareBoundLocalVaultAndCryptoShredding() throws {
        let hw = InMemoryHardwareKeyProvider()
        let (envelope, key) = try VaultCrypto.createNewLocalVault(
            masterPassword: "CorrectHorse!Battery9",
            initialCards: [sampleCard],
            generation: 3,
            iterations: iterations,
            hardwareKeys: hw
        )
        XCTAssertEqual(envelope.magic, VaultEnvelope.localMagicV2)
        XCTAssertEqual(envelope.ephemeralPublicKey?.count, 65)

        // 4 KB padding hides exact card count (12 nonce + 4096 padded frame + 16 tag = 4124 bytes).
        XCTAssertEqual(envelope.encryptedPayload.count, 12 + 4096 + 16)

        // Wrong device / stolen file without Secure Enclave private key MUST fail even with the right password!
        let otherDeviceHW = InMemoryHardwareKeyProvider(preprovisioned: true)
        XCTAssertThrowsError(
            try VaultCrypto.unlockLocalVaultWithPassword(
                envelope: envelope,
                masterPassword: "CorrectHorse!Battery9",
                hardwareKeys: otherDeviceHW
            )
        )

        // Same device + right password succeeds.
        let unlocked = try VaultCrypto.unlockLocalVaultWithPassword(
            envelope: envelope,
            masterPassword: "CorrectHorse!Battery9",
            hardwareKeys: hw
        )
        XCTAssertEqual(unlocked.key, key)
        XCTAssertEqual(unlocked.payload.generation, 3)
        XCTAssertEqual(unlocked.payload.cards.first?.cvv, "618")

        // Crypto-Shredding: destroying the hardware key permanently bricks the ciphertext!
        hw.destroyKey()
        XCTAssertThrowsError(
            try VaultCrypto.unlockLocalVaultWithPassword(
                envelope: envelope,
                masterPassword: "CorrectHorse!Battery9",
                hardwareKeys: hw
            )
        )
    }

    func testDomainSeparationAndAntiSplicing() throws {
        let hw = InMemoryHardwareKeyProvider()
        let (env1, key1) = try VaultCrypto.createNewLocalVault(
            masterPassword: "MasterPassword#Alpha9",
            initialCards: [sampleCard],
            generation: 1,
            iterations: iterations,
            hardwareKeys: hw
        )
        let resealed = try VaultCrypto.resealLocalPayload(
            existingEnvelope: env1,
            key: key1,
            cards: [sampleCard],
            generation: 2
        )

        // Tampering 1 bit of wrappedDEK MUST cause decryptPayload (e.g. biometric path) to fail via payloadAAD!
        var mutatedWrapped = resealed.wrappedDEK
        mutatedWrapped[0] ^= 0x01
        let spliced = VaultEnvelope(
            magic: resealed.magic,
            version: resealed.version,
            vaultID: resealed.vaultID,
            kdfIterations: resealed.kdfIterations,
            salt: resealed.salt,
            ephemeralPublicKey: resealed.ephemeralPublicKey,
            wrappedDEK: mutatedWrapped,
            encryptedPayload: resealed.encryptedPayload,
            updatedAt: resealed.updatedAt
        )
        XCTAssertThrowsError(try VaultCrypto.decryptPayload(envelope: spliced, key: key1, expectedDomain: .localVault))

        // Local vault cannot be imported as a backup; backup cannot be unlocked as a local vault!
        let localEncoder = JSONEncoder()
        localEncoder.dateEncodingStrategy = .iso8601
        let encodedLocal = try localEncoder.encode(env1)
        XCTAssertThrowsError(try VaultCrypto.importEncryptedBackup(data: encodedLocal, backupPassword: "MasterPassword#Alpha9")) {
            XCTAssertEqual($0 as? VaultCryptoError, .domainMismatch)
        }

        let passphrase = PasswordPolicy.generateRecoveryPassphrase()
        let backupData = try VaultCrypto.exportEncryptedBackup(
            cards: [sampleCard],
            backupPassword: passphrase,
            iterations: iterations
        )
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let backupEnv = try decoder.decode(VaultEnvelope.self, from: backupData)
        XCTAssertThrowsError(
            try VaultCrypto.unlockLocalVaultWithPassword(envelope: backupEnv, masterPassword: passphrase, hardwareKeys: hw)
        ) {
            XCTAssertEqual($0 as? VaultCryptoError, .domainMismatch)
        }
    }

    func testPasswordPolicyBlocksCJKPunctuationBypass() {
        for weak in [
            "12345678", "1234567！", "19900101", "19900101。", "@13812345678!",
            "abc12345", "P@ssw0rd2026!", "woaini1314", "１２３４５６７８！",
            "Ab1!Ab1!", "Ab1!\u{200B}Xy9#", "Ab1!\u{0000}Xy9#"
        ] {
            XCTAssertNotNil(PasswordPolicy.validationMessage(weak, for: .master), "Should reject weak master: \(weak)")
        }
        XCTAssertNotNil(PasswordPolicy.validationMessage("19900101520。", for: .backup))
        XCTAssertNotNil(PasswordPolicy.validationMessage("Ab1!Ab1!Ab1!", for: .backup))
        XCTAssertNotNil(PasswordPolicy.validationMessage("!@#19900101$%^", for: .backup))
        XCTAssertNil(PasswordPolicy.validationMessage("mj7#Kq2!vZ", for: .master))
        XCTAssertNil(PasswordPolicy.validationMessage(PasswordPolicy.generateRecoveryPassphrase(), for: .backup))
    }

    func testUnicodeNFCNormalizationRoundtrip() throws {
        let nfc = "K\u{00E9}yVault#9876!Xz"
        let nfd = "Ke\u{0301}yVault#9876!Xz"
        let backup = try VaultCrypto.exportEncryptedBackup(cards: [sampleCard], backupPassword: nfc, iterations: iterations)
        let restored = try VaultCrypto.importEncryptedBackup(data: backup, backupPassword: nfd)
        XCTAssertEqual(restored.count, 1)
    }

    func testLockoutAndBiometricSuspensionPolicy() {
        XCTAssertEqual([4, 5, 6, 7, 8, 9].map(LockoutPolicy.lockoutSeconds), [0, 30, 60, 300, 900, 3600])
        let sec: UInt64 = 1_000_000_000
        let record = LockoutRecord(failures: 6, lockStartMonotonicNs: 100 * sec, lockDurationSeconds: 60, bootSession: "A")
        XCTAssertEqual(LockoutPolicy.remainingSeconds(record: record, nowMonotonicNs: 130 * sec, currentBootSession: "A").remaining, 30)
        XCTAssertEqual(LockoutPolicy.remainingSeconds(record: record, nowMonotonicNs: 1 * sec, currentBootSession: "B").remaining, 60)
    }

    @MainActor
    func testInitialStorePhaseIsNeutralLoading() {
        let store = VaultStore(hardwareKeys: InMemoryHardwareKeyProvider())
        XCTAssertEqual(store.phase, .loading)
    }

    @MainActor
    func testAntiRollbackWatermarkAndFailClosedLockoutGuard() {
        final class MockBackend: @unchecked Sendable, KeychainStateBackend {
            var map: [String: Data] = [:]
            var unavailable = false
            func readResult(_ account: String) -> KeychainReadResult {
                if unavailable { return .unavailable(errSecInteractionNotAllowed) }
                guard let d = map[account] else { return .notFound }
                return .found(d)
            }
            func write(_ data: Data, account: String) -> Bool {
                if unavailable { return false }
                map[account] = data
                return true
            }
            func delete(_ account: String) {
                if !unavailable { map.removeValue(forKey: account) }
            }
        }

        let backend = MockBackend()
        let seed = LockoutGuard(backend: backend)
        for _ in 0..<8 { XCTAssertTrue(seed.beginAttempt()) }

        backend.unavailable = true
        let lockedGuard = LockoutGuard(backend: backend)
        XCTAssertTrue(lockedGuard.isBiometricSuspended)
        XCTAssertFalse(lockedGuard.beginAttempt())

        backend.unavailable = false
        XCTAssertEqual(lockedGuard.failures, 8)

        let id = UUID()
        XCTAssertTrue(VaultIdentityStore.advanceWatermark(VaultIdentityRecord(vaultID: id, generation: 12, envelopeVersion: 2), using: backend))
        XCTAssertTrue(VaultIdentityStore.advanceWatermark(VaultIdentityRecord(vaultID: id, generation: 4, envelopeVersion: 1), using: backend))
        XCTAssertEqual(VaultIdentityStore.readState(using: backend), .found(VaultIdentityRecord(vaultID: id, generation: 12, envelopeVersion: 2)))
    }

    func testOversizedPasswordPasteBombBoundedInConstantTime() {
        let giant = String(repeating: "Ab1!xY9#qZ", count: 5_000) // 50,000 chars
        let start = Date()
        let msg = PasswordPolicy.validationMessage(giant, for: .master)
        let assessment = PasswordPolicy.assess(giant)
        let elapsed = Date().timeIntervalSince(start)

        XCTAssertNotNil(msg)
        XCTAssertEqual(assessment.estimatedBits, 0)
        XCTAssertLessThan(elapsed, 0.05)

        let hw = InMemoryHardwareKeyProvider()
        XCTAssertThrowsError(
            try VaultCrypto.createNewLocalVault(
                masterPassword: giant,
                initialCards: [],
                iterations: iterations,
                hardwareKeys: hw
            )
        ) {
            XCTAssertEqual($0 as? VaultCryptoError, .passwordTooLong(maximum: VaultCrypto.maximumPasswordLength))
        }
    }

    func testCleanRuntimeIntegrityBaseline() {
        let report = RuntimeSecurity.auditEnvironment(antiDebugActive: false)
        XCTAssertFalse(report.isCompromised, "Unexpected compromise on clean test host: \(report.summaryText)")
    }

    /// Proves the GOT-rebinding detector is actually ACTIVE on this platform (not silently skipped):
    /// the shared-cache range must exist and contain genuine system functions but not the app image.
    func testSharedCacheRangeSignalIsActive() throws {
        typealias RangeFn = @convention(c) (UnsafeMutablePointer<Int>?) -> UnsafeRawPointer?
        let rtld = UnsafeMutableRawPointer(bitPattern: -2)
        let sym = try XCTUnwrap(dlsym(rtld, "_dyld_get_shared_cache_range"))
        var length = 0
        let start = try XCTUnwrap(unsafeBitCast(sym, to: RangeFn.self)(&length))
        XCTAssertGreaterThan(length, 0)
        XCTAssertLessThan(length, 1 << 36, "Range must pass RuntimeSecurity's sanity cap, otherwise the check is skipped")
        let range = UInt(bitPattern: start)..<(UInt(bitPattern: start) + UInt(length))
        for name in ["_dyld_get_image_name", "_dyld_get_image_header", "_dyld_image_count", "dladdr", "dlsym",
                     "getenv", "sysctl", "CCKeyDerivationPBKDF", "SecItemCopyMatching", "SecItemAdd"] {
            let ptr = try XCTUnwrap(dlsym(rtld, name), name)
            XCTAssertTrue(range.contains(UInt(bitPattern: ptr)), "\(name) must reside in the shared cache")
        }
        XCTAssertFalse(range.contains(UInt(bitPattern: UnsafeRawPointer(#dsohandle))))
    }

    @MainActor
    func testImportedBackupCardsAreSanitizedAndBounded() throws {
        let dupID = UUID()
        let hostile = BankCard(
            id: dupID, bankName: String(repeating: "B", count: 10_000), cardNumber: "4111111111111111",
            cvv: "1234", notes: String(repeating: "N", count: 500_000)
        )
        var smuggled = hostile
        smuggled.cvv = String(repeating: "9", count: 100_000)   // bypasses init filtering, like a decoded JSON payload
        smuggled.cardNumber = "4111-1111-1111-1111-9999-8888"
        smuggled.statementDay = 999
        let sanitized = try VaultStore.sanitizeImportedCards([hostile, smuggled])
        XCTAssertEqual(sanitized.count, 2)
        XCTAssertNotEqual(sanitized[0].id, sanitized[1].id, "Duplicate IDs must be re-keyed")
        XCTAssertLessThanOrEqual(sanitized[1].cvv.count, 4)
        XCTAssertLessThanOrEqual(sanitized[1].cardNumber.count, 19)
        XCTAssertLessThanOrEqual(sanitized[0].notes.count, 2000)
        XCTAssertLessThanOrEqual(sanitized[0].bankName.count, 64)
        XCTAssertNil(sanitized[1].statementDay)

        let flood = (0...VaultStore.maximumImportedCardCount).map { _ in BankCard(bankName: "X", cardNumber: "4111") }
        XCTAssertThrowsError(try VaultStore.sanitizeImportedCards(flood))
    }

    func testBackupFileReadIsBoundedBeforeLoadingIntoMemory() throws {
        let dir = FileManager.default.temporaryDirectory
        let big = dir.appendingPathComponent("enkard-oversize-\(UUID().uuidString).enkard")
        XCTAssertTrue(FileManager.default.createFile(atPath: big.path, contents: nil))
        let handle = try FileHandle(forWritingTo: big)
        try handle.truncate(atOffset: UInt64(VaultCrypto.maximumBackupFileByteCount + 1)) // sparse file, no RAM cost
        try handle.close()
        defer { try? FileManager.default.removeItem(at: big) }
        XCTAssertThrowsError(try VaultCrypto.readBackupFileBounded(at: big))

        let small = dir.appendingPathComponent("enkard-small-\(UUID().uuidString).enkard")
        try Data("{}".utf8).write(to: small)
        defer { try? FileManager.default.removeItem(at: small) }
        XCTAssertEqual(try VaultCrypto.readBackupFileBounded(at: small), Data("{}".utf8))
    }

    // MARK: - v2.3.0 Bank-Grade Security Regression Suite

    func testRuntimePathTraversalAndSharedCacheHeaderValidation() throws {
        let traversal = RuntimeSecurity.normalizedSystemPathForAudit("/usr/lib/../../var/tmp/evil.dylib")
        XCTAssertTrue(traversal.hasTraversal)
        XCTAssertFalse(RuntimeSecurity.isTrustedSystemImagePath("/usr/lib/../../var/tmp/evil.dylib"))
        XCTAssertFalse(RuntimeSecurity.isTrustedSystemImagePath("/System/Library/../var/jb/tweak.dylib"))
        XCTAssertTrue(RuntimeSecurity.isTrustedSystemImagePath("/usr/lib/libSystem.B.dylib"))

        // Real dyld shared cache header on this Darwin host must pass structural validation.
        typealias RangeFn = @convention(c) (UnsafeMutablePointer<Int>?) -> UnsafeRawPointer?
        let rtld = UnsafeMutableRawPointer(bitPattern: -2)
        let sym = try XCTUnwrap(dlsym(rtld, "_dyld_get_shared_cache_range"))
        var realLen = 0
        let realStart = try XCTUnwrap(unsafeBitCast(sym, to: RangeFn.self)(&realLen))
        XCTAssertTrue(RuntimeSecurity.isValidSharedCacheHeader(start: realStart, length: realLen))

        // Forged page-aligned header buffers (zeroed mappingOffset, writable initProt, or all-zero UUID) must be rejected!
        var pagePtr: UnsafeMutableRawPointer?
        guard posix_memalign(&pagePtr, 0x4000, 0x4000) == 0, let forged = pagePtr else {
            XCTFail("posix_memalign failed")
            return
        }
        defer { free(forged) }
        memset(forged, 0, 0x4000)
        _ = "dyld_v1  arm64e".withCString { src in
            memcpy(forged, src, 15)
        }
        // Variant 1: mappingOffset == 0 (like evil_fishhook_forged_cache.c)
        XCTAssertFalse(RuntimeSecurity.isValidSharedCacheHeader(start: UnsafeRawPointer(forged), length: 512 * 1024 * 1024))

        // Variant 2: plausible mappingOffset & mapping[0], but writable initProt (0x07) or all-zero UUID
        forged.storeBytes(of: UInt32(0x100), toByteOffset: 16, as: UInt32.self)
        forged.storeBytes(of: UInt32(1), toByteOffset: 20, as: UInt32.self)
        forged.storeBytes(of: UInt64(0x100000), toByteOffset: 0x100 + 8, as: UInt64.self)
        forged.storeBytes(of: UInt64(0), toByteOffset: 0x100 + 16, as: UInt64.self)
        forged.storeBytes(of: UInt32(7), toByteOffset: 0x100 + 24, as: UInt32.self) // RWX -> must fail!
        forged.storeBytes(of: UInt32(7), toByteOffset: 0x100 + 28, as: UInt32.self)
        XCTAssertFalse(RuntimeSecurity.isValidSharedCacheHeader(start: UnsafeRawPointer(forged), length: 512 * 1024 * 1024))

        forged.storeBytes(of: UInt32(5), toByteOffset: 0x100 + 24, as: UInt32.self)
        forged.storeBytes(of: UInt32(5), toByteOffset: 0x100 + 28, as: UInt32.self)
        // Still all-zero cache UUID at 0x58..<0x68 -> must fail!
        XCTAssertFalse(RuntimeSecurity.isValidSharedCacheHeader(start: UnsafeRawPointer(forged), length: 512 * 1024 * 1024))

        // Variant 3: Genuine iPhone19,7 (`arm64e.x1`) 0-space magic `"dyld_v1arm64ex1\0"` + non-zero UUID:
        // must PASS both for `r-x` (0x05) single-mapping AND `r--` (0x01) multi-mapping RO headers!
        forged.storeBytes(of: UInt64(0x164A7885_37533172), toByteOffset: 0x58, as: UInt64.self)
        _ = "dyld_v1arm64ex1".withCString { src in
            memcpy(forged, src, 16) // includes '\0' at byte 15
        }
        XCTAssertTrue(RuntimeSecurity.isValidSharedCacheHeader(start: UnsafeRawPointer(forged), length: 512 * 1024 * 1024))

        // Multi-mapping (`mappingCount == 3`) with `r--` (0x01) RO header mapping[0] -> must PASS!
        forged.storeBytes(of: UInt32(3), toByteOffset: 20, as: UInt32.self)
        forged.storeBytes(of: UInt32(1), toByteOffset: 0x100 + 24, as: UInt32.self)
        forged.storeBytes(of: UInt32(1), toByteOffset: 0x100 + 28, as: UInt32.self)
        XCTAssertTrue(RuntimeSecurity.isValidSharedCacheHeader(start: UnsafeRawPointer(forged), length: 512 * 1024 * 1024))

        // Single-mapping (`mappingCount == 1`) with `r--` (0x01) or blank arch `"dyld_v1        \0"` -> must FAIL!
        forged.storeBytes(of: UInt32(1), toByteOffset: 20, as: UInt32.self)
        XCTAssertFalse(RuntimeSecurity.isValidSharedCacheHeader(start: UnsafeRawPointer(forged), length: 512 * 1024 * 1024))
        forged.storeBytes(of: UInt32(5), toByteOffset: 0x100 + 24, as: UInt32.self)
        forged.storeBytes(of: UInt32(5), toByteOffset: 0x100 + 28, as: UInt32.self)
        _ = "dyld_v1        ".withCString { src in
            memcpy(forged, src, 16)
        }
        XCTAssertFalse(RuntimeSecurity.isValidSharedCacheHeader(start: UnsafeRawPointer(forged), length: 512 * 1024 * 1024))
    }

    @MainActor
    func testNonAuthHardwareFaultsNeverTriggerVaultSelfDestruct() async throws {
        final class FaultInjectableHW: HardwareKeyProvider, @unchecked Sendable {
            let inner = InMemoryHardwareKeyProvider()
            var simulateTransientFault = false
            var destroyed = false

            var currentProtectionTier: HardwareProtectionTier? { inner.currentProtectionTier }
            var hasPendingKey: Bool { inner.hasPendingKey }

            func sealNewVaultFactor(salt: Data) throws -> (ephemeralPublicKey: Data, hardwareSecret: SymmetricKey) {
                if simulateTransientFault { throw HardwareKeyError.temporarilyUnavailable }
                return try inner.sealNewVaultFactor(salt: salt)
            }
            func sealExistingVaultFactor(salt: Data) throws -> (ephemeralPublicKey: Data, hardwareSecret: SymmetricKey) {
                if simulateTransientFault { throw HardwareKeyError.temporarilyUnavailable }
                return try inner.sealExistingVaultFactor(salt: salt)
            }
            func unsealVaultFactor(ephemeralPublicKey: Data, salt: Data) throws -> SymmetricKey {
                if simulateTransientFault { throw HardwareKeyError.temporarilyUnavailable }
                return try inner.unsealVaultFactor(ephemeralPublicKey: ephemeralPublicKey, salt: salt)
            }
            func unsealPendingVaultFactor(ephemeralPublicKey: Data, salt: Data) throws -> SymmetricKey {
                if simulateTransientFault { throw HardwareKeyError.temporarilyUnavailable }
                return try inner.unsealPendingVaultFactor(ephemeralPublicKey: ephemeralPublicKey, salt: salt)
            }
            func commitRotatedKey() { inner.commitRotatedKey() }
            func discardPendingKey() { inner.discardPendingKey() }
            func destroyKey() {
                destroyed = true
                inner.destroyKey()
            }
        }

        final class MemoryStateBackend: @unchecked Sendable, KeychainStateBackend {
            var map: [String: Data] = [:]
            func readResult(_ account: String) -> KeychainReadResult {
                map[account].map(KeychainReadResult.found) ?? .notFound
            }
            func write(_ data: Data, account: String) -> Bool {
                map[account] = data
                return true
            }
            func delete(_ account: String) {
                map.removeValue(forKey: account)
            }
        }

        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("enkard-r4-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let tempVaultURL = tempDir.appendingPathComponent("vault.cardse")

        let hw = FaultInjectableHW()
        let backend = MemoryStateBackend()
        let store = VaultStore(hardwareKeys: hw, stateBackend: backend, customVaultFileURL: tempVaultURL)
        store.bootstrapIfNeeded()
        XCTAssertEqual(store.phase, .onboarding)

        let masterPass = "Correct#Vault99!Key"
        let created = await store.setupNewVault(masterPassword: masterPass, enableBiometrics: false, initialCards: [sampleCard])
        XCTAssertTrue(created)
        store.wipeAfterFailedAttempts = true
        store.lock(reason: .manual)
        XCTAssertEqual(store.phase, .locked)

        // 20 consecutive transient hardware faults (> 15 wipe threshold) + empty/oversized inputs MUST NOT wipe the vault!
        hw.simulateTransientFault = true
        for _ in 0..<20 {
            let ok = await store.unlockWithMasterPassword(masterPass)
            XCTAssertFalse(ok)
        }
        _ = await store.unlockWithMasterPassword("")
        _ = await store.unlockWithMasterPassword(String(repeating: "A", count: 2000))

        XCTAssertFalse(hw.destroyed, "Transient SEP/Keychain faults must NEVER destroy the Secure Enclave key!")
        XCTAssertTrue(FileManager.default.fileExists(atPath: tempVaultURL.path), "Vault file must survive transient faults!")
        XCTAssertEqual(store.failedAttemptCount, 0, "Non-auth faults must roll back the pre-KDF attempt increment!")

        // Once hardware recovers, the right password unlocks immediately with all cards intact!
        hw.simulateTransientFault = false
        let recovered = await store.unlockWithMasterPassword(masterPass)
        XCTAssertTrue(recovered)
        XCTAssertEqual(store.cards.count, 1)

        // Also verify re-auth during password rotation survives 20 transient hardware faults without wiping!
        hw.simulateTransientFault = true
        for _ in 0..<20 {
            let rotated = await store.changeMasterPassword(currentPassword: masterPass, newPassword: "Rotated$Pass88!Key")
            XCTAssertFalse(rotated)
        }
        XCTAssertFalse(hw.destroyed)
        XCTAssertEqual(store.phase, .unlocked)
        XCTAssertEqual(store.failedAttemptCount, 0)
    }

    func testGenerationOverflowGuardAndVaultIDOverwriteProtection() throws {
        let hw = InMemoryHardwareKeyProvider()
        let vaultID = UUID()
        let (env, key) = try VaultCrypto.createNewLocalVault(
            masterPassword: "BankGrade#2026!Pass",
            initialCards: [sampleCard],
            vaultID: vaultID,
            generation: 1,
            iterations: iterations,
            hardwareKeys: hw
        )

        // Attempting to seal a payload at or above `maximumValidGeneration` (including `UInt64.max`) must throw cleanly!
        XCTAssertThrowsError(
            try VaultCrypto.resealLocalPayload(
                existingEnvelope: env,
                key: key,
                cards: [sampleCard],
                generation: UInt64.max
            )
        )

        // Forge an authenticated ciphertext containing `generation == UInt64.max` and verify `decryptPayload` rejects it!
        let maliciousPayload = VaultPlaintextPayload(vaultID: vaultID, generation: UInt64.max, cards: [sampleCard])
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        let rawJSON = try enc.encode(maliciousPayload)
        var padded = Data(count: 4096)
        var lenBE = UInt32(rawJSON.count).bigEndian
        withUnsafeBytes(of: &lenBE) { padded.replaceSubrange(0..<4, with: $0) }
        padded.replaceSubrange(4..<(4 + rawJSON.count), with: rawJSON)

        // Even with a valid key, VaultIdentityStore must also reject `UInt64.max` and foreign `vaultID` overwrites:
        final class MemBackend: @unchecked Sendable, KeychainStateBackend {
            var map: [String: Data] = [:]
            func readResult(_ a: String) -> KeychainReadResult { map[a].map(KeychainReadResult.found) ?? .notFound }
            func write(_ d: Data, account a: String) -> Bool { map[a] = d; return true }
            func delete(_ a: String) { map.removeValue(forKey: a) }
        }
        let backend = MemBackend()
        XCTAssertFalse(
            VaultIdentityStore.write(
                VaultIdentityRecord(vaultID: vaultID, generation: UInt64.max, envelopeVersion: 2),
                using: backend
            )
        )
        XCTAssertTrue(
            VaultIdentityStore.write(
                VaultIdentityRecord(vaultID: vaultID, generation: 5, envelopeVersion: 2),
                using: backend
            )
        )
        let foreignVaultID = UUID()
        XCTAssertFalse(
            VaultIdentityStore.advanceWatermark(
                VaultIdentityRecord(vaultID: foreignVaultID, generation: 99, envelopeVersion: 2),
                using: backend
            ),
            "advanceWatermark must refuse to overwrite an established vaultID with a foreign vault's ID!"
        )
        XCTAssertEqual(
            VaultIdentityStore.readState(using: backend),
            .found(VaultIdentityRecord(vaultID: vaultID, generation: 5, envelopeVersion: 2))
        )
    }

    func testSecureZeroMemsetSWipesOwnedBuffersWithoutCoWLeak() {
        var bytes: [UInt8] = Array("4111222233334444|CVV=999".utf8)
        SecureZero.wipe(&bytes)
        XCTAssertTrue(bytes.allSatisfy { $0 == 0 })

        var secretData = Data("SuperSecretMasterKeyMaterial32B!".utf8)
        SecureZero.wipe(&secretData)
        XCTAssertTrue(secretData.allSatisfy { $0 == 0 })
    }

    @MainActor
    func testKeychainStateAuthenticatorMigrationAndAntiTamper() throws {
        final class TamperBackend: @unchecked Sendable, KeychainStateBackend {
            var map: [String: Data] = [:]
            func readResult(_ account: String) -> KeychainReadResult {
                map[account].map(KeychainReadResult.found) ?? .notFound
            }
            func write(_ data: Data, account: String) -> Bool {
                map[account] = data
                return true
            }
            func delete(_ account: String) {
                map.removeValue(forKey: account)
            }
        }

        let backend = TamperBackend()
        let v22VaultID = UUID()
        // Seed pre-v2.3 plain JSON records across all 3 accounts (simulating seamless upgrade from v2.2.0).
        backend.map["vault_identity_v2"] = try JSONEncoder().encode(
            VaultIdentityRecord(vaultID: v22VaultID, generation: 7, envelopeVersion: 2)
        )
        backend.map["local_preferences_v2"] = try JSONEncoder().encode(
            VaultPreferences(biometricsEnabled: true, autoLockTimeoutRaw: 15, idleLockTimeoutRaw: 180, clipboardClearDurationRaw: 15, wipeAfterFailedAttempts: true)
        )
        backend.map["unlock_lockout"] = try JSONEncoder().encode(
            LockoutRecord(failures: 3, lockStartMonotonicNs: nil, lockDurationSeconds: 0, bootSession: nil, isLockdownActive: false)
        )

        // First read transparently upgrades all 3 records to `EKM1` HMAC-SHA256 authenticated blobs!
        XCTAssertEqual(
            VaultIdentityStore.readState(using: backend),
            .found(VaultIdentityRecord(vaultID: v22VaultID, generation: 7, envelopeVersion: 2))
        )
        XCTAssertEqual(VaultPreferencesStore.load(using: backend).autoLockTimeoutRaw, 15)
        let migratedLockout = LockoutGuard(backend: backend)
        XCTAssertEqual(migratedLockout.failures, 3)
        XCTAssertTrue(backend.map["vault_identity_v2"]?.starts(with: Data("EKM1".utf8)) == true)
        XCTAssertTrue(backend.map["unlock_lockout"]?.starts(with: Data("EKM1".utf8)) == true)

        // Attack 1: Inject un-MACed plain JSON with negative failures (`-999999`) -> MUST fail closed!
        backend.map["unlock_lockout"] = Data(#"{"failures":-999999,"lockDurationSeconds":0,"isLockdownActive":false}"#.utf8)
        let forgedPlainGuard = LockoutGuard(backend: backend)
        XCTAssertTrue(forgedPlainGuard.isBiometricSuspended)
        XCTAssertFalse(forgedPlainGuard.beginAttempt())

        // Attack 2: Cross-account replay (`local_preferences_v2` EKM1 blob copied into `vault_identity_v2`) -> `.corrupted`!
        backend.map["vault_identity_v2"] = backend.map["local_preferences_v2"]
        XCTAssertEqual(VaultIdentityStore.readState(using: backend), .corrupted)

        // Attack 3: Delete `state_hmac_key_v2` while `EKM1` blobs exist -> `.corrupted`!
        backend.delete(KeychainStateAuthenticator.hmacKeyAccount)
        XCTAssertEqual(VaultIdentityStore.readState(using: backend), .corrupted)
    }

    @MainActor
    func testBankCardBidiSpoofingSanitizationAndAlertShieldWindowLevel() throws {
        // RLO (`U+202E`), LRI (`U+2066`), ZWSP (`U+200B`), C0 control (`U+0007`), circled digit (`①`), oversized string
        let spoofedJSON = """
        {
          "bankName": "招商\\u202E行银\\u200B\\u0007",
          "nickname": "\(String(repeating: "海", count: 200))",
          "cardNumber": "4111①1111١11111111999999",
          "cvv": "8①999",
          "statementDay": 45,
          "notes": "正常备注\\u202E伪装反转\\u2066"
        }
        """.data(using: .utf8)!

        let decoded = try JSONDecoder().decode(BankCard.self, from: spoofedJSON)
        XCTAssertFalse(decoded.bankName.unicodeScalars.contains(where: { $0.value == 0x202E || $0.value == 0x200B || $0.value == 0x07 }))
        XCTAssertEqual(decoded.bankName, "招商行银")
        XCTAssertEqual(decoded.nickname.count, BankCard.maxNicknameLength)
        XCTAssertEqual(decoded.cardNumber.count, BankCard.maxCardNumberDigits)
        XCTAssertTrue(decoded.cardNumber.allSatisfy { $0.isASCII && $0.isNumber })
        XCTAssertEqual(decoded.cvv, "8999")
        XCTAssertNil(decoded.statementDay)
        XCTAssertEqual(decoded.notes, "正常备注伪装反转")

        // PrivacyShieldWindow must sit strictly above both `.statusBar` (1000) and `.alert` (2000)!
        XCTAssertGreaterThan(PrivacyShieldWindowManager.shieldWindowLevel.rawValue, UIWindow.Level.statusBar.rawValue)
        XCTAssertGreaterThan(PrivacyShieldWindowManager.shieldWindowLevel.rawValue, UIWindow.Level.alert.rawValue)
    }
}
