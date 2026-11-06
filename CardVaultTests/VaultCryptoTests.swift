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
}
