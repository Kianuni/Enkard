import CryptoKit
import XCTest
@testable import CardSe

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
}
