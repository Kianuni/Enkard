import CoreGraphics
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
            "abc12345", "P@ssw0rd2026!", "woaini1314", "１２３４５６７８！"
        ] {
            XCTAssertNotNil(PasswordPolicy.validationMessage(weak, for: .master), "Should reject weak master: \(weak)")
        }
        XCTAssertNotNil(PasswordPolicy.validationMessage("19900101520。", for: .backup))
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

    func testCardOCRParserAndMultiFrameConsensus() {
        let blocks: [RecognizedTextBlock] = [
            RecognizedTextBlock(text: "招商银行", boundingBox: CGRect(x: 0.08, y: 0.82, width: 0.35, height: 0.06)),
            RecognizedTextBlock(text: "4111 Il11 1111 1111", boundingBox: CGRect(x: 0.10, y: 0.48, width: 0.80, height: 0.08)),
            RecognizedTextBlock(text: "VALID FROM 05/24 VALID THRU 08/29", boundingBox: CGRect(x: 0.20, y: 0.34, width: 0.60, height: 0.05)),
            RecognizedTextBlock(text: "VISA PLATINUM", boundingBox: CGRect(x: 0.68, y: 0.14, width: 0.24, height: 0.05)),
            RecognizedTextBlock(text: "SAN ZHANG", boundingBox: CGRect(x: 0.10, y: 0.16, width: 0.36, height: 0.06))
        ]
        let candidate = CardOCRParser.parseFrame(blocks)
        XCTAssertEqual(candidate?.cardNumber, "4111111111111111")
        XCTAssertEqual(candidate?.expiryMonth, "08")
        XCTAssertEqual(candidate?.expiryYear, "29")
        XCTAssertEqual(candidate?.cardholderName, "SAN ZHANG")
        XCTAssertEqual(candidate?.bankName, "招商银行")

        // Reject invalid Luhn
        XCTAssertNil(CardOCRParser.parseFrame([
            RecognizedTextBlock(text: "4111 1111 1111 1112", boundingBox: CGRect(x: 0.1, y: 0.5, width: 0.8, height: 0.08))
        ]))

        // Vertical 4x4 stack stitching + multi-frame consensus
        let verticalBlocks: [RecognizedTextBlock] = [
            RecognizedTextBlock(text: "6225", boundingBox: CGRect(x: 0.16, y: 0.72, width: 0.22, height: 0.05)),
            RecognizedTextBlock(text: "8801", boundingBox: CGRect(x: 0.16, y: 0.62, width: 0.22, height: 0.05)),
            RecognizedTextBlock(text: "3770", boundingBox: CGRect(x: 0.16, y: 0.52, width: 0.22, height: 0.05)),
            RecognizedTextBlock(text: "1232", boundingBox: CGRect(x: 0.16, y: 0.42, width: 0.22, height: 0.05))
        ]
        let verticalCandidate = CardOCRParser.parseFrame(verticalBlocks)
        XCTAssertEqual(verticalCandidate?.cardNumber, "6225880137701232")

        var accumulator = CardScanConsensusAccumulator(requiredConfirmations: 2)
        if case .provisional = accumulator.ingest(verticalCandidate) {} else {
            XCTFail("Expected provisional outcome on first frame")
        }
        let enriched = ScannedCardCandidate(
            cardNumber: "6225880137701232",
            expiryMonth: "11",
            expiryYear: "30",
            cardholderName: "SAN ZHANG",
            bankName: "工商银行"
        )
        if case .confirmed(let merged) = accumulator.ingest(enriched) {
            XCTAssertEqual(merged.expiryMonth, "11")
            XCTAssertEqual(merged.expiryYear, "30")
            XCTAssertEqual(merged.cardholderName, "SAN ZHANG")
            XCTAssertEqual(merged.bankName, "工商银行")
        } else {
            XCTFail("Expected confirmed outcome on second frame")
        }
    }
}
