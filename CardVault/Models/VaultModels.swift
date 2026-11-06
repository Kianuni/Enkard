import Foundation
import SwiftUI
import UniformTypeIdentifiers

enum VaultEnvelopeDomain: Sendable, Equatable {
    case localVault
    case exportedBackup
}

struct VaultEnvelope: Codable, Sendable {
    static let legacyMagicV1 = "CARDVAULT_ENCRYPTED_V1"
    static let localMagicV2 = "CARDSE_LOCAL_VAULT_V2"
    static let backupMagicV2 = "CARDSE_BACKUP_EXPORT_V2"

    static let legacyVersionV1 = 1
    static let currentVersion = 2

    let magic: String
    let version: Int
    let vaultID: UUID?
    let kdfIterations: Int
    let salt: Data
    /// 65-byte X9.63 P-256 public key for Secure Enclave ECDH hardware binding (`localMagicV2` only).
    let ephemeralPublicKey: Data?
    let wrappedDEK: Data
    let encryptedPayload: Data
    let updatedAt: Date

    init(
        magic: String,
        version: Int,
        vaultID: UUID? = nil,
        kdfIterations: Int,
        salt: Data,
        ephemeralPublicKey: Data? = nil,
        wrappedDEK: Data,
        encryptedPayload: Data,
        updatedAt: Date
    ) {
        self.magic = magic
        self.version = version
        self.vaultID = vaultID
        self.kdfIterations = kdfIterations
        self.salt = salt
        self.ephemeralPublicKey = ephemeralPublicKey
        self.wrappedDEK = wrappedDEK
        self.encryptedPayload = encryptedPayload
        self.updatedAt = updatedAt
    }
}

struct VaultPlaintextPayload: Codable, Sendable {
    static let currentSchemaVersion = 3

    var schemaVersion: Int
    /// Matches `VaultEnvelope.vaultID` on v2+ envelopes to defeat cross-vault payload transplanting.
    var vaultID: UUID?
    /// Monotonic save counter (anti-rollback). Lives inside the authenticated ciphertext.
    var generation: UInt64
    var cards: [BankCard]
    var updatedAt: Date

    init(
        schemaVersion: Int = Self.currentSchemaVersion,
        vaultID: UUID? = nil,
        generation: UInt64,
        cards: [BankCard],
        updatedAt: Date = Date()
    ) {
        self.schemaVersion = schemaVersion
        self.vaultID = vaultID
        self.generation = generation
        self.cards = cards
        self.updatedAt = updatedAt
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion, vaultID, generation, cards, updatedAt
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        vaultID = try container.decodeIfPresent(UUID.self, forKey: .vaultID)
        generation = try container.decodeIfPresent(UInt64.self, forKey: .generation) ?? 0
        cards = try container.decode([BankCard].self, forKey: .cards)
        updatedAt = try container.decode(Date.self, forKey: .updatedAt)
    }
}

enum IdleLockTimeout: Int, CaseIterable, Identifiable, Codable, Sendable {
    case minute1 = 60
    case minutes3 = 180
    case minutes5 = 300
    case minutes10 = 600

    var id: Int { rawValue }

    var title: String {
        "前台无操作 \(rawValue / 60) 分钟后"
    }
}

enum AutoLockTimeout: Int, CaseIterable, Identifiable, Codable, Sendable {
    case immediately = 0
    case seconds15 = 15
    case seconds30 = 30
    case seconds60 = 60

    var id: Int { rawValue }

    var title: String {
        switch self {
        case .immediately: return "立即锁定（最安全）"
        case .seconds15: return "离开 15 秒后（网购切屏推荐）"
        case .seconds30: return "离开 30 秒后"
        case .seconds60: return "离开 1 分钟后"
        }
    }
}

enum ClipboardClearDuration: Int, CaseIterable, Identifiable, Codable, Sendable {
    case seconds10 = 10
    case seconds15 = 15
    case seconds30 = 30
    case seconds60 = 60

    var id: Int { rawValue }

    var title: String {
        "\(rawValue) 秒后自动销毁"
    }
}

enum BackupImportMode: String, CaseIterable, Identifiable, Sendable {
    case merge = "merge"
    case replace = "replace"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .merge: return "合并导入（保留现有卡片，跳过同卡号）"
        case .replace: return "覆盖替换（清空现有卡片后导入）"
        }
    }
}

struct EncryptedBackupDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }

    var data: Data

    init(data: Data) {
        self.data = data
    }

    init(configuration: ReadConfiguration) throws {
        guard let fileData = configuration.file.regularFileContents else {
            throw CocoaError(.fileReadCorruptFile)
        }
        self.data = fileData
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}
