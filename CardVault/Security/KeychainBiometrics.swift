import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum BiometricKind: Sendable {
    case faceID
    case touchID
    case opticID
    case none

    var displayName: String {
        switch self {
        case .faceID: return tr("面容 ID", "Face ID")
        case .touchID: return tr("触控 ID", "Touch ID")
        case .opticID: return tr("视网膜 ID", "Optic ID")
        case .none: return tr("生物识别", "Biometrics")
        }
    }

    var systemImage: String {
        switch self {
        case .faceID: return "faceid"
        case .touchID: return "touchid"
        case .opticID: return "opticid"
        case .none: return "lock.fill"
        }
    }
}

enum KeychainBiometricError: LocalizedError {
    case biometricsUnavailable(String)
    case userCancelled
    case itemNotFound
    case keychainFailure(OSStatus)

    var errorDescription: String? {
        switch self {
        case .biometricsUnavailable(let reason):
            return reason
        case .userCancelled:
            return nil
        case .itemNotFound:
            return tr(
                "尚未绑定生物识别密钥（或已启用紧急锁定），请输入主密码解锁",
                "Biometric unlock key is not enrolled (or Emergency Lockdown is active). Enter your master password."
            )
        case .keychainFailure(let status):
            return tr(
                "安全钥匙串访问失败（状态码：\(status)），请使用主密码解锁",
                "Keychain access failed (status: \(status)). Please unlock with your master password."
            )
        }
    }
}

/// Biometric-gated Keychain DEK storage (`WhenPasscodeSetThisDeviceOnly` + `.biometryCurrentSet` + `Synchronizable = false`).
/// Never synced to iCloud Keychain, and invalidated by iOS automatically if Face ID / Touch ID enrollments change.
enum KeychainBiometrics {
    private static let service = "com.local.cardse.biometric.v2"
    private static let legacyServiceV1 = "com.local.cardvault.biometric.v1"
    private static let account = "vault_dek_256"

    static func availableBiometricKind() -> BiometricKind {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .none
        }
        if #available(iOS 17.0, *), context.biometryType == .opticID {
            return .opticID
        }
        switch context.biometryType {
        case .faceID: return .faceID
        case .touchID: return .touchID
        case .opticID: return .opticID
        case .none: return .none
        @unknown default: return .none
        }
    }

    static func hasStoredBiometricKey() -> Bool {
        hasStoredKey(inService: service) || hasStoredKey(inService: legacyServiceV1)
    }

    private static func hasStoredKey(inService targetService: String) -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: targetService,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse!,
            kSecUseAuthenticationContext as String: context,
            kSecReturnData as String: false
        ]

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    static func saveBiometricDEK(_ key: SymmetricKey) throws {
        deleteBiometricDEK()

        var cfError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .biometryCurrentSet,
            &cfError
        ) else {
            throw KeychainBiometricError.biometricsUnavailable(
                tr("请先在系统设置中开启锁屏密码与面容/触控 ID", "Please enable a device passcode and Face ID / Touch ID in Settings first.")
            )
        }

        var keyData = key.withUnsafeBytes { Data($0) }
        defer { SecureZero.wipe(&keyData) }

        let status: OSStatus = keyData.withUnsafeBytes { rawBuffer in
            let nsValue = NSData(bytes: rawBuffer.baseAddress, length: rawBuffer.count)
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecAttrSynchronizable as String: kCFBooleanFalse!,
                kSecValueData as String: nsValue,
                kSecAttrAccessControl as String: accessControl
            ]
            return SecItemAdd(addQuery as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw KeychainBiometricError.keychainFailure(status)
        }
    }

    static func loadBiometricDEK(reason: String? = nil) async throws -> SymmetricKey {
        let promptReason = reason ?? tr("解锁 Enkard 本地加密银行卡包", "Unlock your encrypted Enkard card vault")
        return try await Task.detached(priority: .userInitiated) {
            let context = LAContext()
            context.localizedReason = promptReason
            context.localizedFallbackTitle = ""

            var authError: NSError?
            guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError) else {
                let message = authError?.localizedDescription ?? tr("当前设备生物识别不可用，请输入主密码", "Biometrics unavailable on this device. Please enter your master password.")
                throw KeychainBiometricError.biometricsUnavailable(message)
            }

            // Directly let `SecItemCopyMatching` drive the hardware-gated `.biometryCurrentSet` prompt via `context`,
            // eliminating redundant pre-evaluation double prompts and authentication-context expiry races.
            for candidateService in [service, legacyServiceV1] {
                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: candidateService,
                    kSecAttrAccount as String: account,
                    kSecAttrSynchronizable as String: kCFBooleanFalse!,
                    kSecReturnData as String: true,
                    kSecMatchLimit as String: kSecMatchLimitOne,
                    kSecUseAuthenticationContext as String: context
                ]

                var result: AnyObject?
                let status = SecItemCopyMatching(query as CFDictionary, &result)

                switch status {
                case errSecSuccess:
                    guard let nsData = result as? NSData, nsData.length == 32 else {
                        result = nil
                        continue
                    }
                    var ownedBytes = [UInt8](repeating: 0, count: 32)
                    nsData.getBytes(&ownedBytes, length: 32)
                    result = nil
                    defer { SecureZero.wipe(&ownedBytes) }
                    return SymmetricKey(data: ownedBytes)
                case errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed:
                    throw KeychainBiometricError.userCancelled
                case errSecItemNotFound:
                    continue
                default:
                    throw KeychainBiometricError.keychainFailure(status)
                }
            }
            throw KeychainBiometricError.itemNotFound
        }.value
    }

    static func deleteBiometricDEK() {
        for targetService in [service, legacyServiceV1] {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: targetService,
                kSecAttrAccount as String: account,
                kSecAttrSynchronizable as String: kCFBooleanFalse!
            ]
            SecItemDelete(query as CFDictionary)
        }
    }
}
