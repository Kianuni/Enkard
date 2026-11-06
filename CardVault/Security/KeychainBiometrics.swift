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
        case .faceID: return "面容 ID"
        case .touchID: return "触控 ID"
        case .opticID: return "视网膜 ID"
        case .none: return "生物识别"
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
            return "尚未绑定生物识别密钥（或已启用紧急锁定），请输入主密码解锁"
        case .keychainFailure(let status):
            return "安全钥匙串访问失败（状态码：\(status)），请使用主密码解锁"
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
            throw KeychainBiometricError.biometricsUnavailable("请先在系统设置中开启锁屏密码与面容/触控 ID")
        }

        var keyData = key.withUnsafeBytes { Data($0) }
        defer { keyData.resetBytes(in: 0..<keyData.count) }

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse!,
            kSecValueData as String: keyData,
            kSecAttrAccessControl as String: accessControl
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainBiometricError.keychainFailure(status)
        }
    }

    static func loadBiometricDEK(reason: String = "解锁 Enkard 本地加密银行卡包") async throws -> SymmetricKey {
        try await Task.detached(priority: .userInitiated) {
            let context = LAContext()
            context.localizedReason = reason
            context.localizedFallbackTitle = "使用主密码"

            var authError: NSError?
            guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError) else {
                let message = authError?.localizedDescription ?? "当前设备生物识别不可用，请输入主密码"
                throw KeychainBiometricError.biometricsUnavailable(message)
            }

            let authenticated = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            )
            guard authenticated else {
                throw KeychainBiometricError.userCancelled
            }

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
                    guard var data = result as? Data, data.count == 32 else {
                        continue
                    }
                    defer { data.resetBytes(in: 0..<data.count) }
                    return SymmetricKey(data: data)
                case errSecUserCanceled, errSecAuthFailed:
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
