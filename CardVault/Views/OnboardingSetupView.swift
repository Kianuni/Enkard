import SwiftUI
import UniformTypeIdentifiers

struct OnboardingSetupView: View {
    @ObservedObject var store: VaultStore

    @State private var masterPassword = ""
    @State private var confirmPassword = ""
    @State private var enableBiometrics = true

    @State private var isImportingBackup = false
    @State private var pendingBackupData: Data? = nil
    @State private var showRestoreSheet = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 26) {
                    if store.runtimeIntegrity.isCompromised {
                        RuntimeCompromiseBanner(text: store.runtimeIntegrity.summaryText)
                    }

                    // Header Emblem
                    VStack(spacing: 12) {
                        ZStack {
                            Circle()
                                .fill(
                                    LinearGradient(
                                        colors: [
                                            Color(red: 0.16, green: 0.17, blue: 0.24),
                                            Color(red: 0.08, green: 0.09, blue: 0.13)
                                        ],
                                        startPoint: .topLeading,
                                        endPoint: .bottomTrailing
                                    )
                                )
                                .frame(width: 84, height: 84)
                                .shadow(color: .black.opacity(0.20), radius: 12, y: 5)

                            Image(systemName: "lock.shield.fill")
                                .font(.system(size: 38))
                                .foregroundStyle(
                                    LinearGradient(
                                        colors: [
                                            Color(red: 0.95, green: 0.82, blue: 0.52),
                                            Color(red: 0.77, green: 0.58, blue: 0.29)
                                        ],
                                        startPoint: .top,
                                        endPoint: .bottom
                                    )
                                )
                        }
                        .padding(.top, 12)

                        Text("Enkard")
                            .font(.title.bold())

                        Text(tr(
                            "零网络 · 零云同步 · Secure Enclave 硬件绑定",
                            "Zero Network · Zero Cloud Sync · Secure Enclave Hardware Bound"
                        ))
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }

                    // Security Badges
                    VStack(alignment: .leading, spacing: 12) {
                        SecurityPillarRow(
                            icon: "wifi.exclamationmark",
                            title: tr("彻底断网与零同步", "Completely Offline & Zero Sync"),
                            subtitle: tr(
                                "内置进程级网络阻断器，禁用 iCloud、钥匙串同步、接力、系统备份与输入法词库学习",
                                "Process-level network kill-switch disables iCloud, Keychain sync, Handoff, backups & keyboard learning"
                            )
                        )
                        SecurityPillarRow(
                            icon: "cpu.fill",
                            title: tr("Secure Enclave 双因子硬件加密", "Secure Enclave Dual-Factor Crypto"),
                            subtitle: tr(
                                "主密码 PBKDF2 与本机安全芯片不可导出私钥联合保护，拷走文件也无法离线破解",
                                "Master password PBKDF2 combined with non-exportable chip key — useless even if files are copied off-device"
                            )
                        )
                        SecurityPillarRow(
                            icon: "keyboard.badge.ellipsis",
                            title: tr("封禁全部第三方扩展与 AI 写作工具", "Blocks 3rd-Party Keyboards & AI Tools"),
                            subtitle: tr(
                                "仅限系统原生安全键盘，禁止第三方输入法、自动填充与写作工具读取输入",
                                "Restricts input to Apple's native keyboard and disables 3rd-party extensions, AutoFill & Writing Tools"
                            )
                        )
                        SecurityPillarRow(
                            icon: "eye.slash.circle.fill",
                            title: tr("防截屏安全层与限时剪贴板", "Screenshot Redaction & Expiring Clipboard"),
                            subtitle: tr(
                                "敏感区域在截屏/录屏中自动空白，锁屏或到期立即销毁本机剪贴板",
                                "Sensitive fields render blank in screenshots/recordings; local clipboard auto-clears on lock or timeout"
                            )
                        )
                    }
                    .padding(16)
                    .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16, style: .continuous))

                    // Password Setup Card
                    VStack(alignment: .leading, spacing: 14) {
                        Text(tr("设置 Enkard 主密码", "Set Enkard Master Password"))
                            .font(.headline)

                        SecureField(
                            tr("至少 8 位，混合字母、数字与符号（≥40 bit）", "Min 8 chars: mix letters, digits & symbols (≥40 bits)"),
                            text: $masterPassword
                        )
                            .lockdownTextInput()
                            .onValueChange(of: masterPassword) { val in
                                if val.count > VaultCrypto.maximumPasswordLength {
                                    masterPassword = String(val.prefix(VaultCrypto.maximumPasswordLength))
                                }
                            }
                            .padding(12)
                            .background(Color(.tertiarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12, style: .continuous))

                        SecureField(
                            tr("再次输入主密码确认", "Confirm master password"),
                            text: $confirmPassword
                        )
                            .lockdownTextInput()
                            .onValueChange(of: confirmPassword) { val in
                                if val.count > VaultCrypto.maximumPasswordLength {
                                    confirmPassword = String(val.prefix(VaultCrypto.maximumPasswordLength))
                                }
                            }
                            .padding(12)
                            .background(Color(.tertiarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12, style: .continuous))

                        if !masterPassword.isEmpty {
                            PasswordStrengthIndicator(password: masterPassword)
                            if let message = PasswordPolicy.validationMessage(masterPassword, for: .master) {
                                Label(message, systemImage: "exclamationmark.triangle.fill")
                                    .font(.caption)
                                    .foregroundStyle(.orange)
                            }
                        }

                        if !confirmPassword.isEmpty && masterPassword != confirmPassword {
                            Label(
                                tr("两次输入的主密码不一致", "Master passwords do not match"),
                                systemImage: "exclamationmark.circle.fill"
                            )
                                .font(.caption)
                                .foregroundStyle(.red)
                        }

                        if store.biometricKind != .none && !store.runtimeIntegrity.isCompromised {
                            Divider().padding(.vertical, 2)
                            Toggle(isOn: $enableBiometrics) {
                                Label(
                                    tr("启用\(store.biometricKind.displayName)快捷解锁", "Enable \(store.biometricKind.displayName) Quick Unlock"),
                                    systemImage: store.biometricKind.systemImage
                                )
                                    .font(.subheadline.weight(.medium))
                            }
                        }

                        Text(tr(
                            "注意：Enkard 完全离线且不参与任何云端同步，忘记主密码且无离线备份将永远无法恢复。",
                            "Note: Enkard is strictly offline with zero cloud sync. If you forget your master password without a backup, your data cannot be recovered."
                        ))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(16)
                    .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16, style: .continuous))

                    if let error = store.errorMessage {
                        Text(error)
                            .font(.footnote)
                            .foregroundStyle(.red)
                            .multilineTextAlignment(.center)
                    }

                    // Actions
                    VStack(spacing: 12) {
                        Button {
                            let entered = masterPassword
                            Task {
                                let ok = await store.setupNewVault(
                                    masterPassword: entered,
                                    enableBiometrics: enableBiometrics
                                )
                                if ok {
                                    scrubInputs()
                                }
                            }
                        } label: {
                            HStack(spacing: 8) {
                                if store.isBusy {
                                    ProgressView().tint(.white)
                                } else {
                                    Image(systemName: "lock.doc.fill")
                                }
                                Text(store.isBusy
                                    ? tr("正在绑定硬件安全芯片...", "Binding to Secure Enclave...")
                                    : tr("创建硬件加密卡包", "Create Hardware-Encrypted Vault"))
                                    .fontWeight(.semibold)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(!canSubmit || store.isBusy)

                        Button {
                            isImportingBackup = true
                        } label: {
                            Label(
                                tr("从离线加密备份 (.enkard / .cardse / .cardvault) 恢复", "Restore from Offline Backup (.enkard / .cardse / .cardvault)"),
                                systemImage: "arrow.down.doc.fill"
                            )
                                .font(.subheadline.weight(.medium))
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 10)
                        }
                        .buttonStyle(.bordered)
                        .disabled(store.isBusy)
                    }
                }
                .padding(20)
            }
            .background(Color(.systemGroupedBackground))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cardSeTrailing) {
                    LanguageMenuButton(selection: $store.languageMode)
                }
            }
            .fileImporter(
                isPresented: $isImportingBackup,
                allowedContentTypes: [.data, .json],
                allowsMultipleSelection: false
            ) { result in
                handlePickedBackupFile(result)
            }
            .sheet(isPresented: $showRestoreSheet, onDismiss: {
                pendingBackupData = nil
            }) {
                RestoreFromBackupSheet(
                    store: store,
                    backupData: pendingBackupData ?? Data(),
                    enableBiometricsDefault: enableBiometrics
                )
            }
            .onDisappear {
                scrubInputs()
            }
        }
    }

    private var canSubmit: Bool {
        PasswordPolicy.validationMessage(masterPassword, for: .master) == nil
            && masterPassword == confirmPassword
    }

    private func scrubInputs() {
        masterPassword = ""
        confirmPassword = ""
    }

    private func handlePickedBackupFile(_ result: Result<[URL], Error>) {
        switch result {
        case .success(let urls):
            guard let url = urls.first else { return }
            let didAccess = url.startAccessingSecurityScopedResource()
            defer {
                if didAccess { url.stopAccessingSecurityScopedResource() }
            }
            store.warnIfCloudSyncedURL(url)
            do {
                pendingBackupData = try VaultCrypto.readBackupFileBounded(at: url)
                showRestoreSheet = true
            } catch {
                store.errorMessage = tr(
                    "读取备份文件失败：\(error.localizedDescription)",
                    "Failed to read backup file: \(error.localizedDescription)"
                )
            }
        case .failure(let error):
            store.errorMessage = tr(
                "选择文件失败：\(error.localizedDescription)",
                "Failed to select file: \(error.localizedDescription)"
            )
        }
    }
}

struct RuntimeCompromiseBanner: View {
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.shield.fill")
                .font(.title3)
                .foregroundStyle(.white)
            VStack(alignment: .leading, spacing: 3) {
                Text(tr("检测到高风险运行环境", "High-Risk Runtime Environment Detected"))
                    .font(.subheadline.bold())
                    .foregroundStyle(.white)
                Text(text)
                    .font(.caption)
                    .foregroundStyle(.white.opacity(0.92))
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .background(Color.red.opacity(0.90), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

private struct SecurityPillarRow: View {
    let icon: String
    let title: String
    let subtitle: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 17, weight: .semibold))
                .foregroundStyle(.tint)
                .frame(width: 28, height: 28)
                .background(Color.accentColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 8, style: .continuous))

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

struct PasswordStrengthIndicator: View {
    let password: String

    private var assessment: PasswordAssessment {
        PasswordPolicy.assess(password)
    }

    private var color: Color {
        switch assessment.score {
        case 0: return .red
        case 1: return .orange
        case 2: return .yellow
        case 3: return .green
        default: return .mint
        }
    }

    var body: some View {
        let result = assessment
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                ForEach(0..<4, id: \.self) { index in
                    Capsule()
                        .fill(index < result.score ? color : Color.secondary.opacity(0.20))
                        .frame(height: 4)
                }
            }
            Text(tr(
                "密码强度：\(result.label)（估算约 \(Int(result.estimatedBits)) bit）",
                "Strength: \(result.label) (~\(Int(result.estimatedBits)) bits)"
            ))
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }
}

private struct RestoreFromBackupSheet: View {
    @ObservedObject var store: VaultStore
    let backupData: Data
    let enableBiometricsDefault: Bool

    @Environment(\.dismiss) private var dismiss
    @State private var backupPassword = ""
    @State private var newMasterPassword = ""
    @State private var confirmNewMaster = ""
    @State private var enableBiometrics = true

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField(
                        tr("备份密码或 25 位恢复口令", "Backup password or 25-char recovery passphrase"),
                        text: $backupPassword
                    )
                        .lockdownTextInput()
                } header: {
                    Text(tr("第一步：输入离线备份口令", "Step 1: Enter Offline Backup Passphrase"))
                } footer: {
                    Text(tr(
                        "随机恢复口令须逐字输入，包括大写字母、数字和连字符。",
                        "Enter random recovery passphrases exactly, including uppercase letters, digits, and hyphens."
                    ))
                }

                Section {
                    SecureField(
                        tr("设置本机新主密码（至少 8 位，≥40 bit）", "New master password (min 8 chars, ≥40 bits)"),
                        text: $newMasterPassword
                    )
                        .lockdownTextInput()
                    SecureField(tr("确认本机新主密码", "Confirm new master password"), text: $confirmNewMaster)
                        .lockdownTextInput()
                    if !newMasterPassword.isEmpty {
                        PasswordStrengthIndicator(password: newMasterPassword)
                        if let message = PasswordPolicy.validationMessage(newMasterPassword, for: .master) {
                            Text(message).font(.caption).foregroundStyle(.orange)
                        }
                    }
                    if !backupPassword.isEmpty
                        && !newMasterPassword.isEmpty
                        && VaultCrypto.normalizePassword(backupPassword) == VaultCrypto.normalizePassword(newMasterPassword) {
                        Text(tr("本机主密码禁止与备份口令相同", "Master password cannot match backup passphrase"))
                            .font(.caption)
                            .foregroundStyle(.red)
                    }

                    if store.biometricKind != .none && !store.runtimeIntegrity.isCompromised {
                        Toggle(
                            tr("启用\(store.biometricKind.displayName)解锁", "Enable \(store.biometricKind.displayName) Unlock"),
                            isOn: $enableBiometrics
                        )
                    }
                } header: {
                    Text(tr("第二步：设置本机主密码（绑定本机安全芯片）", "Step 2: Set Device Master Password (Secure Enclave)"))
                } footer: {
                    Text(tr(
                        "恢复后的数据将重新使用本机 Secure Enclave 芯片加密存储，且新主密码必须与备份密码不同。",
                        "Restored cards will be re-encrypted with this device's Secure Enclave. Your new master password must differ from the backup password."
                    ))
                }

                if let error = store.errorMessage {
                    Section {
                        Text(error)
                            .foregroundStyle(.red)
                            .font(.footnote)
                    }
                }
            }
            .navigationTitle(tr("从离线备份恢复", "Restore from Offline Backup"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(tr("取消", "Cancel")) {
                        scrubState()
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(store.isBusy ? tr("解密中...", "Decrypting...") : tr("解密恢复", "Decrypt & Restore")) {
                        let bPass = backupPassword
                        let mPass = newMasterPassword
                        Task {
                            let ok = await store.restoreOnboardingFromBackup(
                                data: backupData,
                                backupPassword: bPass,
                                newMasterPassword: mPass,
                                enableBiometrics: enableBiometrics
                            )
                            if ok {
                                scrubState()
                                dismiss()
                            }
                        }
                    }
                    .disabled(!isValid || store.isBusy)
                }
            }
            .onAppear {
                enableBiometrics = enableBiometricsDefault
            }
            .onDisappear {
                scrubState()
            }
        }
    }

    private var isValid: Bool {
        !backupPassword.isEmpty
            && VaultCrypto.normalizePassword(backupPassword) != VaultCrypto.normalizePassword(newMasterPassword)
            && PasswordPolicy.validationMessage(newMasterPassword, for: .master) == nil
            && newMasterPassword == confirmNewMaster
    }

    private func scrubState() {
        backupPassword = ""
        newMasterPassword = ""
        confirmNewMaster = ""
    }
}
