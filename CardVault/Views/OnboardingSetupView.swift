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

                        Text("零网络 · 零云同步 · Secure Enclave 硬件绑定")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }

                    // Security Badges
                    VStack(alignment: .leading, spacing: 12) {
                        SecurityPillarRow(
                            icon: "wifi.exclamationmark",
                            title: "彻底断网与零同步",
                            subtitle: "内置进程级网络阻断器，禁用 iCloud、钥匙串同步、接力、系统备份与输入法词库学习"
                        )
                        SecurityPillarRow(
                            icon: "cpu.fill",
                            title: "Secure Enclave 双因子硬件加密",
                            subtitle: "主密码 PBKDF2 与本机安全芯片不可导出私钥联合保护，拷走文件也无法离线破解"
                        )
                        SecurityPillarRow(
                            icon: "keyboard.badge.ellipsis",
                            title: "封禁全部第三方扩展与 AI 写作工具",
                            subtitle: "仅限系统原生安全键盘，禁止第三方输入法、自动填充与写作工具读取输入"
                        )
                        SecurityPillarRow(
                            icon: "eye.slash.circle.fill",
                            title: "防截屏安全层与限时剪贴板",
                            subtitle: "敏感区域在截屏/录屏中自动空白，锁屏或到期立即销毁本机剪贴板"
                        )
                    }
                    .padding(16)
                    .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16, style: .continuous))

                    // Password Setup Card
                    VStack(alignment: .leading, spacing: 14) {
                        Text("设置 Enkard 主密码")
                            .font(.headline)

                        SecureField("至少 8 位，混合字母、数字与符号（≥40 bit）", text: $masterPassword)
                            .lockdownTextInput()
                            .padding(12)
                            .background(Color(.tertiarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12, style: .continuous))

                        SecureField("再次输入主密码确认", text: $confirmPassword)
                            .lockdownTextInput()
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
                            Label("两次输入的主密码不一致", systemImage: "exclamationmark.circle.fill")
                                .font(.caption)
                                .foregroundStyle(.red)
                        }

                        if store.biometricKind != .none && !store.runtimeIntegrity.isCompromised {
                            Divider().padding(.vertical, 2)
                            Toggle(isOn: $enableBiometrics) {
                                Label("启用\(store.biometricKind.displayName)快捷解锁", systemImage: store.biometricKind.systemImage)
                                    .font(.subheadline.weight(.medium))
                            }
                        }

                        Text("注意：Enkard 完全离线且不参与任何云端同步，忘记主密码且无离线备份将永远无法恢复。")
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
                                Text(store.isBusy ? "正在绑定硬件安全芯片..." : "创建硬件加密卡包")
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
                            Label("从离线加密备份 (.enkard / .cardse / .cardvault) 恢复", systemImage: "arrow.down.doc.fill")
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
                store.errorMessage = "读取备份文件失败：\(error.localizedDescription)"
            }
        case .failure(let error):
            store.errorMessage = "选择文件失败：\(error.localizedDescription)"
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
                Text("检测到高风险运行环境")
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
            Text("密码强度：\(result.label)（估算约 \(Int(result.estimatedBits)) bit）")
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
                    SecureField("备份密码或 25 位恢复口令", text: $backupPassword)
                        .lockdownTextInput()
                } header: {
                    Text("第一步：输入离线备份口令")
                } footer: {
                    Text("随机恢复口令须逐字输入，包括大写字母、数字和连字符。")
                }

                Section {
                    SecureField("设置本机新主密码（至少 8 位，≥40 bit）", text: $newMasterPassword)
                        .lockdownTextInput()
                    SecureField("确认本机新主密码", text: $confirmNewMaster)
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
                        Text("本机主密码禁止与备份口令相同").font(.caption).foregroundStyle(.red)
                    }

                    if store.biometricKind != .none && !store.runtimeIntegrity.isCompromised {
                        Toggle("启用\(store.biometricKind.displayName)解锁", isOn: $enableBiometrics)
                    }
                } header: {
                    Text("第二步：设置本机主密码（绑定本机安全芯片）")
                } footer: {
                    Text("恢复后的数据将重新使用本机 Secure Enclave 芯片加密存储，且新主密码必须与备份密码不同。")
                }

                if let error = store.errorMessage {
                    Section {
                        Text(error)
                            .foregroundStyle(.red)
                            .font(.footnote)
                    }
                }
            }
            .navigationTitle("从离线备份恢复")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") {
                        scrubState()
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(store.isBusy ? "解密中..." : "解密恢复") {
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
