import SwiftUI
import UniformTypeIdentifiers

struct SecuritySettingsView: View {
    @ObservedObject var store: VaultStore
    @Environment(\.dismiss) private var dismiss

    @State private var showingExportPasswordPrompt = false
    @State private var exportDocument: EncryptedBackupDocument? = nil
    @State private var showingFileExporter = false

    @State private var showingFileImporter = false
    @State private var pendingImportData: Data? = nil
    @State private var showingImportSheet = false

    @State private var showingChangePassword = false
    @State private var showingDestroySheet = false
    @State private var showingWipeConfirm = false

    @State private var statusBannerMessage: String? = nil

    var body: some View {
        NavigationStack {
            Form {
                if let msg = statusBannerMessage {
                    Section {
                        Label(msg, systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                            .font(.subheadline)
                    }
                }

                // Security Architecture Status
                Section {
                    AuditRow(
                        icon: "wifi.slash",
                        label: tr("网络与同步", "Network & Sync"),
                        value: tr("进程断网拦截已激活 · 零云同步", "Kill-switch active · Zero cloud sync")
                    )
                    AuditRow(
                        icon: "cpu.fill",
                        label: tr("硬件密钥绑定", "Hardware Key"),
                        value: store.hardwareProtectionDescription
                    )
                    AuditRow(
                        icon: store.runtimeIntegrity.isCompromised ? "exclamationmark.triangle.fill" : "checkmark.shield.fill",
                        label: tr("运行时完整性", "Runtime Integrity"),
                        value: store.runtimeIntegrity.summaryText,
                        isWarning: store.runtimeIntegrity.isCompromised
                    )
                    AuditRow(
                        icon: "keyboard",
                        label: tr("扩展与 AI 输入", "Extensions & AI"),
                        value: tr("封禁全部第三方扩展 · 禁写作工具", "3rd-party extensions & Writing Tools blocked")
                    )
                    AuditRow(
                        icon: "lock.doc.fill",
                        label: tr("信封加密协议", "Vault Envelope"),
                        value: tr("LOCAL_V2 · 4KB 填充防侧信道", "LOCAL_V2 · 4KB side-channel padding")
                    )
                    AuditRow(
                        icon: "speedometer",
                        label: tr("PBKDF2 迭代", "PBKDF2 Iterations"),
                        value: tr("\(store.kdfIterations.formatted()) 次", "\(store.kdfIterations.formatted()) rounds")
                    )
                    AuditRow(
                        icon: "camera.metering.none",
                        label: tr("截图与录屏防护", "Screen Protection"),
                        value: SecureCanvasSupport.isAvailable
                            ? tr("安全图层空白渲染 + 独立遮罩窗", "Secure blank canvas + Shield window")
                            : tr("录屏遮罩已开启（无截图图层）", "Capture shield active (No canvas layer)")
                    )
                    AuditRow(
                        icon: "internaldrive.fill",
                        label: tr("本机存储保护", "Local Storage"),
                        value: tr("锁屏销毁内存密钥 · 禁系统备份", "Wipes RAM on lock · Excluded from backups")
                    )
                } header: {
                    Text(tr("Enkard 最高安全状态", "Enkard Security Posture"))
                } footer: {
                    Text(tr(
                        "双重物理断网建议：您还可以在 iPhone「设置 → App → Enkard → 无线数据」中选择「关闭」，由 iOS 系统内核再加一道零流量防火墙。",
                        "Defense-in-Depth Tip: You can also set iOS \"Settings → Apps → Enkard → Wireless Data\" to \"Off\" for a kernel-level zero-traffic firewall."
                    ))
                }

                // Biometric & Privacy Controls
                Section {
                    Picker(selection: $store.languageMode) {
                        ForEach(AppLanguageMode.allCases) { mode in
                            Text(mode.displayTitle).tag(mode)
                        }
                    } label: {
                        Label(tr("界面语言", "App Language"), systemImage: "globe")
                    }

                    if store.biometricKind != .none {
                        Toggle(
                            isOn: Binding(
                                get: { store.biometricsEnabled },
                                set: { newValue in
                                    _ = store.setBiometricUnlock(enabled: newValue)
                                }
                            )
                        ) {
                            Label(
                                tr("\(store.biometricKind.displayName)快捷解锁", "\(store.biometricKind.displayName) Unlock"),
                                systemImage: store.biometricKind.systemImage
                            )
                        }
                        .disabled(store.runtimeIntegrity.isCompromised)
                    }

                    Picker(tr("切后台自动锁定", "Auto-Lock in Background"), selection: $store.autoLockTimeout) {
                        ForEach(AutoLockTimeout.allCases) { option in
                            Text(option.title).tag(option)
                        }
                    }

                    Picker(tr("前台空闲自动锁定", "Idle Auto-Lock"), selection: $store.idleLockTimeout) {
                        ForEach(IdleLockTimeout.allCases) { option in
                            Text(option.title).tag(option)
                        }
                    }

                    Picker(tr("剪贴板自动销毁", "Clipboard Auto-Clear"), selection: $store.clipboardClearDuration) {
                        ForEach(ClipboardClearDuration.allCases) { option in
                            Text(option.title).tag(option)
                        }
                    }

                    Button {
                        if store.clipboard.clearIfOwned() {
                            statusBannerMessage = tr(
                                "已立即清空 Enkard 写入剪贴板的内容",
                                "Cleared Enkard clipboard contents immediately"
                            )
                        } else {
                            statusBannerMessage = tr(
                                "剪贴板中当前没有 Enkard 写入的内容",
                                "No Enkard-owned data currently on clipboard"
                            )
                        }
                    } label: {
                        Label(tr("立即清空本机剪贴板", "Clear Local Clipboard Now"), systemImage: "scissors")
                    }
                } header: {
                    Text(tr("语言、解锁与剪贴板策略", "Language, Unlock & Clipboard"))
                } footer: {
                    Text(tr(
                        "语言偏好加密保存于本机专属钥匙串（禁系统备份）。切后台瞬间由顶层独立 UIKit 窗口盖住画面；按电源键锁屏、手动锁定、空闲锁定或倒计时结束时，剪贴板中的卡号/CVV 均会被立即销毁，且绝不通过通用剪贴板同步到其他 Apple 设备。",
                        "Language preference is stored locally in device-only Keychain (never backed up). Switching apps immediately raises an opaque top-level UIKit shield; locking the phone, manual/idle lock, or timer expiry clears copied data and never syncs via Universal Clipboard."
                    ))
                }

                // Brute-force & Coercion Protection
                Section {
                    Toggle(
                        isOn: Binding(
                            get: { store.wipeAfterFailedAttempts },
                            set: { newValue in
                                if newValue {
                                    showingWipeConfirm = true
                                } else {
                                    store.wipeAfterFailedAttempts = false
                                }
                            }
                        )
                    ) {
                        Label(
                            tr(
                                "连续输错 \(LockoutPolicy.wipeThreshold) 次主密码后销毁硬件密钥与数据",
                                "Erase Vault After \(LockoutPolicy.wipeThreshold) Failed Attempts"
                            ),
                            systemImage: "flame.fill"
                        )
                    }

                    if store.biometricsEnabled && store.biometricKind != .none {
                        Button {
                            store.enterEmergencyLockdown()
                            dismiss()
                        } label: {
                            Label(
                                tr(
                                    "立即进入紧急锁定（临时禁用\(store.biometricKind.displayName)）",
                                    "Enter Emergency Lockdown (Disable \(store.biometricKind.displayName))"
                                ),
                                systemImage: "exclamationmark.lock.fill"
                            )
                                .foregroundStyle(.orange)
                        }
                    }
                } header: {
                    Text(tr("防暴力破解与防熟睡/胁迫保护", "Brute-Force & Coercion Protection"))
                } footer: {
                    Text(tr(
                        "错误计数采用 Fail-Closed 机制写入本机专属钥匙串（不同步 iCloud），第 5 次错误起自动挂起生物识别并递增冷却至 1 小时。开启 15 次销毁后，触发时会直接销毁 Secure Enclave 芯片绑定私钥，实现硬件级密码学擦除。",
                        "Failed attempts are stored fail-closed in device-only Keychain (never synced). From attempt 5 onward, biometrics suspend and monotonic cooldown scales up to 1 hour. When 15-attempt wipe is enabled, hitting the limit crypto-shreds the Secure Enclave key."
                    ))
                }

                // Encrypted Offline Backup Section
                Section {
                    Button {
                        guard !store.isScreenCaptured else {
                            store.securityNotice = tr(
                                "录屏或投屏期间禁止导出加密备份。",
                                "Exporting encrypted backups is blocked during screen recording or mirroring."
                            )
                            return
                        }
                        showingExportPasswordPrompt = true
                    } label: {
                        Label(tr("导出离线加密备份 (.enkard)", "Export Offline Backup (.enkard)"), systemImage: "square.and.arrow.up.fill")
                    }
                    .disabled(store.isScreenCaptured)

                    Button {
                        showingFileImporter = true
                    } label: {
                        Label(
                            tr("导入离线加密备份 (.enkard / .cardse / .cardvault)", "Import Offline Backup (.enkard / .cardse / .cardvault)"),
                            systemImage: "square.and.arrow.down.fill"
                        )
                    }
                } header: {
                    Text(tr("纯离线迁移备份（仅换机或重签前使用）", "Offline Migration Backup (Device Switch / Re-signing)"))
                } footer: {
                    Text(tr(
                        "Enkard 严禁任何自动云同步。由于本地加密库绑定了当前手机的安全芯片，换新机前请手动导出备份并保存在「我的 iPhone」本地目录或离线 U 盘中，切勿保存到 iCloud Drive 或网盘。",
                        "Enkard strictly prohibits automatic cloud sync. Because your local vault is bound to this iPhone's Secure Enclave, export an offline backup to \"On My iPhone\" or a physical USB drive before switching devices—never save to iCloud Drive."
                    ))
                }

                // Master Password Rotation
                Section(tr("密钥轮换与锁定", "Key Rotation & Locking")) {
                    Button {
                        showingChangePassword = true
                    } label: {
                        Label(tr("轮换主密码与安全芯片密钥", "Rotate Master Password & Chip Key"), systemImage: "key.horizontal.fill")
                    }

                    Button {
                        store.lock(reason: .manual)
                        dismiss()
                    } label: {
                        Label(tr("立即锁定 Enkard", "Lock Enkard Now"), systemImage: "lock.fill")
                    }
                }

                // Danger Zone
                Section {
                    Button(role: .destructive) {
                        showingDestroySheet = true
                    } label: {
                        Label(tr("销毁安全芯片密钥并彻底擦除卡包", "Destroy Chip Key & Erase Vault"), systemImage: "trash.slash.fill")
                    }
                } footer: {
                    Text(tr(
                        "不可逆操作：将销毁 Secure Enclave 硬件私钥、生物识别密钥与本地密文文件。",
                        "Irreversible: cryptographically shreds the Secure Enclave private key, biometric key, and local ciphertext."
                    ))
                }
            }
            .navigationTitle(tr("安全与离线备份", "Security & Offline Backup"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(tr("完成", "Done")) { dismiss() }
                }
            }
            .confirmationDialog(
                tr(
                    "开启后，连续输错 \(LockoutPolicy.wipeThreshold) 次主密码将直接销毁 Secure Enclave 硬件私钥并擦除所有卡片，无法恢复。请确认您已妥善保存离线备份。",
                    "Once enabled, \(LockoutPolicy.wipeThreshold) consecutive failed master password attempts will destroy the Secure Enclave key and erase all cards permanently. Ensure you keep an offline backup."
                ),
                isPresented: $showingWipeConfirm,
                titleVisibility: .visible
            ) {
                Button(tr("确认开启自动销毁", "Enable Auto-Erase"), role: .destructive) {
                    store.wipeAfterFailedAttempts = true
                }
                Button(tr("取消", "Cancel"), role: .cancel) {}
            }
            .sheet(isPresented: $showingExportPasswordPrompt) {
                ExportBackupPasswordSheet(store: store) { generatedData in
                    exportDocument = EncryptedBackupDocument(data: generatedData)
                    showingFileExporter = true
                }
            }
            .fileExporter(
                isPresented: $showingFileExporter,
                document: exportDocument,
                contentType: .data,
                defaultFilename: defaultBackupFilename()
            ) { result in
                if case .success(let exportedURL) = result {
                    store.warnIfCloudSyncedURL(exportedURL)
                    statusBannerMessage = tr("离线加密备份导出完成", "Offline encrypted backup exported")
                }
                exportDocument = nil
            }
            .fileImporter(
                isPresented: $showingFileImporter,
                allowedContentTypes: [.data, .json],
                allowsMultipleSelection: false
            ) { result in
                switch result {
                case .success(let urls):
                    guard let url = urls.first else { return }
                    let accessed = url.startAccessingSecurityScopedResource()
                    defer { if accessed { url.stopAccessingSecurityScopedResource() } }
                    store.warnIfCloudSyncedURL(url)
                    do {
                        pendingImportData = try VaultCrypto.readBackupFileBounded(at: url)
                        showingImportSheet = true
                    } catch {
                        store.errorMessage = tr(
                            "备份文件无效、包含异常软链接或超过 \(VaultCrypto.maximumBackupFileByteCount / 1024 / 1024) MB 安全上限",
                            "Backup file is invalid, contains a symlink, or exceeds the \(VaultCrypto.maximumBackupFileByteCount / 1024 / 1024) MB safety limit"
                        )
                    }
                case .failure(let error):
                    store.errorMessage = error.localizedDescription
                }
            }
            .sheet(isPresented: $showingImportSheet, onDismiss: {
                pendingImportData = nil
            }) {
                ImportBackupSheet(store: store, data: pendingImportData ?? Data()) { count in
                    statusBannerMessage = tr("成功导入 \(count) 张银行卡", "Successfully imported \(count) card(s)")
                }
            }
            .sheet(isPresented: $showingChangePassword) {
                ChangeMasterPasswordSheet(store: store) {
                    statusBannerMessage = tr(
                        "主密码、DEK 与安全芯片绑定密钥已全部轮换",
                        "Master password, DEK, and hardware key rotated"
                    )
                }
            }
            .sheet(isPresented: $showingDestroySheet) {
                DestroyVaultConfirmSheet(store: store) {
                    dismiss()
                }
            }
            .onValueChange(of: store.isScreenCaptured) { captured in
                if captured {
                    exportDocument = nil
                    showingExportPasswordPrompt = false
                    showingFileExporter = false
                    showingWipeConfirm = false
                }
            }
            .onValueChange(of: store.phase) { newPhase in
                if newPhase != .unlocked {
                    exportDocument = nil
                    pendingImportData = nil
                    showingExportPasswordPrompt = false
                    showingFileExporter = false
                    showingFileImporter = false
                    showingImportSheet = false
                    showingChangePassword = false
                    showingDestroySheet = false
                    showingWipeConfirm = false
                    dismiss()
                }
            }
        }
    }

    private func defaultBackupFilename() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmm"
        return "Enkard-\(formatter.string(from: Date())).enkard"
    }
}

private struct AuditRow: View {
    let icon: String
    var fallbackIcon: String = "shield.fill"
    let label: String
    let value: String
    var isWarning: Bool = false

    var body: some View {
        HStack {
            Label {
                Text(label)
            } icon: {
                Image(systemName: UIImage(systemName: icon) != nil ? icon : fallbackIcon)
                    .foregroundStyle(isWarning ? Color.red : Color.accentColor)
            }
            Spacer()
            Text(value)
                .font(.footnote.weight(.medium))
                .foregroundStyle(isWarning ? Color.red : Color.secondary)
                .multilineTextAlignment(.trailing)
        }
    }
}

private struct ExportBackupPasswordSheet: View {
    @ObservedObject var store: VaultStore
    let onExportReady: (Data) -> Void

    enum Mode: String, CaseIterable, Identifiable {
        case generated
        case custom
        var id: String { rawValue }

        var title: String {
            switch self {
            case .generated: return tr("随机恢复口令（推荐）", "Random Passphrase (Recommended)")
            case .custom: return tr("自定义强密码", "Custom Strong Password")
            }
        }
    }

    @Environment(\.dismiss) private var dismiss
    @State private var currentMasterPassword = ""
    @State private var mode: Mode = .generated
    @State private var generatedPassphrase = PasswordPolicy.generateRecoveryPassphrase()
    @State private var hasRecordedPassphrase = false
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var errorText: String? = nil

    private var effectivePassword: String {
        mode == .generated ? generatedPassphrase : password
    }

    private var canExport: Bool {
        guard !currentMasterPassword.isEmpty else { return false }
        switch mode {
        case .generated:
            return hasRecordedPassphrase
        case .custom:
            return PasswordPolicy.validationMessage(password, for: .backup) == nil
                && password == confirmPassword
                && VaultCrypto.normalizePassword(currentMasterPassword) != VaultCrypto.normalizePassword(password)
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField(
                        tr("输入当前本机主密码以授权导出", "Enter current master password to authorize"),
                        text: $currentMasterPassword
                    )
                        .lockdownTextInput()
                } header: {
                    Text(tr("验证当前本机主密码", "Verify Current Master Password"))
                } footer: {
                    Text(tr(
                        "导出离线备份会剥离本机安全芯片绑定，因此必须验证主密码（仅凭面容/触控 ID 解锁的会话无法直接导出）。",
                        "Exporting an offline backup strips device hardware binding, so master password verification is required (biometric-only sessions cannot export)."
                    ))
                }

                Section {
                    Picker(tr("保护方式", "Protection Method"), selection: $mode) {
                        ForEach(Mode.allCases) { item in
                            Text(item.title).tag(item)
                        }
                    }
                    .pickerStyle(.segmented)
                }

                switch mode {
                case .generated:
                    Section {
                        Text(generatedPassphrase)
                            .font(.system(.title3, design: .monospaced, weight: .semibold))
                            .multilineTextAlignment(.center)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 6)
                            .screenshotProtected()

                        Button {
                            generatedPassphrase = PasswordPolicy.generateRecoveryPassphrase()
                            hasRecordedPassphrase = false
                        } label: {
                            Label(tr("重新生成随机口令", "Regenerate Random Passphrase"), systemImage: "arrow.triangle.2.circlepath")
                        }

                        Toggle(tr("我已离线手写抄录并核对无误", "I have written down and verified this passphrase offline"), isOn: $hasRecordedPassphrase)
                    } header: {
                        Text(tr("一次性 125-bit 恢复口令", "One-Time 125-bit Recovery Passphrase"))
                    } footer: {
                        Text(tr(
                            "共 125 bit 密码学真随机强度，算力穷举在物理上不可行。请手写在纸上离线保管（截图此区域为空白）。口令遗失后任何人都无法解开该备份。",
                            "True 125-bit cryptographic entropy—brute-force is physically infeasible. Write it down on paper offline (screenshots of this area appear blank). Lost passphrases cannot be recovered."
                        ))
                    }
                case .custom:
                    Section {
                        SecureField(tr("备份密码（至少 12 位，≥65 bit）", "Backup password (min 12 chars, ≥65 bits)"), text: $password)
                            .lockdownTextInput()
                        SecureField(tr("再次确认备份密码", "Confirm backup password"), text: $confirmPassword)
                            .lockdownTextInput()
                        if !password.isEmpty {
                            PasswordStrengthIndicator(password: password)
                            if let message = PasswordPolicy.validationMessage(password, for: .backup) {
                                Text(message).font(.caption).foregroundStyle(.orange)
                            }
                        }
                        if !confirmPassword.isEmpty && password != confirmPassword {
                            Text(tr("两次输入不一致", "Passwords do not match")).font(.caption).foregroundStyle(.red)
                        }
                    } header: {
                        Text(tr("自定义备份强口令", "Custom Strong Backup Passphrase"))
                    } footer: {
                        Text(tr(
                            "至少 12 位、强度 ≥65 bit，且禁止与本机主密码相同。",
                            "Minimum 12 characters, ≥65 bits entropy, and must differ from your master password."
                        ))
                    }
                }

                Section {
                    Label(
                        tr(
                            "导出选择保存位置时，请务必选择「我的 iPhone（On My iPhone）」或外接离线 U 盘，请勿选「iCloud 云盘」，确保零云端同步。",
                            "When saving, choose \"On My iPhone\" or an offline USB drive—never \"iCloud Drive\"—to ensure zero cloud sync."
                        ),
                        systemImage: "externaldrive.badge.xmark"
                    )
                    Label(
                        tr(
                            "备份体积已统一按 4KB 块填充对齐，外界无法从文件大小推断卡片数量。",
                            "Backup sizes are padded to 4KB blocks so file size reveals nothing about card count."
                        ),
                        systemImage: "shield.lefthalf.filled"
                    )
                }
                .font(.footnote)
                .foregroundStyle(.secondary)

                if let errorText {
                    Section {
                        Text(errorText)
                            .foregroundStyle(.red)
                            .font(.footnote)
                    }
                }
            }
            .navigationTitle(tr("导出离线加密备份", "Export Offline Backup"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(tr("取消", "Cancel")) {
                        scrubSecrets()
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(store.isBusy ? tr("加密封装中...", "Encrypting...") : tr("下一步", "Next")) {
                        let curMaster = currentMasterPassword
                        let secret = effectivePassword
                        Task {
                            do {
                                let data = try await store.createEncryptedBackupData(
                                    currentMasterPassword: curMaster,
                                    backupPassword: secret
                                )
                                scrubSecrets()
                                dismiss()
                                onExportReady(data)
                            } catch {
                                errorText = error.localizedDescription
                            }
                        }
                    }
                    .disabled(!canExport || store.isBusy)
                }
            }
            .onValueChange(of: store.screenshotEventCount) { _ in
                if mode == .generated && !SecureCanvasSupport.isAvailable {
                    generatedPassphrase = PasswordPolicy.generateRecoveryPassphrase()
                    hasRecordedPassphrase = false
                    errorText = tr(
                        "检测到截屏，已自动作废旧恢复口令并生成新口令。",
                        "Screenshot detected. Previous passphrase invalidated and replaced with a new one."
                    )
                }
            }
            .onValueChange(of: store.phase) { newPhase in
                if newPhase != .unlocked {
                    scrubSecrets()
                    dismiss()
                }
            }
            .onValueChange(of: store.isScreenCaptured) { captured in
                if captured {
                    scrubSecrets()
                    dismiss()
                }
            }
            .onDisappear {
                scrubSecrets()
            }
        }
    }

    private func scrubSecrets() {
        currentMasterPassword = ""
        generatedPassphrase = ""
        password = ""
        confirmPassword = ""
    }
}

private struct ImportBackupSheet: View {
    @ObservedObject var store: VaultStore
    let data: Data
    let onImported: (Int) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var backupPassword = ""
    @State private var mode: BackupImportMode = .merge
    @State private var errorText: String? = nil

    var body: some View {
        NavigationStack {
            Form {
                Section(tr("输入离线备份密码或恢复口令", "Enter Offline Backup Passphrase")) {
                    SecureField(tr("备份文件的口令", "Backup passphrase"), text: $backupPassword)
                        .lockdownTextInput()
                }

                Section(tr("导入方式", "Import Mode")) {
                    Picker(tr("模式", "Mode"), selection: $mode) {
                        ForEach(BackupImportMode.allCases) { item in
                            Text(item.title).tag(item)
                        }
                    }
                    .pickerStyle(.inline)
                }

                if let errorText {
                    Section {
                        Text(errorText)
                            .foregroundStyle(.red)
                            .font(.footnote)
                    }
                }
            }
            .navigationTitle(tr("导入离线加密备份", "Import Offline Backup"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(tr("取消", "Cancel")) {
                        backupPassword = ""
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(store.isBusy ? tr("解密中...", "Decrypting...") : tr("解密导入", "Decrypt & Import")) {
                        let pass = backupPassword
                        Task {
                            do {
                                let count = try await store.importEncryptedBackup(
                                    data: data,
                                    backupPassword: pass,
                                    mode: mode
                                )
                                backupPassword = ""
                                dismiss()
                                onImported(count)
                            } catch {
                                errorText = error.localizedDescription
                            }
                        }
                    }
                    .disabled(backupPassword.isEmpty || store.isBusy)
                }
            }
            .onValueChange(of: store.phase) { newPhase in
                if newPhase != .unlocked {
                    backupPassword = ""
                    dismiss()
                }
            }
            .onDisappear {
                backupPassword = ""
            }
        }
    }
}

private struct ChangeMasterPasswordSheet: View {
    @ObservedObject var store: VaultStore
    let onSuccess: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var currentPassword = ""
    @State private var newPassword = ""
    @State private var confirmPassword = ""

    var body: some View {
        NavigationStack {
            Form {
                Section(tr("验证当前主密码", "Verify Current Master Password")) {
                    SecureField(tr("输入当前主密码", "Current master password"), text: $currentPassword)
                        .lockdownTextInput()
                }

                Section {
                    SecureField(tr("新主密码（至少 8 位，≥40 bit）", "New master password (min 8 chars, ≥40 bits)"), text: $newPassword)
                        .lockdownTextInput()
                    SecureField(tr("确认新主密码", "Confirm new master password"), text: $confirmPassword)
                        .lockdownTextInput()
                    if !newPassword.isEmpty {
                        PasswordStrengthIndicator(password: newPassword)
                        if let message = PasswordPolicy.validationMessage(newPassword, for: .master) {
                            Text(message).font(.caption).foregroundStyle(.orange)
                        }
                    }
                } header: {
                    Text(tr("设置新主密码", "Set New Master Password"))
                } footer: {
                    Text(tr(
                        "将同步轮换随机盐、数据密钥（DEK）与 Secure Enclave 安全芯片私钥。此前已导出的离线备份仍须用导出时的备份口令解开。",
                        "Rotates salt, DEK, and Secure Enclave hardware key simultaneously. Previously exported backups still use their original export passphrase."
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
            .navigationTitle(tr("轮换主密码与芯片密钥", "Rotate Master Password & Key"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(tr("取消", "Cancel")) {
                        scrubState()
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(store.isBusy ? tr("硬件重加密中...", "Re-encrypting...") : tr("确认轮换", "Rotate Keys")) {
                        let cur = currentPassword
                        let next = newPassword
                        Task {
                            let ok = await store.changeMasterPassword(
                                currentPassword: cur,
                                newPassword: next
                            )
                            if ok {
                                scrubState()
                                dismiss()
                                onSuccess()
                            }
                        }
                    }
                    .disabled(
                        currentPassword.isEmpty
                            || PasswordPolicy.validationMessage(newPassword, for: .master) != nil
                            || newPassword != confirmPassword
                            || store.isBusy
                    )
                }
            }
            .onValueChange(of: store.phase) { newPhase in
                if newPhase != .unlocked {
                    scrubState()
                    dismiss()
                }
            }
            .onDisappear {
                scrubState()
            }
        }
    }

    private func scrubState() {
        currentPassword = ""
        newPassword = ""
        confirmPassword = ""
    }
}

private struct DestroyVaultConfirmSheet: View {
    @ObservedObject var store: VaultStore
    let onDestroyed: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var confirmText = ""
    @State private var masterPassword = ""

    private var isConfirmed: Bool {
        confirmText == "销毁"
            || confirmText.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() == "DESTROY"
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(tr(
                        "此操作将销毁本机 Secure Enclave 硬件绑定私钥、生物识别密钥及本地加密数据。若无离线 .enkard 备份，卡片信息将永久无法恢复。",
                        "This permanently shreds the Secure Enclave hardware key, biometric key, and local encrypted vault. Without an offline .enkard backup, your cards cannot be recovered."
                    ))
                        .font(.subheadline)
                        .foregroundStyle(.red)

                    TextField(tr("请输入「销毁」两个字确认", "Type \"DESTROY\" to confirm"), text: $confirmText)
                        .lockdownTextInput()

                    SecureField(tr("输入当前主密码授权销毁", "Enter current master password"), text: $masterPassword)
                        .lockdownTextInput()
                }

                if let error = store.errorMessage {
                    Section {
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle(tr("销毁本机卡包", "Erase Local Vault"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(tr("取消", "Cancel")) {
                        confirmText = ""
                        masterPassword = ""
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(store.isBusy ? tr("验证中...", "Verifying...") : tr("永久销毁", "Erase Forever"), role: .destructive) {
                        let entered = masterPassword
                        masterPassword = ""
                        Task {
                            if await store.destroyVaultAfterReauth(masterPassword: entered) {
                                confirmText = ""
                                dismiss()
                                onDestroyed()
                            }
                        }
                    }
                    .disabled(!isConfirmed || masterPassword.isEmpty || store.isBusy)
                }
            }
            .onValueChange(of: store.phase) { newPhase in
                if newPhase != .unlocked {
                    confirmText = ""
                    masterPassword = ""
                    dismiss()
                }
            }
            .onDisappear {
                confirmText = ""
                masterPassword = ""
            }
        }
    }
}
