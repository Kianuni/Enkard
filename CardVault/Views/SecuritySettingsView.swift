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
                    AuditRow(icon: "wifi.slash", label: "网络与同步", value: "进程断网拦截已激活 · 零云同步")
                    AuditRow(icon: "cpu.fill", label: "硬件密钥绑定", value: store.hardwareProtectionDescription)
                    AuditRow(
                        icon: store.runtimeIntegrity.isCompromised ? "exclamationmark.triangle.fill" : "checkmark.shield.fill",
                        label: "运行时完整性",
                        value: store.runtimeIntegrity.summaryText,
                        isWarning: store.runtimeIntegrity.isCompromised
                    )
                    AuditRow(icon: "keyboard", label: "扩展与 AI 输入", value: "封禁全部第三方扩展 · 禁写作工具")
                    AuditRow(icon: "lock.doc.fill", label: "信封加密协议", value: "LOCAL_V2 · 4KB 填充防侧信道")
                    AuditRow(icon: "speedometer", label: "PBKDF2 迭代", value: "\(store.kdfIterations.formatted()) 次")
                    AuditRow(
                        icon: "camera.metering.none",
                        label: "截图与录屏防护",
                        value: SecureCanvasSupport.isAvailable ? "安全图层空白渲染 + 独立遮罩窗" : "录屏遮罩已开启（无截图图层）"
                    )
                    AuditRow(icon: "internaldrive.fill", label: "本机存储保护", value: "锁屏销毁内存密钥 · 禁系统备份")
                } header: {
                    Text("CardSe 最高安全状态")
                } footer: {
                    Text("双重物理断网建议：您还可以在 iPhone「设置 → App → CardSe → 无线数据」中选择「关闭」，由 iOS 系统内核再加一道零流量防火墙。")
                }

                // Biometric & Privacy Controls
                Section {
                    if store.biometricKind != .none {
                        Toggle(
                            isOn: Binding(
                                get: { store.biometricsEnabled },
                                set: { newValue in
                                    _ = store.setBiometricUnlock(enabled: newValue)
                                }
                            )
                        ) {
                            Label("\(store.biometricKind.displayName)快捷解锁", systemImage: store.biometricKind.systemImage)
                        }
                        .disabled(store.runtimeIntegrity.isCompromised)
                    }

                    Picker("切后台自动锁定", selection: $store.autoLockTimeout) {
                        ForEach(AutoLockTimeout.allCases) { option in
                            Text(option.title).tag(option)
                        }
                    }

                    Picker("前台空闲自动锁定", selection: $store.idleLockTimeout) {
                        ForEach(IdleLockTimeout.allCases) { option in
                            Text(option.title).tag(option)
                        }
                    }

                    Picker("剪贴板自动销毁", selection: $store.clipboardClearDuration) {
                        ForEach(ClipboardClearDuration.allCases) { option in
                            Text(option.title).tag(option)
                        }
                    }

                    Button {
                        if store.clipboard.clearIfOwned() {
                            statusBannerMessage = "已立即清空 CardSe 写入剪贴板的内容"
                        } else {
                            statusBannerMessage = "剪贴板中当前没有 CardSe 写入的内容"
                        }
                    } label: {
                        Label("立即清空本机剪贴板", systemImage: "scissors")
                    }
                } header: {
                    Text("解锁、遮罩与剪贴板策略")
                } footer: {
                    Text("切后台瞬间由顶层独立 UIKit 窗口盖住画面；按电源键锁屏、手动锁定、空闲锁定或倒计时结束时，剪贴板中的卡号/CVV 均会被立即销毁，且绝不通过通用剪贴板同步到其他 Apple 设备。")
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
                        Label("连续输错 \(LockoutPolicy.wipeThreshold) 次主密码后销毁硬件密钥与数据", systemImage: "flame.fill")
                    }

                    if store.biometricsEnabled && store.biometricKind != .none {
                        Button {
                            store.enterEmergencyLockdown()
                            dismiss()
                        } label: {
                            Label("立即进入紧急锁定（临时禁用\(store.biometricKind.displayName)）", systemImage: "exclamationmark.lock.fill")
                                .foregroundStyle(.orange)
                        }
                    }
                } header: {
                    Text("防暴力破解与防熟睡/胁迫保护")
                } footer: {
                    Text("错误计数采用 Fail-Closed 机制写入本机专属钥匙串（不同步 iCloud），第 5 次错误起自动挂起生物识别并递增冷却至 1 小时。开启 15 次销毁后，触发时会直接销毁 Secure Enclave 芯片绑定私钥，实现硬件级密码学擦除。")
                }

                // Encrypted Offline Backup Section
                Section {
                    Button {
                        guard !store.isScreenCaptured else {
                            store.securityNotice = "录屏或投屏期间禁止导出加密备份。"
                            return
                        }
                        showingExportPasswordPrompt = true
                    } label: {
                        Label("导出离线加密备份 (.cardse)", systemImage: "square.and.arrow.up.fill")
                    }
                    .disabled(store.isScreenCaptured)

                    Button {
                        showingFileImporter = true
                    } label: {
                        Label("导入离线加密备份 (.cardse / .cardvault)", systemImage: "square.and.arrow.down.fill")
                    }
                } header: {
                    Text("纯离线迁移备份（仅换机或重签前使用）")
                } footer: {
                    Text("CardSe 严禁任何自动云同步。由于本地加密库绑定了当前手机的安全芯片，换新机前请手动导出备份并保存在「我的 iPhone」本地目录或离线 U 盘中，切勿保存到 iCloud Drive 或网盘。")
                }

                // Master Password Rotation
                Section("密钥轮换与锁定") {
                    Button {
                        showingChangePassword = true
                    } label: {
                        Label("轮换主密码与安全芯片密钥", systemImage: "key.horizontal.fill")
                    }

                    Button {
                        store.lock(reason: .manual)
                        dismiss()
                    } label: {
                        Label("立即锁定 CardSe", systemImage: "lock.fill")
                    }
                }

                // Danger Zone
                Section {
                    Button(role: .destructive) {
                        showingDestroySheet = true
                    } label: {
                        Label("销毁安全芯片密钥并彻底擦除卡包", systemImage: "trash.slash.fill")
                    }
                } footer: {
                    Text("不可逆操作：将销毁 Secure Enclave 硬件私钥、生物识别密钥与本地密文文件。")
                }
            }
            .navigationTitle("安全与离线备份")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("完成") { dismiss() }
                }
            }
            .confirmationDialog(
                "开启后，连续输错 \(LockoutPolicy.wipeThreshold) 次主密码将直接销毁 Secure Enclave 硬件私钥并擦除所有卡片，无法恢复。请确认您已妥善保存离线备份。",
                isPresented: $showingWipeConfirm,
                titleVisibility: .visible
            ) {
                Button("确认开启自动销毁", role: .destructive) {
                    store.wipeAfterFailedAttempts = true
                }
                Button("取消", role: .cancel) {}
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
                    statusBannerMessage = "离线加密备份导出完成"
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
                    if let data = try? Data(contentsOf: url) {
                        pendingImportData = data
                        showingImportSheet = true
                    }
                case .failure(let error):
                    store.errorMessage = error.localizedDescription
                }
            }
            .sheet(isPresented: $showingImportSheet, onDismiss: {
                pendingImportData = nil
            }) {
                ImportBackupSheet(store: store, data: pendingImportData ?? Data()) { count in
                    statusBannerMessage = "成功导入 \(count) 张银行卡"
                }
            }
            .sheet(isPresented: $showingChangePassword) {
                ChangeMasterPasswordSheet(store: store) {
                    statusBannerMessage = "主密码、DEK 与安全芯片绑定密钥已全部轮换"
                }
            }
            .sheet(isPresented: $showingDestroySheet) {
                DestroyVaultConfirmSheet(store: store) {
                    dismiss()
                }
            }
        }
    }

    private func defaultBackupFilename() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmm"
        return "CardSe-\(formatter.string(from: Date())).cardse"
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
        case generated = "随机恢复口令（推荐）"
        case custom = "自定义强密码"
        var id: String { rawValue }
    }

    @Environment(\.dismiss) private var dismiss
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
        switch mode {
        case .generated:
            return hasRecordedPassphrase
        case .custom:
            return PasswordPolicy.validationMessage(password, for: .backup) == nil && password == confirmPassword
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("保护方式", selection: $mode) {
                        ForEach(Mode.allCases) { item in
                            Text(item.rawValue).tag(item)
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
                            Label("重新生成随机口令", systemImage: "arrow.triangle.2.circlepath")
                        }

                        Toggle("我已离线手写抄录并核对无误", isOn: $hasRecordedPassphrase)
                    } header: {
                        Text("一次性 125-bit 恢复口令")
                    } footer: {
                        Text("共 125 bit 密码学真随机强度，算力穷举在物理上不可行。请手写在纸上离线保管（截图此区域为空白）。口令遗失后任何人都无法解开该备份。")
                    }
                case .custom:
                    Section {
                        SecureField("备份密码（至少 12 位，≥65 bit）", text: $password)
                            .lockdownTextInput()
                        SecureField("再次确认备份密码", text: $confirmPassword)
                            .lockdownTextInput()
                        if !password.isEmpty {
                            PasswordStrengthIndicator(password: password)
                            if let message = PasswordPolicy.validationMessage(password, for: .backup) {
                                Text(message).font(.caption).foregroundStyle(.orange)
                            }
                        }
                        if !confirmPassword.isEmpty && password != confirmPassword {
                            Text("两次输入不一致").font(.caption).foregroundStyle(.red)
                        }
                    } header: {
                        Text("自定义备份强口令")
                    } footer: {
                        Text("至少 12 位、强度 ≥65 bit，且禁止与本机主密码相同。")
                    }
                }

                Section {
                    Label("导出选择保存位置时，请务必选择「我的 iPhone（On My iPhone）」或外接离线 U 盘，请勿选「iCloud 云盘」，确保零云端同步。", systemImage: "externaldrive.badge.xmark")
                    Label("备份体积已统一按 4KB 块填充对齐，外界无法从文件大小推断卡片数量。", systemImage: "shield.lefthalf.filled")
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
            .navigationTitle("导出离线加密备份")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") {
                        scrubSecrets()
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(store.isBusy ? "加密封装中..." : "下一步") {
                        let secret = effectivePassword
                        Task {
                            do {
                                let data = try await store.createEncryptedBackupData(password: secret)
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
                    errorText = "检测到截屏，已自动作废旧恢复口令并生成新口令。"
                }
            }
            .onDisappear {
                scrubSecrets()
            }
        }
    }

    private func scrubSecrets() {
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
                Section("输入离线备份密码或恢复口令") {
                    SecureField("备份文件的口令", text: $backupPassword)
                        .lockdownTextInput()
                }

                Section("导入方式") {
                    Picker("模式", selection: $mode) {
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
            .navigationTitle("导入离线加密备份")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") {
                        backupPassword = ""
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(store.isBusy ? "解密中..." : "解密导入") {
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
                Section("验证当前主密码") {
                    SecureField("输入当前主密码", text: $currentPassword)
                        .lockdownTextInput()
                }

                Section {
                    SecureField("新主密码（至少 8 位，≥40 bit）", text: $newPassword)
                        .lockdownTextInput()
                    SecureField("确认新主密码", text: $confirmPassword)
                        .lockdownTextInput()
                    if !newPassword.isEmpty {
                        PasswordStrengthIndicator(password: newPassword)
                        if let message = PasswordPolicy.validationMessage(newPassword, for: .master) {
                            Text(message).font(.caption).foregroundStyle(.orange)
                        }
                    }
                } header: {
                    Text("设置新主密码")
                } footer: {
                    Text("将同步轮换随机盐、数据密钥（DEK）与 Secure Enclave 安全芯片私钥。此前已导出的离线备份仍须用导出时的备份口令解开。")
                }

                if let error = store.errorMessage {
                    Section {
                        Text(error)
                            .foregroundStyle(.red)
                            .font(.footnote)
                    }
                }
            }
            .navigationTitle("轮换主密码与芯片密钥")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") {
                        scrubState()
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(store.isBusy ? "硬件重加密中..." : "确认轮换") {
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

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("此操作将销毁本机 Secure Enclave 硬件绑定私钥、生物识别密钥及本地加密数据。若无离线 .cardse 备份，卡片信息将永久无法恢复。")
                        .font(.subheadline)
                        .foregroundStyle(.red)

                    TextField("请输入「销毁」两个字确认", text: $confirmText)
                        .lockdownTextInput()
                }
            }
            .navigationTitle("销毁本机卡包")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") {
                        confirmText = ""
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("永久销毁", role: .destructive) {
                        confirmText = ""
                        store.destroyVaultCompletely()
                        dismiss()
                        onDestroyed()
                    }
                    .disabled(confirmText != "销毁")
                }
            }
            .onDisappear {
                confirmText = ""
            }
        }
    }
}
