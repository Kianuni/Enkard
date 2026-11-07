import SwiftUI

struct LockScreenView: View {
    @ObservedObject var store: VaultStore

    @State private var password = ""
    @State private var didAutoTriggerBiometrics = false
    @FocusState private var passwordFocused: Bool

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    Color(red: 0.06, green: 0.07, blue: 0.11),
                    Color(red: 0.10, green: 0.12, blue: 0.18)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            VStack(spacing: 24) {
                if store.runtimeIntegrity.isCompromised {
                    RuntimeCompromiseBanner(text: store.runtimeIntegrity.summaryText)
                        .padding(.top, 12)
                }

                Spacer()

                // Vault Emblem
                VStack(spacing: 14) {
                    ZStack {
                        Circle()
                            .fill(Color.white.opacity(0.07))
                            .frame(width: 92, height: 92)
                        Image(systemName: store.isLockdownModeActive ? "exclamationmark.lock.fill" : "lock.shield.fill")
                            .font(.system(size: 42))
                            .foregroundStyle(
                                LinearGradient(
                                    colors: [
                                        Color(red: 0.95, green: 0.82, blue: 0.52),
                                        Color(red: 0.78, green: 0.60, blue: 0.30)
                                    ],
                                    startPoint: .top,
                                    endPoint: .bottom
                                )
                            )
                    }

                    Text(store.isLockdownModeActive ? "Enkard 紧急锁定中" : "Enkard 已锁定")
                        .font(.title2.bold())
                        .foregroundStyle(.white)

                    HStack(spacing: 6) {
                        Image(systemName: "cpu.fill")
                        Text("断网零同步 · Secure Enclave 硬件保护中")
                    }
                    .font(.caption)
                    .foregroundStyle(.white.opacity(0.58))
                }

                // Biometric Primary Button (hidden automatically during lockout cooldown or emergency lockdown)
                if store.canUseBiometricUnlock {
                    Button {
                        Task {
                            _ = await store.unlockWithBiometrics()
                        }
                    } label: {
                        HStack(spacing: 10) {
                            Image(systemName: store.biometricKind.systemImage)
                                .font(.system(size: 20, weight: .semibold))
                            Text("使用\(store.biometricKind.displayName)解锁")
                                .fontWeight(.semibold)
                        }
                        .foregroundStyle(.black)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 15)
                        .background(
                            LinearGradient(
                                colors: [
                                    Color(red: 0.96, green: 0.84, blue: 0.55),
                                    Color(red: 0.84, green: 0.68, blue: 0.37)
                                ],
                                startPoint: .leading,
                                endPoint: .trailing
                            ),
                            in: RoundedRectangle(cornerRadius: 14, style: .continuous)
                        )
                    }
                    .disabled(store.isBusy)
                } else if store.biometricsEnabled && store.isBiometricSuspendedBySecurityPolicy {
                    HStack(spacing: 6) {
                        Image(systemName: "hand.raised.slash.fill")
                        Text("已暂停\(store.biometricKind.displayName)快捷解锁，必须验证主密码")
                    }
                    .font(.caption)
                    .foregroundStyle(Color(red: 0.96, green: 0.80, blue: 0.45))
                }

                // Master Password Box (Always SecureField — never converted to plain TextField)
                VStack(spacing: 12) {
                    SecureField("输入主密码解锁", text: $password)
                        .lockdownTextInput()
                        .focused($passwordFocused)
                        .submitLabel(.go)
                        .foregroundStyle(.white)
                        .onValueChange(of: password) { val in
                            if val.count > VaultCrypto.maximumPasswordLength {
                                password = String(val.prefix(VaultCrypto.maximumPasswordLength))
                            }
                        }
                        .onSubmit {
                            submitPassword()
                        }
                        .padding(14)
                        .background(Color.white.opacity(0.09), in: RoundedRectangle(cornerRadius: 13, style: .continuous))
                        .overlay(
                            RoundedRectangle(cornerRadius: 13, style: .continuous)
                                .strokeBorder(Color.white.opacity(0.15), lineWidth: 0.8)
                        )

                    Button(action: submitPassword) {
                        HStack(spacing: 8) {
                            if store.isBusy {
                                ProgressView().tint(.white)
                            } else {
                                Image(systemName: "key.fill")
                            }
                            Text(store.isBusy ? "正在验证安全芯片与密钥..." : "主密码解锁")
                                .fontWeight(.semibold)
                        }
                        .foregroundStyle(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(Color.white.opacity(0.15), in: RoundedRectangle(cornerRadius: 13, style: .continuous))
                    }
                    .disabled(password.isEmpty || store.isBusy)
                }

                if let error = store.errorMessage {
                    Text(error)
                        .font(.footnote)
                        .foregroundStyle(Color(red: 1.0, green: 0.45, blue: 0.45))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }

                Spacer()

                // 1-Tap Emergency Biometric Kill-Switch right on the lock screen (sleep / customs / repair protection)
                if store.canUseBiometricUnlock {
                    Button {
                        store.enterEmergencyLockdown()
                    } label: {
                        Label("紧急禁用\(store.biometricKind.displayName)（下次必须输主密码）", systemImage: "exclamationmark.lock.fill")
                            .font(.caption.weight(.medium))
                            .foregroundStyle(.white.opacity(0.65))
                            .padding(.vertical, 8)
                            .padding(.horizontal, 14)
                            .background(Color.white.opacity(0.06), in: Capsule())
                    }
                    .buttonStyle(.plain)
                    .padding(.bottom, 12)
                } else {
                    Spacer().frame(height: 12)
                }
            }
            .padding(.horizontal, 26)
        }
        .environment(\.colorScheme, .dark)
        .preferredColorScheme(.dark)
        .task {
            guard !didAutoTriggerBiometrics else { return }
            didAutoTriggerBiometrics = true
            if store.canUseBiometricUnlock && !store.isAppInactive {
                _ = await store.unlockWithBiometrics()
            }
        }
        .onDisappear {
            password = ""
        }
    }

    private func submitPassword() {
        guard !password.isEmpty, !store.isBusy else { return }
        let entered = password
        password = ""
        Task {
            _ = await store.unlockWithMasterPassword(entered)
        }
    }
}
