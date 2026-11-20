# Enkard

> **An Offline-Only Private Card Vault Bound to Your iPhone's Secure Enclave**  
> Zero Networking Code · Zero Cloud Sync · Zero Privacy Permissions · Zero Third-Party Dependencies · Dual-Factor Hardware Cryptography

[简体中文](README.md) · **English** · [📖 Full Feature & Security Architecture Guide](docs/DETAILS_EN.md)

**Enkard** (`v2.4.0`) is a native iOS bank and virtual card vault engineered specifically for local sideloading and self-signing. It seals your credit, debit, and virtual card details (card number, expiry date, CVV, legacy PIN, billing address, statement/due cycle, and encrypted notes) behind both your master password and your iPhone's physical **Secure Enclave**—with **no networking, no cloud sync, and no camera or photo library permissions**, eliminating remote leaks and third-party SDK supply-chain exposure at the root.

---

## Key Highlights

### Card Management Experience
- **Native Bilingual UI (English / 简体中文)**: Full in-app UI, security alerts, password strength diagnostics, and system Face ID prompts in both English and Simplified Chinese. Supports instant **Follow System / 简体中文 / English** switching, stored in `EKM1` HMAC-authenticated, device-only Keychain (never `UserDefaults`).
- **Card Types & Smart Network Detection**: Supports Credit, Debit, and Virtual cards; automatically identifies **UnionPay, Visa, Mastercard, AMEX, JCB, and Discover** with automatic AMEX `4-6-5` formatting and real-time Luhn check-digit validation.
- **8 Metallic Card Finishes**: Includes Obsidian Gold, Midnight Blue, Titanium Slate, Emerald Jade, Crimson Ruby, Royal Violet, Aurora Teal, and Rose Bronze, with favorite pinning and instant local search across English and Chinese network keywords.
- **Billing Cycle & Expiration Alerts**: Track credit limits, monthly statement/due days, and get clear visual indicators when cards are expiring soon or expired.
- **Masked by Default + Local Self-Destructing Clipboard**: Sensitive values stay masked until revealed inside a screenshot-protected layer. Copied data sets `.localOnly = true` (blocking Universal Clipboard Handoff) with **10–60s auto-expiration** and immediate wipe on screen lock.
- **Face ID + 1-Tap Emergency Lockdown**: Unlock seamlessly with Face ID / Touch ID day-to-day, or trigger **Emergency Lockdown** before sleeping, border crossings, or device repair to purge biometric keys and require your master password.
- **`.enkard` Offline Encrypted Backups**: Built-in 125-bit random recovery passphrase generator for offline device migration without touching any cloud service.

### Bank-Grade+ Defense-in-Depth Overview

| Defense Layer | Summary |
| :--- | :--- |
| **Complete Offline & Zero-Sync Isolation** | Zero networking code + `OfflineKillSwitchURLProtocol` circuit breaker; disables iCloud Keychain sync, system backups, all 3rd-party keyboards/extensions, and Apple Intelligence Writing Tools; POSIX `SafeVaultFileIO` (`O_NOFOLLOW` / `openat` + 40 MB cap) |
| **Dual-Factor Hardware Cryptography** | `PBKDF2-HMAC-SHA256` (≥ 600k dynamically calibrated rounds) + non-exportable **Secure Enclave** P-256 ECDH → `AES-256-GCM` envelope encryption + `4 KB` block padding against size side-channels |
| **Authenticated State & Anti-Brute-Force** | Device-bound Keychain `EKM1` `HMAC-SHA256` state authentication, fail-closed pre-KDF attempt counter, `CLOCK_MONOTONIC` backoff scaling to 1 hr, anti-rollback watermarks, and optional 15-attempt crypto-shredding |
| **Self-Signed Runtime Self-Defense** | Early native `PT_DENY_ATTACH` kernel anti-debug stub, Mach-O `__interpose` section scan, 19 critical symbol origin audits, 17 GOT import-table pointer checks, and `dyld_v1` shared-cache structural validation |
| **Memory & Screen Leak Prevention** | C11 `memset_s` zeroization + zero-CoW single-owner buffers, full symbol & Swift reflection stripping, secure-canvas blanking + alert-exceeding privacy shield window, Unicode Bidi spoofing sanitization |
| **Re-Signing Supply-Chain Verification** | Ships with `verify_signed_ipa.sh` to audit signed IPAs against ZIP symlink traversal, injected dylibs, 38 Mach-O/resource SHA-256 baseline hashes, and zero-sync entitlements |

👉 For the full cryptographic protocol specification, 6-layer defense deep dive, and honest platform boundaries, read **[docs/DETAILS_EN.md](docs/DETAILS_EN.md)**.

---

## Quick Download & Verification

### 1. Download Unsigned IPA & Self-Sign
Download the latest `Enkard-unsigned.ipa` and `Enkard-integrity.sha256` from **[GitHub Releases](https://github.com/Kianuni/Enkard/releases)** and sign locally with your Apple account (Xcode or Sideloadly in local mode with all tweak/dylib injection options turned **off**).

After signing, run the supply-chain verifier on macOS to confirm your signing tool did not inject or alter any code:

```bash
chmod +x scripts/verify_signed_ipa.sh
./scripts/verify_signed_ipa.sh /path/to/signed.ipa
```

### 2. Build from Source

```bash
chmod +x scripts/build_ipa.sh scripts/verify_signed_ipa.sh
./scripts/build_ipa.sh   # Outputs dist/Enkard-unsigned.ipa & dist/Enkard-integrity.sha256
```

---

## Upgrading & Important Notes

- **Seamless Upgrade from CardSe / v2.2 / v2.3**: Bundle ID (`com.local.cardse.app`), Keychain identifiers, Secure Enclave key tags, and local storage remain 100% compatible. Overwrite-install with the same signing certificate to retain all cards and settings seamlessly; legacy `.cardse` and `.cardvault` backups remain importable.
- **Never Turn Off Your Device Passcode**: Hardware keys use `WhenPasscodeSetThisDeviceOnly`. Disabling your iPhone passcode causes iOS to permanently erase Secure Enclave keys (always export an `.enkard` offline backup before resetting your passcode or switching devices).

---

## License & Disclaimer

Licensed under the **[GNU General Public License v3.0 (GPL-3.0)](LICENSE)**. You are free to study, audit, build, and use Enkard for personal use; any distributed derivative work must also be open-sourced in full under `GPL-3.0` (closed-source commercial repackaging is prohibited).

> **Disclaimer**: This software is provided "AS IS" without warranties of any kind. Enkard has no backend servers and no password recovery mechanism. Always memorize your master password and maintain offline encrypted backups; data loss caused by forgotten passwords, disabled device passcodes, or hardware failure is solely the user's responsibility.
