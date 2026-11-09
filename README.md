# Enkard

> **装在 iPhone 安全芯片里的纯离线私人卡包**  
> 零联网代码 · 零云端同步 · 零隐私权限 · 零第三方依赖 · Apple Secure Enclave 硬件双因子加密

**Enkard**（当前版本 `v2.3.2`）是一款专为 iPhone 本地自签打造的原生银行卡与金融卡片保险库。它将你的信用卡、借记卡、虚拟卡敏感信息（卡号、有效期、CVV、PIN、账单地址、账单/还款日等）完全封存在手机物理安全芯片（Secure Enclave）与你的主密码双重保护之下——**不联网、不上云、不申请相机或相册权限**，从根源上消除云端泄露与第三方 SDK 风险。

📖 **[点击查看《Enkard 完整功能与银行级+安全架构详解》 →](docs/DETAILS.md)**

---

## 核心亮点

### 卡片管理体验
- **多卡种与智能卡组织识别**：支持信用卡、借记卡、虚拟卡；输入卡号自动识别 **银联、Visa、Mastercard、AMEX、JCB、Discover** 并执行 Luhn 校验。
- **8 款暗色金属卡面**：内置曜石黑金、深海鎏蓝、钛金深灰、翡翠暗绿等 8 款渐变主题，支持常用卡收藏置顶与秒级本地检索。
- **账单与到期提醒**：支持记录授信额度、每月账单日与还款日，卡片临近到期自动标记提醒。
- **默认脱敏 + 本机自毁剪贴板**：敏感字段默认掩码隐藏；复制时强制锁定本机剪贴板（禁绝通用剪贴板跨设备广播），支持 **10–60 秒自动销毁** 与锁屏即清。
- **面容 ID + 一键紧急锁定**：日常支持 Face ID / Touch ID 秒开；熟睡、过检或送修前可一键进入「紧急锁定」，强制仅凭主密码解锁。
- **`.enkard` 离线加密迁移备份**：内置 125-bit 随机恢复口令生成器，无需任何云服务即可安全完成换机迁移。

### 银行级+ 纵深防御速览

| 防御维度 | 核心机制简述 |
| :--- | :--- |
| **彻底断网零同步** | 零联网代码 + `OfflineKillSwitchURLProtocol` 进程熔断；禁 iCloud 钥匙串、禁系统备份、禁全部第三方扩展与键盘、禁 Apple Intelligence 写作工具 |
| **硬件双因子加密** | 主密码 `PBKDF2-HMAC-SHA256`（≥ 60 万次动态校准）+ **Secure Enclave** 不可导出 P-256 芯片私钥 ECDH → `AES-256-GCM` 信封加密 + `4 KB` 填充防体积侧信道 |
| **状态认证与防爆破** | 钥匙串 `EKM1` 专属 `HMAC-SHA256` 防篡改签名、PBKDF2 前置计次、内核单调时钟递增冷却、防回滚版本号与可选 15 次硬件级密码学自毁 |
| **自签运行时自卫** | 启动原生桩 `PT_DENY_ATTACH` 内核反调试、Mach-O 劫持段扫描、19 项安全符号归属核验、17 项导入表（GOT）重绑定与 `dyld_v1` 共享缓存头结构验证 |
| **内存与屏幕防泄露** | C11 `memset_s` 抗优化清零 + 零 CoW 独立缓冲、全符号与反射名剥离、防截屏录屏安全图层 + 超 Alert 级独立遮罩窗、Unicode Bidi 反欺骗净化 |
| **供应链重签校验** | 提供 `verify_signed_ipa.sh`，对自签后的 IPA 执行 ZIP 符号链接拦截、注入库检测、38 项二进制代码/资源段 SHA-256 基线核对与权限审计 |

👉 关于完整的密码学协议设计、六层防御细节与平台客观物理边界说明，请阅读独立文档：**[docs/DETAILS.md](docs/DETAILS.md)**。

---

## 快速获取与自签校验

### 1. 下载未签名包自签
前往 **[GitHub Releases](https://github.com/Kianuni/Enkard/releases)** 下载最新 `Enkard-unsigned.ipa` 与 `Enkard-integrity.sha256`，使用你本人的 Apple 账号在本地签名（Xcode 或 Sideloadly 本地模式，请关闭一切插件/Dylib 注入选项）。

签名完成后，可在 macOS 终端运行校验脚本验证包体未被签名工具篡改：

```bash
chmod +x scripts/verify_signed_ipa.sh
./scripts/verify_signed_ipa.sh /path/to/signed.ipa
```

### 2. 从源码本地构建

```bash
chmod +x scripts/build_ipa.sh scripts/verify_signed_ipa.sh
./scripts/build_ipa.sh   # 输出至 dist/Enkard-unsigned.ipa 与 dist/Enkard-integrity.sha256
```

---

## 升级与重要提示

- **从 CardSe 无缝升级**：`v2.2.0` 起应用更名为 **Enkard**，Bundle ID（`com.local.cardse.app`）与底层加密存储保持兼容，使用同一证书直接覆盖安装即可无缝保留全部卡片；旧版 `.cardse` / `.cardvault` 备份亦可直接导入。
- **切勿关闭手机锁屏密码**：硬件密钥绑定 iPhone 锁屏密码（`WhenPasscodeSetThisDeviceOnly`），关闭系统锁屏密码会导致安全芯片永久清除密钥（重置密码或换机前请先导出 `.enkard` 离线备份）。

---

## 开源协议与免责声明

本项目基于 **[GNU General Public License v3.0 (GPL-3.0)](LICENSE)** 协议开源：允许个人免费学习、审计、构建与自用，任何基于本项目的修改或再分发衍生作品必须同样以 `GPL-3.0` 协议完整开源，禁止闭源商业套壳分发。

> **免责声明**：本软件按“原样（AS IS）”提供，不附带任何明示或暗示担保。Enkard 无任何后端服务器与密码找回机制，请务必妥善牢记主密码并定期保存离线加密备份，因遗忘主密码、关闭系统锁屏密码或设备损坏导致的数据不可恢复由使用者自行承担。
