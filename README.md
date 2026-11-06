# CardSe (v2.0.0)：最高安全等级 · 断网零同步 iPhone 银行卡硬件保险库

**CardSe** 是专为 iPhone 自签场景打造的纯离线原生银行卡加密保险库，仅使用 Apple 系统安全框架（`SwiftUI` + `CryptoKit` + `SecureEnclave` + `CommonCrypto` + `Security` + `LocalAuthentication`），**零第三方依赖、零网络代码、内置进程级断网拦截器、禁绝一切云同步**。

---

## 核心安全架构（v2.0 最高安全等级）

### 1. 禁绝一切网络与同步
- **零联网代码 + 进程级断网拦截器**：源码与二进制不含任何网络请求逻辑，并在启动瞬间注册 `OfflineKillSwitchURLProtocol` 阻断所有非本地 URL 加载，同时将 `URLCache` 容量设为 `0`、Cookie 策略设为 `.never`、`NSAppTransportSecurity` 封锁本地局域网与任意连接。
- **彻底零同步**：
  - **无 iCloud Keychain 同步**：所有钥匙串条目显式写入 `kSecAttrSynchronizable = false` 与 `ThisDeviceOnly`；
  - **无 iCloud / 电脑备份同步**：存储目录、密文文件与偏好设置均排除在系统备份之外（不再使用会被备份的 `UserDefaults`）；
  - **无通用剪贴板与接力同步**：剪贴板固定 `localOnly = true`，并显式拒绝 `NSUserActivity` 接力；
  - **无键盘词库与 AI 同步**：全面封禁所有第三方扩展（`shouldAllowExtensionPointIdentifier -> false`），关闭拼写检查、键盘动态词库学习、自动填充提示及 iOS 18+ **Apple Intelligence 写作工具**（`writingToolsBehavior(.disabled)`）；
  - **导出云目录检测**：手动导入/导出离线备份时若误选 iCloud Drive 路径，App 会立即弹窗告警。
- **系统级双重断网建议**：安装后可在 iPhone **「设置 → App → CardSe → 无线数据」** 中选择 **「关闭」**，叠加 iOS 内核防火墙。

### 2. Secure Enclave 硬件双因子加密 + 防嫁接协议
- **双因子硬件绑定（`CARDSE_LOCAL_VAULT_V2`）**：本地数据加密密钥（DEK）由 **主密码 PBKDF2-HMAC-SHA256（≥60 万次，CPU 时间中位数校准）** 与 **iPhone Secure Enclave 安全芯片不可导出 P-256 私钥（ECDH）** 经 `HKDF-SHA256` 联合保护。即使本地密文文件被提取出手机，脱离这块物理安全芯片后离线 GPU 暴力破解在数学上不可行。
- **严格域分离与全字段 AAD 绑定**：本地库（`LOCAL_V2`）与跨设备离线备份（`BACKUP_V2`）严格隔离、禁止混用；加密载荷的 AAD 同时绑定 `magic`、`version`、`vaultID`、`salt`、`ephemeralPublicKey` 与 `SHA256(wrappedDEK)`，彻底杜绝跨文件密文嫁接与参数降级。
- **4 KB 块填充防体积侧信道**：明文 JSON 采用二进制定长分帧并对齐填充至 `4096` 字节整数倍，外界无法从文件大小推断卡包内保存了几张卡。
- **硬件级密码学擦除（Crypto-Shredding）**：手动销毁或连续输错 15 次触发自毁时，直接销毁 Secure Enclave 芯片密钥令牌，闪存底层残留块永久作废。

### 3. 防暴力破解、防回滚与防熟睡/胁迫
- **Fail-Closed 硬件计数器**：错误次数在执行 PBKDF2 **之前**强制写入钥匙串（写失败则拒绝验证），基于 `CLOCK_MONOTONIC` 与内核 `bootsessionuuid` 递增冷却（30 秒 → 1 小时）。
- **5 次错误自动挂起生物识别 + 未读爆破提醒**：连续输错达 5 次即自动移除生物识别快捷密钥，强制使用主密码；若解锁前曾发生任何失败尝试，解锁后立即弹窗告警。
- **一键紧急锁定（禁用面容 ID）**：首页导航栏与锁屏底部均提供一键进入紧急锁定模式，瞬间擦除钥匙串中的生物识别密钥，睡觉、过检、送修手机时必须凭主密码才能打开。
- **Vault ID + 版本号双重防回滚**：同时比对唯一库 ID 与单调递增版本号，拦截旧文件回滚与整库替换。

### 4. 自签运行时自卫与屏幕防泄露
- **进程内反调试与注入自检**：Release 包启动即调用 `PT_DENY_ATTACH` 在内核层拒绝调试器附加（化解个人开发证书 `get-task-allow` 风险），周期性监控 `P_TRACED` 并扫描 `_dyld` 已加载镜像与越狱/注入特征。
- **全覆盖防截屏输入体验**：彻底移除密码与 CVV 的普通明文输入框切换；卡号、有效期、CVV、安全备注均采用安全输入控件或置于安全渲染图层内（截屏与录屏自动空白）；切后台同步拉起顶层独立 UIKit 遮罩窗口；按电源键锁屏、手动锁定或倒计时归零均主动覆写清空剪贴板。

---

## 构建、自签与安全校验

```bash
chmod +x scripts/build_ipa.sh scripts/verify_signed_ipa.sh
./scripts/build_ipa.sh                      # 编译生成 dist/CardSe-unsigned.ipa 与多段哈希基线
./scripts/verify_signed_ipa.sh signed.ipa   # 签名后校验动态库、白名单、Info.plist、多段哈希与同步权限
```

- **自签规范**：仅使用你自己的 Apple 账号/证书在本地签名（Xcode 或 Sideloadly 本地模式），关闭签名工具中的所有“插件注入”选项。

---

## 平台物理边界如实说明
- **Swift 内存模型限制**：DEK 使用 `SymmetricKey`（释放时清零），中间字节缓冲区用完即清零，弹窗关闭即清空状态字符串；但 Swift `String` 与 UIKit 输入缓冲区的历史副本受系统运行时管理，无法做 100% 物理内存清零。
- **网购粘贴瞬间**：结账粘贴时建议在浏览器中也使用系统原生键盘，粘贴完成后点击横幅「立即清空」。
- **内核失陷 / 已越狱设备**：不在任何用户态 App 的绝对防护能力之内。
