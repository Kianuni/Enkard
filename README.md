# Enkard (v2.3.0)：银行级+ · 断网零同步 · 极简零相机权限 iPhone 银行卡硬件保险库

**Enkard** 是专为 iPhone 自签场景打造的纯离线原生银行卡加密保险库，仅使用 Apple 系统核心安全框架（`SwiftUI` + `CryptoKit` + `SecureEnclave` + `CommonCrypto` + `Security` + `LocalAuthentication`），**零第三方依赖、零网络代码、零相机/相册权限、内置进程级断网拦截器、禁绝一切云同步**。

---

## 核心安全架构（v2.3 银行级深度纵深防御）

### 1. 禁绝一切网络与同步
- **零联网代码 + 进程级断网拦截器**：源码与二进制不含任何网络请求逻辑，并在启动瞬间注册 `OfflineKillSwitchURLProtocol` 阻断所有非本地 URL 加载，同时将 `URLCache` 容量设为 `0`、Cookie 策略设为 `.never`、`NSAppTransportSecurity` 封锁本地局域网与任意连接。
- **彻底零同步**：
  - **无 iCloud Keychain 同步**：所有钥匙串条目显式写入 `kSecAttrSynchronizable = false` 与 `ThisDeviceOnly`；
  - **无 iCloud / 电脑备份同步**：存储目录、密文文件与偏好设置均排除在系统备份之外（不再使用会被备份的 `UserDefaults`）；
  - **无通用剪贴板与接力同步**：剪贴板固定 `localOnly = true`，并显式拒绝 `NSUserActivity` 接力；
  - **无键盘词库与 AI 同步**：全面封禁所有第三方扩展（`shouldAllowExtensionPointIdentifier -> false`），关闭拼写检查、键盘动态词库学习、自动填充提示及 iOS 18+ **Apple Intelligence 写作工具**（`writingToolsBehavior(.disabled)`）；
  - **导出云目录检测**：手动导入/导出离线备份时若误选 iCloud Drive 路径，App 会立即弹窗告警。
- **系统级双重断网建议**：安装后可在 iPhone **「设置 → App → Enkard → 无线数据」** 中选择 **「关闭」**，叠加 iOS 内核防火墙。

### 2. Secure Enclave 硬件双因子加密 + 防嫁接协议
- **双因子硬件绑定（`CARDSE_LOCAL_VAULT_V2`）**：本地数据加密密钥（DEK）由 **主密码 PBKDF2-HMAC-SHA256（≥60 万次，CPU 时间中位数校准）** 与 **iPhone Secure Enclave 安全芯片不可导出 P-256 私钥（ECDH）** 经 `HKDF-SHA256` 联合保护。即使本地密文文件被提取出手机，脱离这块物理安全芯片后离线 GPU 暴力破解在数学上不可行。
- **严格域分离与全字段 AAD 绑定**：本地库（`LOCAL_V2`）与跨设备离线备份（`BACKUP_V2`）严格隔离、禁止混用；加密载荷的 AAD 同时绑定 `magic`、`version`、`vaultID`、`salt`、`ephemeralPublicKey` 与 `SHA256(wrappedDEK)`，彻底杜绝跨文件密文嫁接与参数降级。
- **4 KB 块填充防体积侧信道**：明文 JSON 采用二进制定长分帧并对齐填充至 `4096` 字节整数倍，外界无法从文件大小推断卡包内保存了几张卡。
- **硬件级密码学擦除（Crypto-Shredding）**：手动销毁或连续输错 15 次触发自毁时，直接销毁 Secure Enclave 芯片密钥令牌，闪存底层残留块永久作废。

### 3. 防暴力破解、钥匙串 HMAC 状态防篡改、防回滚与防误自毁
- **设备绑定钥匙串状态 HMAC-SHA256 认证（`EKM1`）**：防回滚水位、错误计数与本地安全偏好均使用本机专属 256-bit HMAC 密钥按账户名域分离签名认证，兼容旧版平滑迁移，彻底封堵跨账户状态调包、负计数注入与删键降级。
- **Fail-Closed 硬件计数器 + 非认证故障防误毁保护**：错误次数在执行 PBKDF2 **之前**强制写入钥匙串（写失败则拒绝验证），基于 `CLOCK_MONOTONIC` 与内核 `bootsessionuuid` 递增冷却（30 秒 → 1 小时）；同时严格区分密码错误（`authenticationFailed`）与安全芯片瞬态不可用，防止锁屏瞬态错误误触发 15 次硬件自毁或覆盖在用芯片密钥。
- **5 次错误自动挂起生物识别 + 未读爆破提醒**：连续输错达 5 次即自动移除生物识别快捷密钥，强制使用主密码；若解锁前曾发生任何失败尝试，解锁后立即弹窗告警。
- **一键紧急锁定（禁用面容 ID）**：首页导航栏与锁屏底部均提供一键进入紧急锁定模式，瞬间擦除钥匙串中的生物识别密钥并收起输入焦点，睡觉、过检、送修手机时必须凭主密码才能打开。
- **Vault ID 防覆写 + 安全有界版本号双重防回滚**：同时比对唯一库 ID 与单调递增版本号（内置 `2^62` 算术上溢保护），拒绝异库覆盖既有 `Vault ID`，拦截旧文件回滚与整库替换。

### 4. 自签运行时自卫、C11 抗优化擦除、符号剥离与屏幕防泄露
- **内核级反调试 + 反符号劫持持续监控**：Release 包在启动时通过 Mach-O 原生桩调用 XNU `PT_DENY_ATTACH`（置位内核 `P_LNOATTACH` 拒绝外部 `lldb` / `debugserver` 附加），并配合 Fail-Closed `P_TRACED` 持续监控、前台周期性重审计、`_dyld` / `dladdr` 规范化防目录穿越路径反伪造、Mach-O `S_INTERPOSING` / `__interpose` 劫持段扫描、19 项关键安全符号来源校验，以及**直连原生桩 + `dyld_cache_header` 结构校验的导入表（GOT）运行时重绑定检测**（识破 `dlsym` 屏蔽、伪造共享缓存区间与 `fishhook` 重绑定）。
- **C11 `memset_s` 抗编译器死存储消除与零 CoW 残留擦除**：密钥派生缓冲、解封 DEK 与解密载荷采用独立单持有者内存与 C11 `memset_s` 强制清零，杜绝 `-O` 编译优化消除清零指令及 Swift `Data` 切片写时复制残留。
- **全量符号与属性名反射剥离**：Release 二进制剥离全部本地符号、Swift 符号与存储属性反射名称（`-disable-reflection-names` + `strip -rSTx`），最大化逆向分析与 Hook 成本。
- **超 Alert 层级隐私遮罩 + Unicode Bidi 反欺骗净化**：隐私遮罩窗口层级提升至 `UIWindow.Level.alert + 500`，完整遮蔽系统确认弹窗；模型与解码层全面剥离 `RLO`（`U+202E`）等双向字符伪装与控制字符；`verify_signed_ipa.sh` 新增解压前 ZIP 符号链接拦截及共享 App Group / 跨应用共享 Keychain 组权限审计。

---

## 构建、自签与安全校验

```bash
chmod +x scripts/build_ipa.sh scripts/verify_signed_ipa.sh
./scripts/build_ipa.sh                      # 编译生成 dist/Enkard-unsigned.ipa 与多段哈希基线
./scripts/verify_signed_ipa.sh signed.ipa   # 签名后校验动态库、白名单、Info.plist、多段哈希与同步权限
```

- **自签规范**：仅使用你自己的 Apple 账号/证书在本地签名（Xcode 或 Sideloadly 本地模式），关闭签名工具中的所有“插件注入”选项。

---

## 从 CardSe 升级到 Enkard
- v2.2.0 起应用更名为 **Enkard**。为保证无缝升级，Bundle ID（`com.local.cardse.app`）、钥匙串服务名、加密文件格式与存储目录均保持不变：用同一签名方式覆盖安装即可直接解锁原有卡包，无需重新录入。
- 新导出的离线备份默认扩展名为 `.enkard`，旧的 `.cardse` / `.cardvault` 备份仍可正常导入。

## 平台物理边界如实说明
- **请勿关闭 iPhone 锁屏密码**：Secure Enclave 硬件密钥与面容 ID 密钥均绑定「已设置设备密码」（`WhenPasscodeSetThisDeviceOnly`），关闭锁屏密码会导致系统永久删除这些密钥，本机卡包将无法再解密（请提前导出离线备份）。
- **进程内自检的上限**：运行时注入/Hook 检测只能提高攻击成本；若攻击者已能在本 App 进程内执行任意代码（越狱或被恶意重签注入），任何用户态自检理论上都可被同时伪造。因此务必使用 `verify_signed_ipa.sh` 校验签名包，并只在未越狱设备上使用。
- **Swift 内存模型限制**：DEK 使用 `SymmetricKey`（释放时清零），中间字节缓冲区用完即清零，弹窗关闭即清空状态字符串；但 Swift `String` 与 UIKit 输入缓冲区的历史副本受系统运行时管理，无法做 100% 物理内存清零。
- **网购粘贴瞬间**：结账粘贴时建议在浏览器中也使用系统原生键盘，粘贴完成后点击横幅「立即清空」。
- **内核失陷 / 已越狱设备**：不在任何用户态 App 的绝对防护能力之内。
