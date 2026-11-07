import CommonCrypto
import Darwin
import Foundation
import MachO
import Security

#if !DEBUG
@_silgen_name("ptrace")
private func cardse_ptrace(
    _ request: CInt,
    _ pid: pid_t,
    _ addr: UnsafeMutableRawPointer?,
    _ data: CInt
) -> CInt
#endif

@_silgen_name("_dyld_get_shared_cache_range")
private func cardse_dyld_get_shared_cache_range(
    _ length: UnsafeMutablePointer<Int>?
) -> UnsafeRawPointer?

struct RuntimeIntegrityReport: Equatable, Sendable {
    let isCompromised: Bool
    let antiDebugActive: Bool
    let unexpectedLibraries: [String]
    let anomalies: [String]

    static let cleanInitial = RuntimeIntegrityReport(
        isCompromised: false,
        antiDebugActive: true,
        unexpectedLibraries: [],
        anomalies: []
    )

    var summaryText: String {
        if !isCompromised {
            return antiDebugActive ? "正常（内核反调试已启用 · 无注入库）" : "正常（调试构建 · 无注入库）"
        }
        let all = anomalies + unexpectedLibraries.map { "检测到非系统动态库：\($0)" }
        return all.joined(separator: "；")
    }
}

/// Process-level tamper, dylib-injection, symbol-interposition, and kernel anti-debug protection for self-signed iOS deployments.
/// Combines XNU `PT_DENY_ATTACH` (`P_LNOATTACH`) via a direct Mach-O `dyld` stub (preventing `dlsym` hooks
/// and `arm64e` PAC pointer-cast traps) with continuous read-only `sysctl(KERN_PROC_PID)` (`P_TRACED`) polling,
/// Mach-O `S_INTERPOSING` / `__interpose` inspection, `dladdr` header cross-verification, and critical symbol origin checks.
enum RuntimeSecurity {
    private static let ptDenyAttach: CInt = 31 // PT_DENY_ATTACH in <sys/ptrace.h>
    private static let pTracedFlag: Int32 = 0x00000800 // P_TRACED in <sys/proc.h>
    private static let libSystemUmbrellaPrefixes = [
        "/usr/lib/system/",
        "/usr/lib/libSystem.B.dylib"
    ]
    private static let securityFrameworkPrefixes = [
        "/System/Library/Frameworks/Security.framework/"
    ]
    private static let criticalSystemSymbols: [(name: String, allowedPrefixes: [String])] = [
        ("ptrace", libSystemUmbrellaPrefixes),
        ("sysctl", libSystemUmbrellaPrefixes),
        ("sysctlbyname", libSystemUmbrellaPrefixes),
        ("access", libSystemUmbrellaPrefixes),
        ("_dyld_get_shared_cache_range", libSystemUmbrellaPrefixes),
        ("_dyld_get_image_name", libSystemUmbrellaPrefixes),
        ("_dyld_get_image_header", libSystemUmbrellaPrefixes),
        ("_dyld_image_count", libSystemUmbrellaPrefixes),
        ("dladdr", libSystemUmbrellaPrefixes),
        ("dlsym", libSystemUmbrellaPrefixes),
        ("getenv", libSystemUmbrellaPrefixes),
        ("CCKeyDerivationPBKDF", libSystemUmbrellaPrefixes),
        ("CCCrypt", libSystemUmbrellaPrefixes),
        ("memset_s", libSystemUmbrellaPrefixes),
        ("SecRandomCopyBytes", securityFrameworkPrefixes),
        ("SecItemCopyMatching", securityFrameworkPrefixes),
        ("SecItemAdd", securityFrameworkPrefixes),
        ("SecItemUpdate", securityFrameworkPrefixes),
        ("SecItemDelete", securityFrameworkPrefixes)
    ]

    /// Sets XNU `P_LNOATTACH` on the current process in Release builds, rejecting external `lldb` / `debugserver`
    /// attachment at the kernel level even when personal self-signing profiles include `get-task-allow=true`.
    @discardableResult
    static func enforceReleaseAntiDebug() -> Bool {
        #if DEBUG
        return false
        #else
        return cardse_ptrace(ptDenyAttach, 0, nil, 0) == 0
        #endif
    }

    /// Queries the kernel process table (`KERN_PROC_PID`) for `P_TRACED` (read-only, sandbox-safe, fail-closed).
    static func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        // `sysctl(KERN_PROC_PID, getpid())` always succeeds (0) in the iOS app sandbox; failing closed
        // prevents a `sysctl -> -1` interposer from masking an attached debugger (`P_TRACED`).
        guard result == 0 else { return true }
        return (info.kp_proc.p_flag & pTracedFlag) != 0
    }

    /// Inspects loaded Mach-O images, section tables, symbol origins, environment variables, and known hook paths
    /// using strictly read-only checks.
    static func auditEnvironment(antiDebugActive: Bool = false) -> RuntimeIntegrityReport {
        var anomalies: [String] = []
        var unexpectedLibraries: [String] = []

        if let inserted = getenv("DYLD_INSERT_LIBRARIES") {
            let insertedValue = String(cString: inserted)
            if !insertedValue.isEmpty {
                #if DEBUG
                let nonXCTestEntries = insertedValue
                    .split(separator: ":")
                    .filter {
                        !$0.contains("libXCTestBundleInject.dylib")
                            && !$0.contains("libMainThreadChecker.dylib")
                            && !$0.contains("libRPAC.dylib")
                    }
                if !nonXCTestEntries.isEmpty {
                    appendUnique(&anomalies, "环境变量存在 DYLD_INSERT_LIBRARIES 动态注入")
                }
                #else
                appendUnique(&anomalies, "环境变量存在 DYLD_INSERT_LIBRARIES 动态注入")
                #endif
            }
        }

        #if !DEBUG
        if isDebuggerAttached() {
            appendUnique(&anomalies, "检测到调试器附加（P_TRACED）")
        }
        #endif

        let mainExecutable = normalizedPath(Bundle.main.executablePath ?? "")
        let mainAppDir = normalizedPath(Bundle.main.bundlePath)
        var seenHeadersByPath: [String: UnsafeRawPointer] = [:]

        let imageCount = _dyld_image_count()
        for idx in 0..<imageCount {
            let rawNamePtr = _dyld_get_image_name(idx)
            let headerPtr = _dyld_get_image_header(idx)

            var dyldPath = ""
            if let rawNamePtr {
                let rawDyld = String(cString: rawNamePtr)
                let validated = normalizedSystemPathForAudit(rawDyld)
                dyldPath = validated.path
                if validated.hasTraversal {
                    appendUnique(&anomalies, "检测到动态库路径包含目录穿越伪装")
                }
            }
            var dladdrPath = ""
            if let headerPtr {
                var dlInfo = Dl_info()
                if dladdr(UnsafeRawPointer(headerPtr), &dlInfo) != 0, let fname = dlInfo.dli_fname {
                    let rawDl = String(cString: fname)
                    let validated = normalizedSystemPathForAudit(rawDl)
                    dladdrPath = validated.path
                    if validated.hasTraversal {
                        appendUnique(&anomalies, "检测到动态库路径包含目录穿越伪装")
                    }
                }
            }

            if !dyldPath.isEmpty && !dladdrPath.isEmpty && dyldPath != dladdrPath {
                appendUnique(&anomalies, "检测到 dyld 镜像路径伪造（_dyld_get_image_name 与 dladdr 不一致）")
            }

            let effectivePath = !dladdrPath.isEmpty ? dladdrPath : dyldPath
            if !effectivePath.isEmpty, let headerPtr {
                let rawHeader = UnsafeRawPointer(headerPtr)
                if let previousHeader = seenHeadersByPath[effectivePath], previousHeader != rawHeader {
                    let dupBase = (effectivePath as NSString).lastPathComponent
                    appendUnique(&anomalies, "检测到重复伪装的系统镜像路径（\(dupBase)）")
                } else {
                    seenHeadersByPath[effectivePath] = rawHeader
                }
            }

            if let headerPtr, hasInterposeSection(headerPtr) {
                #if targetEnvironment(simulator)
                let isSimulatorHostShim = effectivePath.hasPrefix("/usr/lib/system/libsystem_sim_")
                #else
                let isSimulatorHostShim = false
                #endif
                #if DEBUG
                let isDebugXCTestInjector = effectivePath.hasPrefix("/Developer/")
                    || effectivePath.contains("Xcode")
                    || effectivePath.contains("XCTest")
                    || effectivePath.hasSuffix("/libRPAC.dylib")
                #else
                let isDebugXCTestInjector = false
                #endif
                if !isSimulatorHostShim && !isDebugXCTestInjector {
                    let interposeBase = (effectivePath as NSString).lastPathComponent
                    appendUnique(&anomalies, "检测到 Mach-O __interpose 符号劫持段（\(interposeBase)）")
                }
            }

            let isMainExecutableImage = (headerPtr?.pointee.filetype == UInt32(MH_EXECUTE))
            for candidatePath in [dyldPath, dladdrPath] where !candidatePath.isEmpty {
                if isMainExecutableImage || candidatePath == mainExecutable { continue }
                if isTrustedSystemImagePath(candidatePath) { continue }
                #if DEBUG
                if !mainAppDir.isEmpty && candidatePath.hasPrefix(mainAppDir) { continue }
                #endif

                let basename = (candidatePath as NSString).lastPathComponent
                appendUnique(&unexpectedLibraries, basename)
            }
        }

        verifyCriticalSymbolOrigins(anomalies: &anomalies)
        verifyBoundImportPointers(anomalies: &anomalies)

        for jbPath in [
            "/var/jb",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/usr/lib/ellekit.dylib",
            "/usr/lib/TweakInject"
        ] where access(jbPath, F_OK) == 0 {
            appendUnique(&anomalies, "检测到越狱或 Hook 环境路径（\(jbPath)）")
            break
        }

        let compromised = !anomalies.isEmpty || !unexpectedLibraries.isEmpty
        return RuntimeIntegrityReport(
            isCompromised: compromised,
            antiDebugActive: antiDebugActive,
            unexpectedLibraries: unexpectedLibraries,
            anomalies: anomalies
        )
    }

    // MARK: - Runtime Import-Table (GOT) Rebinding Detection

    private typealias DyldImageNameFn = @convention(c) (UInt32) -> UnsafePointer<CChar>?
    private typealias DyldImageHeaderFn = @convention(c) (UInt32) -> UnsafePointer<mach_header>?
    private typealias DyldImageCountFn = @convention(c) () -> UInt32
    private typealias DladdrFn = @convention(c) (UnsafeRawPointer?, UnsafeMutablePointer<Dl_info>?) -> Int32
    private typealias DlsymFn = @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<CChar>?) -> UnsafeMutableRawPointer?
    private typealias GetenvFn = @convention(c) (UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
    private typealias AccessFn = @convention(c) (UnsafePointer<CChar>?, Int32) -> Int32
    private typealias SysctlFn = @convention(c) (
        UnsafeMutablePointer<Int32>?, UInt32, UnsafeMutableRawPointer?,
        UnsafeMutablePointer<Int>?, UnsafeMutableRawPointer?, Int
    ) -> Int32
    private typealias SysctlByNameFn = @convention(c) (
        UnsafePointer<CChar>?, UnsafeMutableRawPointer?, UnsafeMutablePointer<Int>?,
        UnsafeMutableRawPointer?, Int
    ) -> Int32
    private typealias PBKDFFn = @convention(c) (
        CCPBKDFAlgorithm, UnsafePointer<CChar>?, Int, UnsafePointer<UInt8>?, Int,
        CCPseudoRandomAlgorithm, UInt32, UnsafeMutablePointer<UInt8>?, Int
    ) -> Int32
    private typealias CCCryptFn = @convention(c) (
        CCOperation, CCAlgorithm, CCOptions, UnsafeRawPointer?, Int, UnsafeRawPointer?,
        UnsafeRawPointer?, Int, UnsafeMutableRawPointer?, Int, UnsafeMutablePointer<Int>?
    ) -> CCCryptorStatus
    private typealias SecRandomFn = @convention(c) (SecRandomRef?, Int, UnsafeMutableRawPointer) -> Int32
    private typealias SecItemCopyFn = @convention(c) (CFDictionary, UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
    private typealias SecItemAddFn = @convention(c) (CFDictionary, UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
    private typealias SecItemUpdateFn = @convention(c) (CFDictionary, CFDictionary) -> OSStatus
    private typealias SecItemDeleteFn = @convention(c) (CFDictionary) -> OSStatus
    private typealias MemsetSFn = @convention(c) (UnsafeMutableRawPointer?, Int, Int32, Int) -> errno_t

    /// Function pointers loaded through THIS image's own import table (`__DATA_CONST,__got`) — i.e. exactly
    /// the addresses the app really calls. A fishhook-style injector that rewrites GOT slots changes these values.
    /// Note: only Clang-imported `@convention(c)` functions are listed here (Swift `@_silgen_name` wrappers emit local thunks).
    private static func boundImportPointers() -> [(String, UnsafeRawPointer)] {
        let imageName: DyldImageNameFn = _dyld_get_image_name
        let imageHeader: DyldImageHeaderFn = _dyld_get_image_header
        let imageCount: DyldImageCountFn = _dyld_image_count
        let dladdrFn: DladdrFn = dladdr
        let dlsymFn: DlsymFn = dlsym
        let getenvFn: GetenvFn = getenv
        let accessFn: AccessFn = access
        let sysctlFn: SysctlFn = sysctl
        let sysctlByNameFn: SysctlByNameFn = sysctlbyname
        let pbkdfFn: PBKDFFn = CCKeyDerivationPBKDF
        let ccCryptFn: CCCryptFn = CCCrypt
        let secRandomFn: SecRandomFn = SecRandomCopyBytes
        let secCopyFn: SecItemCopyFn = SecItemCopyMatching
        let secAddFn: SecItemAddFn = SecItemAdd
        let secUpdateFn: SecItemUpdateFn = SecItemUpdate
        let secDeleteFn: SecItemDeleteFn = SecItemDelete
        let memsetSFn: MemsetSFn = memset_s
        return [
            ("_dyld_get_image_name", unsafeBitCast(imageName, to: UnsafeRawPointer.self)),
            ("_dyld_get_image_header", unsafeBitCast(imageHeader, to: UnsafeRawPointer.self)),
            ("_dyld_image_count", unsafeBitCast(imageCount, to: UnsafeRawPointer.self)),
            ("dladdr", unsafeBitCast(dladdrFn, to: UnsafeRawPointer.self)),
            ("dlsym", unsafeBitCast(dlsymFn, to: UnsafeRawPointer.self)),
            ("getenv", unsafeBitCast(getenvFn, to: UnsafeRawPointer.self)),
            ("access", unsafeBitCast(accessFn, to: UnsafeRawPointer.self)),
            ("sysctl", unsafeBitCast(sysctlFn, to: UnsafeRawPointer.self)),
            ("sysctlbyname", unsafeBitCast(sysctlByNameFn, to: UnsafeRawPointer.self)),
            ("CCKeyDerivationPBKDF", unsafeBitCast(pbkdfFn, to: UnsafeRawPointer.self)),
            ("CCCrypt", unsafeBitCast(ccCryptFn, to: UnsafeRawPointer.self)),
            ("SecRandomCopyBytes", unsafeBitCast(secRandomFn, to: UnsafeRawPointer.self)),
            ("SecItemCopyMatching", unsafeBitCast(secCopyFn, to: UnsafeRawPointer.self)),
            ("SecItemAdd", unsafeBitCast(secAddFn, to: UnsafeRawPointer.self)),
            ("SecItemUpdate", unsafeBitCast(secUpdateFn, to: UnsafeRawPointer.self)),
            ("SecItemDelete", unsafeBitCast(secDeleteFn, to: UnsafeRawPointer.self)),
            ("memset_s", unsafeBitCast(memsetSFn, to: UnsafeRawPointer.self))
        ]
    }

    /// Every genuine Apple system function (libsystem, libdyld, Security, CommonCrypto…) lives inside the dyld
    /// shared cache. Hook code from an injected dylib or anonymous executable memory never does. So each pointer
    /// in our own import table must fall inside the verified shared-cache address range.
    private static func verifyBoundImportPointers(anomalies: inout [String]) {
        guard let cacheRange = sharedCacheAddressRange(anomalies: &anomalies) else { return }
        for (name, pointer) in boundImportPointers() where !cacheRange.contains(UInt(bitPattern: pointer)) {
            #if targetEnvironment(simulator)
            // On iOS Simulator, syscall shims (`access`, `ptrace`) reside in host macOS `libsystem_kernel.dylib`
            // mapped from the host macOS shared cache rather than the simulator's `dyld_sim` shared cache.
            var simInfo = Dl_info()
            if dladdr(pointer, &simInfo) != 0, let rawFname = simInfo.dli_fname {
                let owner = normalizedPath(String(cString: rawFname))
                if owner == "/usr/lib/system/libsystem_kernel.dylib"
                    || owner.hasPrefix("/usr/lib/system/libsystem_sim_") {
                    continue
                }
            }
            #endif
            appendUnique(&anomalies, "检测到关键函数导入表被运行时重绑定（\(name)）")
        }
    }

    /// Validates the structural integrity of a Darwin `dyld_cache_header` (`dyld_v1`) in memory.
    static func isValidSharedCacheHeader(start: UnsafeRawPointer, length: Int) -> Bool {
        let minimumCacheBytes = 16 * 1024 * 1024
        guard length >= minimumCacheBytes, length < (1 << 36) else { return false }
        let lower = UInt(bitPattern: start)
        guard (lower & 0xFFF) == 0 else { return false }

        // 1. Magic must start with 8-byte "dyld_v1 " and terminate with '\0' at byte 15.
        let expectedMagicPrefix: [UInt8] = [0x64, 0x79, 0x6C, 0x64, 0x5F, 0x76, 0x31, 0x20]
        for i in 0..<expectedMagicPrefix.count {
            if start.load(fromByteOffset: i, as: UInt8.self) != expectedMagicPrefix[i] {
                return false
            }
        }
        guard start.load(fromByteOffset: 15, as: UInt8.self) == 0 else { return false }

        // 2. Validate mapping table offset & count (`mappingOffset` at +16, `mappingCount` at +20).
        let mappingOffset = start.load(fromByteOffset: 16, as: UInt32.self)
        let mappingCount = start.load(fromByteOffset: 20, as: UInt32.self)
        guard mappingOffset >= 0x40,
              mappingOffset <= 0x4000,
              mappingOffset % 4 == 0,
              mappingCount >= 1,
              mappingCount <= 64,
              Int(mappingOffset) + 32 <= length else {
            return false
        }

        // 3. Validate mapping[0] (`dyld_cache_mapping_info` = 32 bytes): fileOffset == 0 and read+execute non-writable!
        let m0Base = Int(mappingOffset)
        let m0Size = start.load(fromByteOffset: m0Base + 8, as: UInt64.self)
        let m0FileOffset = start.load(fromByteOffset: m0Base + 16, as: UInt64.self)
        let m0MaxProt = start.load(fromByteOffset: m0Base + 24, as: UInt32.self)
        let m0InitProt = start.load(fromByteOffset: m0Base + 28, as: UInt32.self)
        let rxNonWritable: UInt32 = 0x05 // VM_PROT_READ (1) | VM_PROT_EXECUTE (4), no VM_PROT_WRITE (2)
        guard m0Size >= 0x4000,
              m0Size <= UInt64(length),
              m0FileOffset == 0,
              m0MaxProt == rxNonWritable,
              m0InitProt == rxNonWritable else {
            return false
        }

        // 4. Non-zero 16-byte cache UUID at +0x58 when header includes the UUID field (`mappingOffset >= 0x68`).
        if mappingOffset >= 0x68 {
            var anyNonZeroUUIDByte = false
            for off in 0x58..<0x68 where start.load(fromByteOffset: off, as: UInt8.self) != 0 {
                anyNonZeroUUIDByte = true
                break
            }
            guard anyNonZeroUUIDByte else { return false }
        }

        return true
    }

    /// Returns the verified dyld shared-cache range, failing closed if missing, unaligned, or forged.
    private static func sharedCacheAddressRange(anomalies: inout [String]) -> Range<UInt>? {
        var length = 0
        guard let start = cardse_dyld_get_shared_cache_range(&length),
              length > 0,
              length < (1 << 36) else {
            #if !targetEnvironment(simulator)
            appendUnique(&anomalies, "检测到 dyld 共享缓存范围缺失或异常（疑似被 Hook 屏蔽）")
            #endif
            return nil
        }
        let lower = UInt(bitPattern: start)
        let (upper, overflow) = lower.addingReportingOverflow(UInt(length))
        guard !overflow else {
            appendUnique(&anomalies, "检测到 dyld 共享缓存范围被伪造")
            return nil
        }

        // The genuine dyld_cache_header precedes all Mach-O images in the cache (`dladdr(start) == 0`),
        // whereas a forged header buffer embedded inside an injected dylib resolves to that dylib's image!
        var startInfo = Dl_info()
        if !isValidSharedCacheHeader(start: start, length: length) || dladdr(start, &startInfo) != 0 {
            appendUnique(&anomalies, "检测到 dyld 共享缓存范围被伪造")
            return nil
        }

        let range = lower..<upper
        let ownImage = UInt(bitPattern: UnsafeRawPointer(#dsohandle))
        if range.contains(ownImage) {
            appendUnique(&anomalies, "检测到 dyld 共享缓存范围被伪造")
            return nil
        }

        // Cross-check loaded images: no untrusted or main-executable Mach-O image may ever reside inside cacheRange.
        let totalImages = _dyld_image_count()
        for idx in 0..<totalImages {
            guard let hdr = _dyld_get_image_header(idx) else { continue }
            let hdrAddr = UInt(bitPattern: hdr)
            guard range.contains(hdrAddr) else { continue }
            if hdr.pointee.filetype == UInt32(MH_EXECUTE) {
                appendUnique(&anomalies, "检测到 dyld 共享缓存范围被伪造")
                return nil
            }
            if let rawName = _dyld_get_image_name(idx) {
                let checked = normalizedSystemPathForAudit(String(cString: rawName))
                if checked.hasTraversal || !isTrustedSystemImagePath(checked.path) {
                    appendUnique(&anomalies, "检测到 dyld 共享缓存范围被伪造")
                    return nil
                }
            }
        }
        return range
    }

    // MARK: - Mach-O & Symbol Origin Verification (Read-Only, Bounds-Checked)

    private static func hasInterposeSection(_ header: UnsafePointer<mach_header>) -> Bool {
        guard header.pointee.magic == MH_MAGIC_64 else { return false }
        let headerRaw = UnsafeRawPointer(header)
        let header64 = readMachStruct(mach_header_64.self, at: headerRaw)

        let ncmds = Int(header64.ncmds)
        let sizeofcmds = Int(header64.sizeofcmds)
        guard ncmds >= 0, ncmds <= 4096, sizeofcmds >= 0, sizeofcmds <= 4 * 1024 * 1024 else {
            return false
        }

        var cmdPtr = headerRaw.advanced(by: MemoryLayout<mach_header_64>.size)
        let cmdsEnd = cmdPtr.advanced(by: sizeofcmds)

        for _ in 0..<ncmds {
            guard cmdPtr.advanced(by: MemoryLayout<load_command>.size) <= cmdsEnd else { break }
            let loadCmd = readMachStruct(load_command.self, at: cmdPtr)
            let cmdSize = Int(loadCmd.cmdsize)
            guard cmdSize >= MemoryLayout<load_command>.size,
                  cmdPtr.advanced(by: cmdSize) <= cmdsEnd else {
                break
            }

            if loadCmd.cmd == UInt32(LC_SEGMENT_64),
               cmdSize >= MemoryLayout<segment_command_64>.size {
                let segCmd = readMachStruct(segment_command_64.self, at: cmdPtr)
                let nsects = Int(segCmd.nsects)
                let sectionStride = MemoryLayout<section_64>.size
                if nsects > 0,
                   nsects <= 4096,
                   MemoryLayout<segment_command_64>.size + nsects * sectionStride <= cmdSize {
                    var sectPtr = cmdPtr.advanced(by: MemoryLayout<segment_command_64>.size)
                    for _ in 0..<nsects {
                        let sect = readMachStruct(section_64.self, at: sectPtr)
                        let sectType = sect.flags & UInt32(SECTION_TYPE)
                        if sectType == UInt32(S_INTERPOSING) {
                            return true
                        }
                        let sectName = withUnsafeBytes(of: sect.sectname) { raw in
                            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
                        }
                        if sectName == "__interpose" {
                            return true
                        }
                        sectPtr = sectPtr.advanced(by: sectionStride)
                    }
                }
            }

            cmdPtr = cmdPtr.advanced(by: cmdSize)
        }
        return false
    }

    private static func verifyCriticalSymbolOrigins(anomalies: inout [String]) {
        guard let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2) else { return }
        for entry in criticalSystemSymbols {
            let symbol = entry.name
            guard let symAddr = dlsym(rtldDefault, symbol) else {
                appendUnique(&anomalies, "关键系统安全符号缺失（\(symbol)）")
                continue
            }
            var dlInfo = Dl_info()
            guard dladdr(symAddr, &dlInfo) != 0, let rawFname = dlInfo.dli_fname else {
                appendUnique(&anomalies, "关键系统安全符号来源不可解析（\(symbol)）")
                continue
            }
            let validated = normalizedSystemPathForAudit(String(cString: rawFname))
            let ownerPath = validated.path
            let matchesAllowedUmbrella = entry.allowedPrefixes.contains { prefix in
                ownerPath == prefix || (prefix.hasSuffix("/") && ownerPath.hasPrefix(prefix))
            }
            if validated.hasTraversal || !matchesAllowedUmbrella || !isTrustedSystemImagePath(ownerPath) {
                appendUnique(&anomalies, "检测到关键系统符号被重定向或 Hook（\(symbol)）")
            }
        }
    }

    private static func readMachStruct<T>(_ type: T.Type, at ptr: UnsafeRawPointer) -> T {
        withUnsafeTemporaryAllocation(of: T.self, capacity: 1) { buffer in
            let dst = UnsafeMutableRawPointer(buffer.baseAddress!)
            memcpy(dst, ptr, MemoryLayout<T>.size)
            return buffer[0]
        }
    }

    private static func appendUnique(_ array: inout [String], _ value: String) {
        if !array.contains(value) {
            array.append(value)
        }
    }

    /// Canonicalizes a Mach-O path while explicitly detecting relative traversal segments (`..` / `.` / `\`)
    /// so a crafted path such as `/usr/lib/../../var/tmp/evil.dylib` can never pass prefix allowlists.
    static func normalizedSystemPathForAudit(_ rawPath: String) -> (path: String, hasTraversal: Bool) {
        let hasSuspiciousSegments = rawPath.contains("/../")
            || rawPath.hasSuffix("/..")
            || rawPath.hasPrefix("../")
            || rawPath == ".."
            || rawPath.contains("/./")
            || rawPath.hasSuffix("/.")
            || rawPath.contains("\\")
            || rawPath.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F })

        var result = rawPath
        #if targetEnvironment(simulator)
        if let simRootPtr = getenv("SIMULATOR_ROOT") {
            let simRoot = String(cString: simRootPtr)
            if !simRoot.isEmpty, result.hasPrefix(simRoot) {
                result = String(result.dropFirst(simRoot.count))
            }
        }
        if let runtimeRange = result.range(of: "/RuntimeRoot/") {
            result = String(result[runtimeRange.upperBound...])
            if !result.hasPrefix("/") {
                result = "/" + result
            }
        }
        #endif
        if !result.isEmpty {
            result = (result as NSString).standardizingPath
        }
        if result.hasPrefix("/private/var/") || result.hasPrefix("/private/etc/") || result.hasPrefix("/private/tmp/") {
            result = String(result.dropFirst("/private".count))
        }
        return (result, hasSuspiciousSegments)
    }

    private static func normalizedPath(_ path: String) -> String {
        normalizedSystemPathForAudit(path).path
    }

    static func isTrustedSystemImagePath(_ path: String) -> Bool {
        guard !path.isEmpty else { return false }
        let checked = normalizedSystemPathForAudit(path)
        if checked.hasTraversal { return false }
        let canonical = checked.path
        let trustedPrefixes = [
            "/System/Library/",
            "/usr/lib/",
            "/System/Cryptexes/",
            "/private/preboot/Cryptexes/",
            "/Preboot/Cryptexes/",
            "/System/iOSSupport/",
            "/System/DriverKit/",
            "/Library/Apple/"
        ]
        if trustedPrefixes.contains(where: { canonical.hasPrefix($0) }) {
            let lower = canonical.lowercased()
            if lower.contains("substrate")
                || lower.contains("ellekit")
                || lower.contains("tweakinject")
                || lower.contains("cycript")
                || lower.contains("frida")
                || lower.contains("sslkillswitch") {
                return false
            }
            return true
        }
        #if targetEnvironment(simulator)
        if canonical.contains(".simruntime/") || canonical.contains("/CoreSimulator/") {
            return true
        }
        #endif
        #if DEBUG
        if canonical.hasPrefix("/Developer/") || canonical.contains(".xctest/") || canonical.contains("Xcode") {
            return true
        }
        #endif
        return false
    }
}
