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
    private static let criticalSystemSymbols = [
        "ptrace",
        "sysctl",
        "_dyld_get_image_name",
        "dladdr",
        "CCKeyDerivationPBKDF"
    ]

    /// Sets XNU `P_LNOATTACH` on the current process in Release builds, rejecting external `lldb` / `debugserver`
    /// attachment at the kernel level even when personal self-signing profiles include `get-task-allow=true`.
    @discardableResult
    static func enforceReleaseAntiDebug() -> Bool {
        #if DEBUG
        return false
        #else
        _ = cardse_ptrace(ptDenyAttach, 0, nil, 0)
        return true
        #endif
    }

    /// Queries the kernel process table (`KERN_PROC_PID`) for `P_TRACED` (read-only, sandbox-safe).
    static func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        guard result == 0 else { return false }
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

            let dyldPath = rawNamePtr.map { normalizedPath(String(cString: $0)) } ?? ""
            var dladdrPath = ""
            if let headerPtr {
                var dlInfo = Dl_info()
                if dladdr(UnsafeRawPointer(headerPtr), &dlInfo) != 0, let fname = dlInfo.dli_fname {
                    dladdrPath = normalizedPath(String(cString: fname))
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
    private typealias SysctlFn = @convention(c) (
        UnsafeMutablePointer<Int32>?, UInt32, UnsafeMutableRawPointer?,
        UnsafeMutablePointer<Int>?, UnsafeMutableRawPointer?, Int
    ) -> Int32
    private typealias PBKDFFn = @convention(c) (
        CCPBKDFAlgorithm, UnsafePointer<CChar>?, Int, UnsafePointer<UInt8>?, Int,
        CCPseudoRandomAlgorithm, UInt32, UnsafeMutablePointer<UInt8>?, Int
    ) -> Int32
    private typealias SecItemCopyFn = @convention(c) (CFDictionary, UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
    private typealias SecItemAddFn = @convention(c) (CFDictionary, UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus

    /// Function pointers loaded through THIS image's own import table (`__DATA_CONST,__got`) — i.e. exactly
    /// the addresses the app really calls. A fishhook-style injector that rewrites GOT slots changes these values.
    private static func boundImportPointers() -> [(String, UnsafeRawPointer)] {
        let imageName: DyldImageNameFn = _dyld_get_image_name
        let imageHeader: DyldImageHeaderFn = _dyld_get_image_header
        let imageCount: DyldImageCountFn = _dyld_image_count
        let dladdrFn: DladdrFn = dladdr
        let dlsymFn: DlsymFn = dlsym
        let getenvFn: GetenvFn = getenv
        let sysctlFn: SysctlFn = sysctl
        let pbkdfFn: PBKDFFn = CCKeyDerivationPBKDF
        let secCopyFn: SecItemCopyFn = SecItemCopyMatching
        let secAddFn: SecItemAddFn = SecItemAdd
        return [
            ("_dyld_get_image_name", unsafeBitCast(imageName, to: UnsafeRawPointer.self)),
            ("_dyld_get_image_header", unsafeBitCast(imageHeader, to: UnsafeRawPointer.self)),
            ("_dyld_image_count", unsafeBitCast(imageCount, to: UnsafeRawPointer.self)),
            ("dladdr", unsafeBitCast(dladdrFn, to: UnsafeRawPointer.self)),
            ("dlsym", unsafeBitCast(dlsymFn, to: UnsafeRawPointer.self)),
            ("getenv", unsafeBitCast(getenvFn, to: UnsafeRawPointer.self)),
            ("sysctl", unsafeBitCast(sysctlFn, to: UnsafeRawPointer.self)),
            ("CCKeyDerivationPBKDF", unsafeBitCast(pbkdfFn, to: UnsafeRawPointer.self)),
            ("SecItemCopyMatching", unsafeBitCast(secCopyFn, to: UnsafeRawPointer.self)),
            ("SecItemAdd", unsafeBitCast(secAddFn, to: UnsafeRawPointer.self))
        ]
    }

    private typealias SharedCacheRangeFn = @convention(c) (UnsafeMutablePointer<Int>?) -> UnsafeRawPointer?

    /// Every genuine Apple system function (libsystem, libdyld, Security, CommonCrypto…) lives inside the dyld
    /// shared cache. Hook code from an injected dylib or anonymous executable memory never does. So each pointer
    /// in our own import table must fall inside the shared-cache address range.
    private static func verifyBoundImportPointers(anomalies: inout [String]) {
        guard let cacheRange = sharedCacheAddressRange(anomalies: &anomalies) else { return }
        for (name, pointer) in boundImportPointers() where !cacheRange.contains(UInt(bitPattern: pointer)) {
            appendUnique(&anomalies, "检测到关键函数导入表被运行时重绑定（\(name)）")
        }
    }

    /// Returns the dyld shared-cache range, or `nil` when unavailable (fail-quiet, no false positives).
    /// A forged "cover everything" range is rejected because our own executable is never part of the cache.
    private static func sharedCacheAddressRange(anomalies: inout [String]) -> Range<UInt>? {
        guard let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2),
              let symbol = dlsym(rtldDefault, "_dyld_get_shared_cache_range") else {
            return nil
        }
        let rangeFn = unsafeBitCast(symbol, to: SharedCacheRangeFn.self)
        var length = 0
        guard let start = rangeFn(&length), length > 0, length < (1 << 36) else {
            return nil
        }
        let lower = UInt(bitPattern: start)
        let (upper, overflow) = lower.addingReportingOverflow(UInt(length))
        guard !overflow else { return nil }
        let range = lower..<upper
        let ownImage = UInt(bitPattern: UnsafeRawPointer(#dsohandle))
        if range.contains(ownImage) {
            appendUnique(&anomalies, "检测到 dyld 共享缓存范围被伪造")
            return nil
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
        for symbol in criticalSystemSymbols {
            guard let symAddr = dlsym(rtldDefault, symbol) else {
                appendUnique(&anomalies, "关键系统安全符号缺失（\(symbol)）")
                continue
            }
            var dlInfo = Dl_info()
            guard dladdr(symAddr, &dlInfo) != 0, let rawFname = dlInfo.dli_fname else {
                appendUnique(&anomalies, "关键系统安全符号来源不可解析（\(symbol)）")
                continue
            }
            let ownerPath = normalizedPath(String(cString: rawFname))
            let isSystemUmbrella = ownerPath.hasPrefix("/usr/lib/system/")
                || ownerPath == "/usr/lib/libSystem.B.dylib"
            if !isSystemUmbrella || !isTrustedSystemImagePath(ownerPath) {
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

    private static func normalizedPath(_ path: String) -> String {
        var result = path
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
        if result.hasPrefix("/private/var/") || result.hasPrefix("/private/etc/") || result.hasPrefix("/private/tmp/") {
            return String(result.dropFirst("/private".count))
        }
        return result
    }

    private static func isTrustedSystemImagePath(_ path: String) -> Bool {
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
        if trustedPrefixes.contains(where: { path.hasPrefix($0) }) {
            let lower = path.lowercased()
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
        if path.contains(".simruntime/") || path.contains("/CoreSimulator/") {
            return true
        }
        #endif
        #if DEBUG
        if path.hasPrefix("/Developer/") || path.contains(".xctest/") || path.contains("Xcode") {
            return true
        }
        #endif
        return false
    }
}
