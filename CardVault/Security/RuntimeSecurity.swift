import Darwin
import Foundation
import MachO

struct RuntimeIntegrityReport: Equatable, Sendable {
    let isCompromised: Bool
    let antiDebugActive: Bool
    let unexpectedLibraries: [String]
    let anomalies: [String]

    var summaryText: String {
        if !isCompromised {
            return antiDebugActive ? "正常（反调试已启用 · 无注入库）" : "正常（调试构建 · 无注入库）"
        }
        let all = anomalies + unexpectedLibraries.map { "检测到非系统动态库：\($0)" }
        return all.joined(separator: "；")
    }
}

/// Process-level tamper, dylib-injection, debugger, and sandbox-escape detection for self-signed iOS deployments.
enum RuntimeSecurity {
    private static let ptDenyAttach: CInt = 31 // PT_DENY_ATTACH in <sys/ptrace.h>
    private static let pTracedFlag: Int32 = 0x00000800 // P_TRACED in <sys/proc.h>

    /// Asks the XNU kernel to block `ptrace` / `lldb` / `debugserver` attachment in Release builds,
    /// neutralizing the `get-task-allow` risk of personal Apple ID self-signing profiles.
    @discardableResult
    static func enforceReleaseAntiDebug() -> Bool {
        #if DEBUG
        return false
        #else
        typealias PtraceFn = @convention(c) (CInt, pid_t, UnsafeMutableRawPointer?, CInt) -> CInt
        guard let handle = dlopen(nil, RTLD_NOW),
              let sym = dlsym(handle, "ptrace") else {
            return false
        }
        let ptraceCall = unsafeBitCast(sym, to: PtraceFn.self)
        _ = ptraceCall(ptDenyAttach, 0, nil, 0)
        return true
        #endif
    }

    /// Queries the kernel process table (`KERN_PROC_PID`) for `P_TRACED`.
    static func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        guard result == 0 else { return false }
        return (info.kp_proc.p_flag & pTracedFlag) != 0
    }

    /// Inspects loaded Mach-O images, environment variables, and sandbox boundaries.
    static func auditEnvironment(antiDebugActive: Bool) -> RuntimeIntegrityReport {
        var anomalies: [String] = []
        var unexpectedLibraries: [String] = []

        if let inserted = getenv("DYLD_INSERT_LIBRARIES"), String(cString: inserted).isEmpty == false {
            anomalies.append("环境变量存在 DYLD_INSERT_LIBRARIES 动态注入")
        }

        #if !DEBUG
        if isDebuggerAttached() {
            anomalies.append("检测到调试器附加（P_TRACED）")
        }
        #endif

        let mainExecutable = normalizedPath(Bundle.main.executablePath ?? "")
        let imageCount = _dyld_image_count()
        for idx in 0..<imageCount {
            guard let rawName = _dyld_get_image_name(idx) else { continue }
            let imagePath = normalizedPath(String(cString: rawName))
            if imagePath == mainExecutable { continue }
            if isTrustedSystemImagePath(imagePath) { continue }

            let basename = (imagePath as NSString).lastPathComponent
            if !unexpectedLibraries.contains(basename) {
                unexpectedLibraries.append(basename)
            }
        }

        for jbPath in [
            "/var/jb",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/usr/lib/ellekit.dylib",
            "/usr/lib/TweakInject"
        ] where access(jbPath, F_OK) == 0 {
            anomalies.append("检测到越狱或 Hook 环境路径（\(jbPath)）")
            break
        }

        // Verify iOS app sandbox still blocks writes outside container.
        let probePath = "/private/cardse_sandbox_probe_\(UUID().uuidString)"
        if FileManager.default.createFile(atPath: probePath, contents: Data([0x00])) {
            try? FileManager.default.removeItem(atPath: probePath)
            anomalies.append("应用沙盒边界异常（允许向沙盒外写入）")
        }

        let compromised = !anomalies.isEmpty || !unexpectedLibraries.isEmpty
        return RuntimeIntegrityReport(
            isCompromised: compromised,
            antiDebugActive: antiDebugActive,
            unexpectedLibraries: unexpectedLibraries,
            anomalies: anomalies
        )
    }

    private static func normalizedPath(_ path: String) -> String {
        if path.hasPrefix("/private/var/") {
            return String(path.dropFirst("/private".count))
        }
        if path.hasPrefix("/private/etc/") {
            return String(path.dropFirst("/private".count))
        }
        return path
    }

    private static func isTrustedSystemImagePath(_ path: String) -> Bool {
        let trustedPrefixes = [
            "/System/Library/",
            "/usr/lib/",
            "/System/Cryptexes/OS/System/Library/",
            "/System/Cryptexes/OS/usr/lib/",
            "/System/DriverKit/"
        ]
        if trustedPrefixes.contains(where: { path.hasPrefix($0) }) {
            // `/usr/lib/TweakInject` or `ellekit` / `substrate` under `/usr/lib` on rootful/rootless setups must still fail!
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
        #if DEBUG
        if path.hasPrefix("/Developer/") || path.contains(".xctest/") || path.contains("Xcode.app/") {
            return true
        }
        #endif
        return false
    }
}
