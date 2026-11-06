import Darwin
import Foundation
import MachO

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
            return antiDebugActive ? "正常（调试监控已启用 · 无注入库）" : "正常（调试构建 · 无注入库）"
        }
        let all = anomalies + unexpectedLibraries.map { "检测到非系统动态库：\($0)" }
        return all.joined(separator: "；")
    }
}

/// Process-level tamper, dylib-injection, and debugger detection safe for iOS App Sandbox & self-signed deployments.
/// Note: Never invoke `ptrace(PT_DENY_ATTACH)` on iOS — XNU's iOS Sandbox (`Sandbox.kext`) immediately kills (`SIGKILL`)
/// sandboxed processes invoking `SYS_ptrace`, and arm64e PAC rejects raw `dlsym` casts. Instead we use read-only
/// `sysctl(KERN_PROC_PID)` (`P_TRACED`) polling, which is 100% sandbox-safe across all iOS versions.
enum RuntimeSecurity {
    private static let pTracedFlag: Int32 = 0x00000800 // P_TRACED in <sys/proc.h>

    /// Queries the kernel process table (`KERN_PROC_PID`) for `P_TRACED` (read-only, sandbox-safe).
    static func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        guard result == 0 else { return false }
        return (info.kp_proc.p_flag & pTracedFlag) != 0
    }

    /// Inspects loaded Mach-O images, environment variables, and known hook paths using strictly read-only checks.
    static func auditEnvironment() -> RuntimeIntegrityReport {
        var anomalies: [String] = []
        var unexpectedLibraries: [String] = []

        if let inserted = getenv("DYLD_INSERT_LIBRARIES"), String(cString: inserted).isEmpty == false {
            anomalies.append("环境变量存在 DYLD_INSERT_LIBRARIES 动态注入")
        }

        #if DEBUG
        let antiDebugActive = false
        #else
        let antiDebugActive = true
        if isDebuggerAttached() {
            anomalies.append("检测到调试器附加（P_TRACED）")
        }
        #endif

        let mainExecutable = normalizedPath(Bundle.main.executablePath ?? "")
        let mainAppDir = normalizedPath(Bundle.main.bundlePath)
        let imageCount = _dyld_image_count()
        for idx in 0..<imageCount {
            guard let rawName = _dyld_get_image_name(idx) else { continue }
            let imagePath = normalizedPath(String(cString: rawName))
            if imagePath == mainExecutable { continue }
            if isTrustedSystemImagePath(imagePath) { continue }
            // Ignore system-generated app bundle plugins during XCTest runs in Debug.
            #if DEBUG
            if !mainAppDir.isEmpty && imagePath.hasPrefix(mainAppDir) { continue }
            #endif

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
            "/System/Cryptexes/",
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
        #if DEBUG
        if path.hasPrefix("/Developer/") || path.contains(".xctest/") || path.contains("Xcode") {
            return true
        }
        #endif
        return false
    }
}
