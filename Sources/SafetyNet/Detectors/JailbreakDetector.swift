import Darwin
import Foundation
import MachO
import UIKit

// Ported from cordova-plugin-security JailbreakDetector.m.
//
// Note: the memory-scan Frida check (_check_frida_memory in the Cordova
// version) is intentionally not ported. It caused false positives on clean
// devices because third-party SDKs (AirshipKit etc.) contain the same byte
// sequence as the scanner's own signature. Frida is already covered by the
// port-scan and dylib-scan checks below.
enum JailbreakDetector {

    struct Result {
        var filesystem = false
        var dylib = false
        var fridaPort = false
        var sandboxBreach = false
        var urlScheme = false
        var suspiciousProcess = false
        var shadowTweak = false

        var isJailbroken: Bool {
            filesystem || dylib || fridaPort || sandboxBreach
                || urlScheme || suspiciousProcess || shadowTweak
        }
    }

    static func detect() async -> Result {
        #if targetEnvironment(simulator)
        return Result()
        #else
        var result = Result()
        result.filesystem = checkFilesystem()
        result.dylib = checkDylibs()
        result.fridaPort = checkFridaPorts()
        result.sandboxBreach = checkSandbox()
        result.urlScheme = await checkURLSchemes()
        result.suspiciousProcess = checkRunningProcesses()
        result.shadowTweak = checkShadowClass()
        return result
        #endif
    }

    // MARK: - Filesystem check

    private static let suspiciousPaths = [
        // Package managers
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Installer.app",
        // Substrate / Substitute / libhooker
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/lib/libsubstitute.dylib",
        "/usr/lib/libhooker.dylib",
        "/usr/lib/TweakInject.dylib",
        "/usr/lib/substrate",
        // Shells & tools
        "/bin/bash",
        "/bin/sh",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/usr/bin/cycript",
        "/usr/local/bin/cycript",
        // Package system
        "/etc/apt",
        "/var/lib/apt",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/stash",
        "/private/var/mobile/Library/SBSettings/Themes",
        // Checkra1n specific
        "/var/checkra1n.dmg",
        "/var/binpack",
        "/.bootstrapped_electra",
        // Dopamine / XinaA15
        "/var/jb",
        "/var/LIB",
        "/var/ulb",
    ]

    private static func checkFilesystem() -> Bool {
        var st = stat()
        return suspiciousPaths.contains { stat($0, &st) == 0 }
    }

    // MARK: - Injected dylib scan

    private static let suspiciousDylibs = [
        "FridaGadget", "frida-agent", "frida", "cynject", "libcycript",
        "MobileSubstrate", "substrate", "substitute", "libhooker",
        "TweakInject", "SSLKillSwitch", "A-Bypass", "Liberty", "Choicy",
        "PreferenceLoader",
    ]

    private static func checkDylibs() -> Bool {
        let count = _dyld_image_count()
        for i in 0..<count {
            guard let namePtr = _dyld_get_image_name(i) else { continue }
            let name = String(cString: namePtr)
            for suspicious in suspiciousDylibs {
                if name.range(of: suspicious, options: .caseInsensitive) != nil {
                    secLog("Suspicious dylib detected")
                    return true
                }
            }
        }
        return false
    }

    // MARK: - Frida port check

    private static func checkFridaPorts() -> Bool {
        let ports: [UInt16] = [27042, 27043, 4444, 1234]
        for port in ports {
            let sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
            guard sock >= 0 else { continue }
            defer { close(sock) }

            var tv = timeval(tv_sec: 0, tv_usec: 100_000)
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            addr.sin_addr.s_addr = in_addr_t(INADDR_LOOPBACK).bigEndian

            let result = withUnsafePointer(to: &addr) { ptr -> Int32 in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            if result == 0 { return true }
        }
        return false
    }

    // MARK: - Sandbox write test

    private static func checkSandbox() -> Bool {
        let testPath = "/private/JBTestProbe_DeleteMe"
        let fd = open(testPath, O_WRONLY | O_CREAT, 0o644)
        guard fd >= 0 else { return false }
        close(fd)
        unlink(testPath)
        return true
    }

    // MARK: - URL scheme check

    private static let jailbreakSchemes = [
        "cydia://package/com.fake.package",
        "sileo://",
        "zbra://",
        "undecimus://",
        "activator://",
        "filza://",
        "unc0ver://",
    ]

    @MainActor
    private static func checkURLSchemes() -> Bool {
        for scheme in jailbreakSchemes {
            guard let url = URL(string: scheme) else { continue }
            if UIApplication.shared.canOpenURL(url) {
                secLog("JB URL scheme detected")
                return true
            }
        }
        return false
    }

    // MARK: - Running process scan

    private static let suspiciousProcessNames = [
        "frida-server", "frida", "cynject", "cycript",
        "MobileCydia", "Cydia", "afpd", "sftp-server", "sshd",
    ]

    private static func checkRunningProcesses() -> Bool {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0 else { return false }

        size += size / 10 // 10% buffer
        let count = size / MemoryLayout<kinfo_proc>.stride
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count)

        guard sysctl(&mib, 4, &procs, &size, nil, 0) == 0 else { return false }

        let actualCount = size / MemoryLayout<kinfo_proc>.stride
        for i in 0..<actualCount {
            let name = withUnsafeBytes(of: procs[i].kp_proc.p_comm) { rawBuffer -> String in
                let ptr = rawBuffer.baseAddress!.assumingMemoryBound(to: CChar.self)
                return String(cString: ptr)
            }
            if suspiciousProcessNames.contains(where: { $0.caseInsensitiveCompare(name) == .orderedSame }) {
                secLog("Suspicious process detected")
                return true
            }
        }
        return false
    }

    // MARK: - Shadow class detection

    private static func checkShadowClass() -> Bool {
        // Shadow tweak registers ShadowRuleset with these specific internal
        // methods. Presence of the class name alone is NOT sufficient — must
        // confirm methods, since a third-party SDK could coincidentally use
        // the same generic class name.
        if let shadowClass = NSClassFromString("ShadowRuleset") {
            if shadowClass.instancesRespond(to: Selector(("internalDictionary")))
                || shadowClass.instancesRespond(to: Selector(("shouldHidePath:"))) {
                secLog("Shadow tweak detected")
                return true
            }
        }
        if let shadowAlt = NSClassFromString("Shadow") {
            if shadowAlt.instancesRespond(to: Selector(("shouldHidePath:")))
                || shadowAlt.instancesRespond(to: Selector(("isBypassEnabled"))) {
                secLog("Shadow tweak detected (alt class)")
                return true
            }
        }
        return false
    }
}
