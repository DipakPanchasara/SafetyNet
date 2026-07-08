import Darwin
import Foundation
import SafetyNetObjC

// Ported from cordova-plugin-security DebuggerDetector.m.
enum DebuggerDetector {

    static func installAntiDebugAtLaunch() {
        // The __attribute__((constructor)) in AntiDebugBridge.m already ran
        // before main(). This call exists as a documented integration point.
        safetynet_install_anti_debug()
    }

    static func isDebuggerAttached() -> Bool {
        #if DEBUG || targetEnvironment(simulator)
        return false
        #else
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = sysctl(&mib, 4, &info, &size, nil, 0)
        guard result == 0 else { return false }
        return (info.kp_proc.p_flag & P_TRACED) != 0
        #endif
    }

    static func isBeingTraced() -> Bool {
        #if DEBUG || targetEnvironment(simulator)
        return false
        #else
        // Legitimate parent = SpringBoard or launchd, not lldb/Xcode
        let ppid = getppid()
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, ppid]
        let result = sysctl(&mib, 4, &info, &size, nil, 0)
        guard result == 0 else { return false }

        let parentName = withUnsafeBytes(of: info.kp_proc.p_comm) { rawBuffer -> String in
            let ptr = rawBuffer.baseAddress!.assumingMemoryBound(to: CChar.self)
            return String(cString: ptr)
        }
        let legitimateParents: Set<String> = ["launchd", "SpringBoard", "backboardd"]
        return !legitimateParents.contains(parentName)
        #endif
    }
}
