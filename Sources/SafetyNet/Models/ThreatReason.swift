import Foundation

public enum ThreatReason: String, Sendable {
    case jailbreakFilesystem = "jb_filesystem"
    case jailbreakDylib = "jb_dylib"
    case fridaPort = "jb_frida_port"
    case sandboxBreach = "jb_sandbox"
    case urlScheme = "jb_url_scheme"
    case suspiciousProcess = "jb_suspicious_process"
    case shadowTweak = "jb_shadow_tweak"
    case suspiciousSymlinks = "jb_symlinks"
    case suspiciousOpenPort = "jb_open_port"
    case debuggerAttached = "debugger_attached"
    case processTraced = "process_traced"
    case watchpointDetected = "watchpoint_detected"
    case pSelectFlagSet = "p_select_flag"
    case codeSignatureInvalid = "codesig_invalid"
    case memoryPatched = "memory_patched"
    case systemProxyDetected = "system_proxy"
    case vpnDetected = "vpn_detected"
}
