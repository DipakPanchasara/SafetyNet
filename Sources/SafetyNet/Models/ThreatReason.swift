import Foundation

public enum ThreatReason: String, Sendable {
    case jailbreakFilesystem = "jb_filesystem"
    case jailbreakDylib = "jb_dylib"
    case fridaPort = "jb_frida_port"
    case sandboxBreach = "jb_sandbox"
    case urlScheme = "jb_url_scheme"
    case suspiciousProcess = "jb_suspicious_process"
    case shadowTweak = "jb_shadow_tweak"
    case debuggerAttached = "debugger_attached"
    case processTraced = "process_traced"
    case codeSignatureInvalid = "codesig_invalid"
    case memoryPatched = "memory_patched"
}
