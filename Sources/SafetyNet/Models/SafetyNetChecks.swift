import Foundation

/// Selects which of SafetyNet's individually-scored signals participate in
/// a `check()`/`startMonitoring()` call.
///
/// `.all` (the default) reproduces today's behavior exactly: every signal
/// runs and `ThreatEvent.level` is populated. Any other combination is a
/// "partial" run — see `SecurityOrchestrator.runChecks(checks:)` for why
/// `ThreatEvent.level` is `nil` for partial runs.
public struct SafetyNetChecks: OptionSet, Sendable {
    public let rawValue: Int

    public init(rawValue: Int) {
        self.rawValue = rawValue
    }

    // MARK: - Jailbreak sub-signals (JailbreakDetector)
    public static let jailbreakFilesystem  = SafetyNetChecks(rawValue: 1 << 0)
    public static let jailbreakDylib       = SafetyNetChecks(rawValue: 1 << 1)
    public static let fridaPort            = SafetyNetChecks(rawValue: 1 << 2)
    public static let sandboxBreach        = SafetyNetChecks(rawValue: 1 << 3)
    public static let urlScheme            = SafetyNetChecks(rawValue: 1 << 4)
    public static let suspiciousProcess    = SafetyNetChecks(rawValue: 1 << 5)
    public static let shadowTweak          = SafetyNetChecks(rawValue: 1 << 6)
    public static let suspiciousSymlinks   = SafetyNetChecks(rawValue: 1 << 10)
    public static let suspiciousOpenPort   = SafetyNetChecks(rawValue: 1 << 11)

    // MARK: - Debugger signals (DebuggerDetector)
    public static let debuggerAttached     = SafetyNetChecks(rawValue: 1 << 7)
    public static let processTraced        = SafetyNetChecks(rawValue: 1 << 8)
    public static let watchpointDetected   = SafetyNetChecks(rawValue: 1 << 12)
    public static let pSelectFlagSet       = SafetyNetChecks(rawValue: 1 << 13)

    // MARK: - Integrity signal (IntegrityValidator)
    public static let codeSignatureInvalid = SafetyNetChecks(rawValue: 1 << 9)

    // MARK: - Network signals (ProxyDetector)
    public static let systemProxy          = SafetyNetChecks(rawValue: 1 << 14)
    public static let vpnAsProxy           = SafetyNetChecks(rawValue: 1 << 15)

    // MARK: - Convenience group unions

    /// All 9 jailbreak sub-signals. Note: `JailbreakDetector.detect()` runs
    /// all of its internal checks any time *any* member of this group is
    /// selected — see SecurityOrchestrator for details.
    public static let jailbreak: SafetyNetChecks = [
        .jailbreakFilesystem, .jailbreakDylib, .fridaPort, .sandboxBreach,
        .urlScheme, .suspiciousProcess, .shadowTweak, .suspiciousSymlinks,
        .suspiciousOpenPort,
    ]

    public static let debugger: SafetyNetChecks = [
        .debuggerAttached, .processTraced, .watchpointDetected, .pSelectFlagSet,
    ]

    public static let integrity: SafetyNetChecks = [.codeSignatureInvalid]

    /// System proxy and VPN-as-proxy signals (ProxyDetector). Independently
    /// selectable, mirroring an equivalent upstream opt-in
    /// `considerVPNConnectionAsProxy` flag on its own proxy check.
    public static let network: SafetyNetChecks = [.systemProxy, .vpnAsProxy]

    /// The default. Running with `.all` reproduces the pre-existing
    /// behavior exactly, including a non-nil `ThreatEvent.level`.
    public static let all: SafetyNetChecks = [.jailbreak, .debugger, .integrity, .network]
}
