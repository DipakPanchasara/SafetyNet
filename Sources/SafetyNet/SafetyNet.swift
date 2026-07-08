import Foundation

/// SafetyNet — native Swift security library for iOS apps.
///
/// Ported from cordova-plugin-security. Unlike that plugin, SafetyNet never
/// takes automatic destructive action (no auto-lockdown, no forced app
/// termination, no NotificationCenter side effects). It only ever reports a
/// `ThreatEvent` back to the caller and lets the host app decide what to do.
/// This is a deliberate design choice: in the Cordova integration, automatic
/// notifications posted on HIGH/CRITICAL threat caused the host banking app
/// to disable its own login UI, which was extremely difficult to diagnose.
/// A library should never make that call on the host app's behalf.
public final class SafetyNet {

    public static let shared = SafetyNet()

    private init() {
        DebuggerDetector.installAntiDebugAtLaunch()
    }

    /// Runs the selected `checks` once and returns the current threat
    /// assessment. Defaults to `.all`, matching the original behavior
    /// exactly (zero-argument call sites keep compiling and behaving
    /// identically).
    ///
    /// When `checks` is a partial subset, `event.level` is `nil` — see
    /// `ThreatEvent.level` and `SafetyNetChecks` for why.
    public func check(checks: SafetyNetChecks = .all) async -> ThreatEvent {
        await SecurityOrchestrator.shared.runChecks(checks: checks)
    }

    /// Starts periodic background re-checks (randomised interval 30-120s)
    /// using the selected `checks`. No-op in Debug builds.
    ///
    /// `onThreat` fires when `level >= .medium` (full `checks`), or when
    /// `level == nil && reasons` is non-empty (partial `checks`).
    public func startMonitoring(
        checks: SafetyNetChecks = .all,
        onThreat: @escaping @Sendable (ThreatEvent) -> Void
    ) {
        Task { await SecurityOrchestrator.shared.startMonitoring(checks: checks, onThreat: onThreat) }
    }

    public func stopMonitoring() {
        Task { await SecurityOrchestrator.shared.stopMonitoring() }
    }

    // MARK: - Secure Keychain

    public func store(secret: String, forKey key: String) throws {
        try SecureKeychain.store(secret: secret, forKey: key)
    }

    public func retrieve(forKey key: String) throws -> String {
        try SecureKeychain.retrieve(forKey: key)
    }

    @discardableResult
    public func delete(forKey key: String) -> Bool {
        SecureKeychain.delete(forKey: key)
    }

    /// Wipes all Keychain items stored by SafetyNet. Does not touch items
    /// from other SDKs or the host app's own Keychain usage.
    @discardableResult
    public func wipeKeychain() -> Bool {
        SecureKeychain.wipeAll()
    }
}
