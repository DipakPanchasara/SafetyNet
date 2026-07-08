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

    /// Runs all checks once and returns the current threat assessment.
    public func check() async -> ThreatEvent {
        await SecurityOrchestrator.shared.runChecks()
    }

    /// Starts periodic background re-checks (randomised interval 30-120s).
    /// `onThreat` is only invoked when the level is `.medium` or above.
    /// No-op in Debug builds.
    public func startMonitoring(onThreat: @escaping @Sendable (ThreatEvent) -> Void) {
        Task { await SecurityOrchestrator.shared.startMonitoring(onThreat: onThreat) }
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
