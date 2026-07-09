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

    // MARK: - Environment info (informational, not scored)

    /// Whether the app is running in the iOS Simulator. Ported from a
    /// well-known open-source iOS security-detection technique.
    /// Informational only — SafetyNet already gates every scored check on
    /// this via `#if targetEnvironment(simulator)`, so it is not itself a
    /// threat signal.
    public var isSimulator: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
        #endif
    }

    /// Whether the device has iOS Lockdown Mode enabled. Ported from the
    /// same upstream technique referenced above. Informational only, not
    /// scored — Lockdown Mode is a legitimate Apple opt-in defensive
    /// feature, not evidence of compromise.
    public var isInLockdownMode: Bool {
        UserDefaults.standard.bool(forKey: "LDMGlobalEnabled")
    }

    // MARK: - Opt-in diagnostics (not wired into scoring — need a caller-supplied target)

    /// Checks whether a debugger breakpoint is set at `functionAddr`.
    /// ARM64-only (returns `false` on other architectures). Ported from the
    /// equivalent breakpoint-detection check in a well-known open-source
    /// iOS security-detection technique.
    public func hasBreakpoint(at functionAddr: UnsafeRawPointer, functionSize: vm_size_t? = nil) -> Bool {
        DebuggerDetector.hasBreakpoint(at: functionAddr, functionSize: functionSize)
    }

    /// Checks whether the function at `functionAddr` has been hooked via
    /// MSHookFunction (Cydia Substrate/Substitute). Detection only — does
    /// not patch anything. ARM64-only. Ported from the equivalent MSHook
    /// detection check in the same upstream technique.
    public func isMSHooked(at functionAddr: UnsafeMutableRawPointer) -> Bool {
        HookDetector.isMSHooked(at: functionAddr)
    }

    /// Checks whether `selector` on `detectionClass` has been swizzled to
    /// an implementation outside system frameworks, your app's own binary,
    /// or `dyldAllowList`. Ported from the equivalent runtime-hook detection
    /// check in the same upstream technique — see
    /// `HookDetector.isRuntimeHooked` for a documented deviation from
    /// upstream (omits a live-patching pre-step to keep SafetyNet entirely
    /// read-only).
    public func isRuntimeHooked(
        dyldAllowList: [String],
        detectionClass: AnyClass,
        selector: Selector,
        isClassMethod: Bool
    ) -> Bool {
        HookDetector.isRuntimeHooked(
            dyldAllowList: dyldAllowList,
            detectionClass: detectionClass,
            selector: selector,
            isClassMethod: isClassMethod
        )
    }

    /// Checks the app's bundle ID, embedded provisioning profile hash,
    /// and/or a named Mach-O image's `__TEXT,__text` hash against
    /// caller-supplied expected values. Ported from the equivalent file
    /// integrity check in the same upstream technique.
    public func checkFileIntegrity(_ checks: [FileIntegrityCheck]) -> FileIntegrityCheckResult {
        FileIntegrityChecker.checkFileIntegrity(checks)
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
