import Foundation

// Ported from cordova-plugin-security SecurityOrchestrator.m.
actor SecurityOrchestrator {

    static let shared = SecurityOrchestrator()

    private var monitorTask: Task<Void, Never>?
    private(set) var currentThreatLevel: ThreatLevel = .none

    private init() {}

    // MARK: - Score all checks

    /// Runs the selected `checks` and returns a `ThreatEvent`.
    ///
    /// When `checks == .all` (the default), this reproduces the original
    /// behavior exactly: every scored signal runs, scores sum into
    /// an aggregate `ThreatLevel`, and `event.level` is non-nil.
    ///
    /// When `checks` is a partial subset, `event.level` is always `nil` —
    /// the medium/high/critical thresholds below assume all signals
    /// could contribute, and were deliberately calibrated so no single
    /// check can reach `.critical` alone; a caller-chosen subset could
    /// otherwise reach `.critical` off far fewer independent signals than
    /// intended. Partial runs report only which of the *selected* checks
    /// fired via `event.reasons`, leaving severity judgment to the caller.
    func runChecks(checks: SafetyNetChecks = .all) async -> ThreatEvent {
        #if DEBUG
        // Never run real checks in Debug — debugger attachment and dev code
        // signing produce false-positive HIGH scores that would disable
        // sensitive features or trigger lockdown during development.
        return ThreatEvent(level: checks == .all ? ThreatLevel.none : nil, reasons: [])
        #else
        var score = 0
        var reasons: [ThreatReason] = []

        // JailbreakDetector.detect() is monolithic — it always runs all 7
        // of its internal checks in one pass. We run it once if ANY
        // jailbreak sub-signal is selected, then keep only the selected
        // sub-results.
        if !checks.isDisjoint(with: .jailbreak) {
            let jb = await JailbreakDetector.detect()
            if checks.contains(.jailbreakFilesystem), jb.filesystem {
                score += 30; reasons.append(.jailbreakFilesystem)
            }
            if checks.contains(.jailbreakDylib), jb.dylib {
                score += 50; reasons.append(.jailbreakDylib)
            }
            if checks.contains(.fridaPort), jb.fridaPort {
                score += 60; reasons.append(.fridaPort)
            }
            if checks.contains(.sandboxBreach), jb.sandboxBreach {
                score += 40; reasons.append(.sandboxBreach)
            }
            if checks.contains(.urlScheme), jb.urlScheme {
                score += 35; reasons.append(.urlScheme)
            }
            if checks.contains(.suspiciousProcess), jb.suspiciousProcess {
                score += 45; reasons.append(.suspiciousProcess)
            }
            if checks.contains(.shadowTweak), jb.shadowTweak {
                score += 60; reasons.append(.shadowTweak)
            }
            if checks.contains(.suspiciousSymlinks), jb.suspiciousSymlinks {
                score += 35; reasons.append(.suspiciousSymlinks)
            }
            if checks.contains(.suspiciousOpenPort), jb.suspiciousOpenPort {
                score += 40; reasons.append(.suspiciousOpenPort)
            }
        }

        if checks.contains(.debuggerAttached), DebuggerDetector.isDebuggerAttached() {
            score += 50; reasons.append(.debuggerAttached)
        }
        if checks.contains(.processTraced), DebuggerDetector.isBeingTraced() {
            score += 40; reasons.append(.processTraced)
        }
        if checks.contains(.watchpointDetected), DebuggerDetector.hasWatchpoint() {
            score += 40; reasons.append(.watchpointDetected)
        }
        if checks.contains(.pSelectFlagSet), DebuggerDetector.hasPSelectFlag() {
            // Upstream marks this check "EXPERIMENTAL" —
            // weighted below the existing minimum (30) accordingly.
            score += 25; reasons.append(.pSelectFlagSet)
        }
        if checks.contains(.codeSignatureInvalid), !IntegrityValidator.validateCodeSignature() {
            score += 60; reasons.append(.codeSignatureInvalid)
        }
        if checks.contains(.systemProxy), ProxyDetector.checkSystemProxy() {
            // Legitimate corporate/privacy proxies are common — weak
            // evidence alone, weighted low.
            score += 15; reasons.append(.systemProxyDetected)
        }
        if checks.contains(.vpnAsProxy), ProxyDetector.checkVPNAsProxy() {
            score += 15; reasons.append(.vpnDetected)
        }

        guard checks == .all else {
            // Partial run: report raw facts only, decline to editorialize
            // a severity. currentThreatLevel is intentionally left
            // untouched here rather than reset — it only ever reflects the
            // most recent *full* assessment.
            return ThreatEvent(level: nil, reasons: reasons)
        }

        // Thresholds require multiple independent signals before Critical —
        // no single check (e.g. Shadow alone) can trigger full lockdown.
        let level: ThreatLevel
        switch score {
        case 100...: level = .critical
        case 60..<100: level = .high
        case 30..<60: level = .medium
        default: level = .none
        }

        currentThreatLevel = level
        return ThreatEvent(level: level, reasons: reasons)
        #endif
    }

    // MARK: - Continuous monitoring with jitter

    /// Starts periodic background re-checks (randomised interval 30-120s)
    /// using the selected `checks`.
    ///
    /// - When `checks == .all`: `onThreat` fires exactly as before, only
    ///   when the aggregate `level >= .medium`.
    /// - When `checks` is a partial subset: `level` is always `nil`, so
    ///   `onThreat` instead fires whenever `reasons` is non-empty, i.e.
    ///   whenever any selected signal fired positive on that poll.
    func startMonitoring(
        checks: SafetyNetChecks = .all,
        onThreat: @escaping @Sendable (ThreatEvent) -> Void
    ) {
        #if DEBUG
        return
        #else
        guard monitorTask == nil else { return }
        monitorTask = Task { [weak self] in
            while !Task.isCancelled {
                // Randomised interval (30-120s) so timing is unpredictable —
                // defeats scripted bypass attempts that wait for a fixed gap.
                let seconds = Double.random(in: 30...120)
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                guard !Task.isCancelled, let self else { return }
                let event = await self.runChecks(checks: checks)

                let shouldFire: Bool
                if let level = event.level {
                    shouldFire = level >= .medium
                } else {
                    shouldFire = !event.reasons.isEmpty
                }

                if shouldFire {
                    onThreat(event)
                }
            }
        }
        #endif
    }

    func stopMonitoring() {
        monitorTask?.cancel()
        monitorTask = nil
    }
}
