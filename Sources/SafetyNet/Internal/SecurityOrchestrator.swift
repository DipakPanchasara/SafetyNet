import Foundation

// Ported from cordova-plugin-security SecurityOrchestrator.m.
actor SecurityOrchestrator {

    static let shared = SecurityOrchestrator()

    private var monitorTask: Task<Void, Never>?
    private(set) var currentThreatLevel: ThreatLevel = .none

    private init() {}

    // MARK: - Score all checks

    func runChecks() async -> ThreatEvent {
        #if DEBUG
        // Never run real checks in Debug — debugger attachment and dev code
        // signing produce false-positive HIGH scores that would disable
        // sensitive features or trigger lockdown during development.
        return ThreatEvent(level: .none, reasons: [])
        #else
        var score = 0
        var reasons: [ThreatReason] = []

        let jb = await JailbreakDetector.detect()
        if jb.filesystem { score += 30; reasons.append(.jailbreakFilesystem) }
        if jb.dylib { score += 50; reasons.append(.jailbreakDylib) }
        if jb.fridaPort { score += 60; reasons.append(.fridaPort) }
        if jb.sandboxBreach { score += 40; reasons.append(.sandboxBreach) }
        if jb.urlScheme { score += 35; reasons.append(.urlScheme) }
        if jb.suspiciousProcess { score += 45; reasons.append(.suspiciousProcess) }
        if jb.shadowTweak { score += 60; reasons.append(.shadowTweak) }

        if DebuggerDetector.isDebuggerAttached() { score += 50; reasons.append(.debuggerAttached) }
        if DebuggerDetector.isBeingTraced() { score += 40; reasons.append(.processTraced) }

        if !IntegrityValidator.validateCodeSignature() { score += 60; reasons.append(.codeSignatureInvalid) }

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

    func startMonitoring(onThreat: @escaping @Sendable (ThreatEvent) -> Void) {
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
                let event = await self.runChecks()
                if event.level >= .medium {
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
