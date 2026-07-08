import Foundation

public struct ThreatEvent: Sendable {
    /// Aggregate severity across all selected signals. Only populated when
    /// the *full* check set (`SafetyNetChecks.all`) was run — see
    /// `SecurityOrchestrator.runChecks(checks:)`. `nil` for partial runs:
    /// the threshold math (medium 30-59 / high 60-99 / critical 100+) was
    /// calibrated assuming all 10 signals could contribute, and a
    /// caller-chosen subset could otherwise reach `.critical` off far fewer
    /// signals than intended. For partial runs, inspect `reasons` directly
    /// and decide severity yourself.
    public let level: ThreatLevel?
    public let reasons: [ThreatReason]
    public let timestamp: Date

    public init(level: ThreatLevel?, reasons: [ThreatReason], timestamp: Date = Date()) {
        self.level = level
        self.reasons = reasons
        self.timestamp = timestamp
    }
}
