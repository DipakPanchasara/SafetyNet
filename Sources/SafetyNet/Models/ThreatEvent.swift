import Foundation

public struct ThreatEvent: Sendable {
    public let level: ThreatLevel
    public let reasons: [ThreatReason]
    public let timestamp: Date

    public init(level: ThreatLevel, reasons: [ThreatReason], timestamp: Date = Date()) {
        self.level = level
        self.reasons = reasons
        self.timestamp = timestamp
    }
}
