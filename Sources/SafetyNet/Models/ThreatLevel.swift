import Foundation

public enum ThreatLevel: Int, Comparable, Sendable {
    case none = 0
    case medium = 1
    case high = 2
    case critical = 3

    public static func < (lhs: ThreatLevel, rhs: ThreatLevel) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}
