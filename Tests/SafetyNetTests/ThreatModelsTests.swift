import XCTest
@testable import SafetyNet

final class ThreatModelsTests: XCTestCase {

    // MARK: - ThreatLevel

    func testThreatLevelRawValues() {
        XCTAssertEqual(ThreatLevel.none.rawValue, 0)
        XCTAssertEqual(ThreatLevel.medium.rawValue, 1)
        XCTAssertEqual(ThreatLevel.high.rawValue, 2)
        XCTAssertEqual(ThreatLevel.critical.rawValue, 3)
    }

    func testThreatLevelOrderingAscending() {
        XCTAssertLessThan(ThreatLevel.none, .medium)
        XCTAssertLessThan(ThreatLevel.medium, .high)
        XCTAssertLessThan(ThreatLevel.high, .critical)
        XCTAssertLessThan(ThreatLevel.none, .critical)
    }

    func testThreatLevelOrderingNotReversed() {
        XCTAssertFalse(ThreatLevel.critical < .none)
        XCTAssertFalse(ThreatLevel.high < .medium)
    }

    func testThreatLevelEquality() {
        XCTAssertEqual(ThreatLevel.high, ThreatLevel.high)
        XCTAssertNotEqual(ThreatLevel.high, ThreatLevel.critical)
    }

    func testThreatLevelSorting() {
        let shuffled: [ThreatLevel] = [.critical, .none, .high, .medium]
        XCTAssertEqual(shuffled.sorted(), [.none, .medium, .high, .critical])
    }

    // MARK: - ThreatReason

    func testThreatReasonRawValues() {
        XCTAssertEqual(ThreatReason.jailbreakFilesystem.rawValue, "jb_filesystem")
        XCTAssertEqual(ThreatReason.jailbreakDylib.rawValue, "jb_dylib")
        XCTAssertEqual(ThreatReason.fridaPort.rawValue, "jb_frida_port")
        XCTAssertEqual(ThreatReason.sandboxBreach.rawValue, "jb_sandbox")
        XCTAssertEqual(ThreatReason.urlScheme.rawValue, "jb_url_scheme")
        XCTAssertEqual(ThreatReason.suspiciousProcess.rawValue, "jb_suspicious_process")
        XCTAssertEqual(ThreatReason.shadowTweak.rawValue, "jb_shadow_tweak")
        XCTAssertEqual(ThreatReason.debuggerAttached.rawValue, "debugger_attached")
        XCTAssertEqual(ThreatReason.processTraced.rawValue, "process_traced")
        XCTAssertEqual(ThreatReason.codeSignatureInvalid.rawValue, "codesig_invalid")
        XCTAssertEqual(ThreatReason.memoryPatched.rawValue, "memory_patched")
    }

    func testThreatReasonInitFromRawValue() {
        XCTAssertEqual(ThreatReason(rawValue: "jb_dylib"), .jailbreakDylib)
        XCTAssertNil(ThreatReason(rawValue: "not_a_real_reason"))
    }

    // MARK: - ThreatEvent

    func testThreatEventStoresLevelAndReasons() {
        let event = ThreatEvent(level: .high, reasons: [.debuggerAttached, .processTraced])
        XCTAssertEqual(event.level, .high)
        XCTAssertEqual(event.reasons, [.debuggerAttached, .processTraced])
    }

    func testThreatEventDefaultTimestampIsRecent() {
        let before = Date()
        let event = ThreatEvent(level: .none, reasons: [])
        let after = Date()
        XCTAssertTrue(event.timestamp >= before && event.timestamp <= after)
    }

    func testThreatEventExplicitTimestamp() {
        let fixed = Date(timeIntervalSince1970: 0)
        let event = ThreatEvent(level: .medium, reasons: [], timestamp: fixed)
        XCTAssertEqual(event.timestamp, fixed)
    }

    func testThreatEventEmptyReasonsAllowed() {
        let event = ThreatEvent(level: .none, reasons: [])
        XCTAssertTrue(event.reasons.isEmpty)
    }
}
