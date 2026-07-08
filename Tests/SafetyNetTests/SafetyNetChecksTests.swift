import XCTest
@testable import SafetyNet

final class SafetyNetChecksTests: XCTestCase {

    func testAllContainsEveryIndividualSignal() {
        let all: [SafetyNetChecks] = [
            .jailbreakFilesystem, .jailbreakDylib, .fridaPort, .sandboxBreach,
            .urlScheme, .suspiciousProcess, .shadowTweak,
            .debuggerAttached, .processTraced, .codeSignatureInvalid,
        ]
        for signal in all {
            XCTAssertTrue(SafetyNetChecks.all.contains(signal))
        }
    }

    func testJailbreakGroupUnionMatchesSevenSubSignals() {
        let expected: SafetyNetChecks = [
            .jailbreakFilesystem, .jailbreakDylib, .fridaPort, .sandboxBreach,
            .urlScheme, .suspiciousProcess, .shadowTweak,
        ]
        XCTAssertEqual(SafetyNetChecks.jailbreak, expected)
    }

    func testDebuggerAndIntegrityGroupsAreDisjointFromJailbreak() {
        XCTAssertTrue(SafetyNetChecks.jailbreak.isDisjoint(with: .debugger))
        XCTAssertTrue(SafetyNetChecks.jailbreak.isDisjoint(with: .integrity))
        XCTAssertTrue(SafetyNetChecks.debugger.isDisjoint(with: .integrity))
    }

    func testGroupsTogetherEqualAll() {
        let union: SafetyNetChecks = [.jailbreak, .debugger, .integrity]
        XCTAssertEqual(union, .all)
    }

    func testPartialSelectionIsNotEqualToAll() {
        let partial: SafetyNetChecks = [.debuggerAttached]
        XCTAssertNotEqual(partial, .all)
    }
}
