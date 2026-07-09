import XCTest
@testable import SafetyNet

final class SafetyNetChecksTests: XCTestCase {

    func testAllContainsEveryIndividualSignal() {
        let all: [SafetyNetChecks] = [
            .jailbreakFilesystem, .jailbreakDylib, .fridaPort, .sandboxBreach,
            .urlScheme, .suspiciousProcess, .shadowTweak, .suspiciousSymlinks,
            .suspiciousOpenPort,
            .debuggerAttached, .processTraced, .watchpointDetected, .pSelectFlagSet,
            .codeSignatureInvalid,
            .systemProxy, .vpnAsProxy,
        ]
        for signal in all {
            XCTAssertTrue(SafetyNetChecks.all.contains(signal))
        }
    }

    func testJailbreakGroupUnionMatchesNineSubSignals() {
        let expected: SafetyNetChecks = [
            .jailbreakFilesystem, .jailbreakDylib, .fridaPort, .sandboxBreach,
            .urlScheme, .suspiciousProcess, .shadowTweak, .suspiciousSymlinks,
            .suspiciousOpenPort,
        ]
        XCTAssertEqual(SafetyNetChecks.jailbreak, expected)
    }

    func testDebuggerGroupUnionMatchesFourSubSignals() {
        let expected: SafetyNetChecks = [
            .debuggerAttached, .processTraced, .watchpointDetected, .pSelectFlagSet,
        ]
        XCTAssertEqual(SafetyNetChecks.debugger, expected)
    }

    func testNetworkGroupUnionMatchesTwoSubSignals() {
        let expected: SafetyNetChecks = [.systemProxy, .vpnAsProxy]
        XCTAssertEqual(SafetyNetChecks.network, expected)
    }

    func testDebuggerIntegrityNetworkGroupsAreDisjointFromJailbreak() {
        XCTAssertTrue(SafetyNetChecks.jailbreak.isDisjoint(with: .debugger))
        XCTAssertTrue(SafetyNetChecks.jailbreak.isDisjoint(with: .integrity))
        XCTAssertTrue(SafetyNetChecks.jailbreak.isDisjoint(with: .network))
        XCTAssertTrue(SafetyNetChecks.debugger.isDisjoint(with: .integrity))
        XCTAssertTrue(SafetyNetChecks.debugger.isDisjoint(with: .network))
        XCTAssertTrue(SafetyNetChecks.integrity.isDisjoint(with: .network))
    }

    func testGroupsTogetherEqualAll() {
        let union: SafetyNetChecks = [.jailbreak, .debugger, .integrity, .network]
        XCTAssertEqual(union, .all)
    }

    func testPartialSelectionIsNotEqualToAll() {
        let partial: SafetyNetChecks = [.debuggerAttached]
        XCTAssertNotEqual(partial, .all)
    }
}
