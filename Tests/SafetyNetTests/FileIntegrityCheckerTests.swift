import XCTest
@testable import SafetyNet

final class FileIntegrityCheckerTests: XCTestCase {

    // Unlike every other detector in this codebase, these checks are
    // deterministic string/hash comparisons unrelated to jailbreak/device
    // state — not gated by DEBUG/Simulator — so real positive-path
    // assertions are possible here, not just "returns false in this
    // environment."

    func testBundleIDCheckPassesForCorrectBundleID() throws {
        guard let actualBundleID = Bundle.main.bundleIdentifier else {
            throw XCTSkip("No bundle identifier available in this test environment")
        }
        let result = FileIntegrityChecker.checkFileIntegrity([.bundleID(actualBundleID)])
        XCTAssertFalse(result.result)
        XCTAssertTrue(result.hitChecks.isEmpty)
    }

    func testBundleIDCheckFlagsIncorrectBundleID() {
        let result = FileIntegrityChecker.checkFileIntegrity([
            .bundleID("com.definitely.not.the.real.bundle.id"),
        ])
        XCTAssertTrue(result.result)
        XCTAssertEqual(result.hitChecks.count, 1)
    }

    func testMobileProvisionCheckDoesNotFlagWhenFileIsAbsent() {
        // SPM test bundles don't ship an embedded.mobileprovision — matches
        // upstream's own behavior of only flagging when the file exists
        // AND the hash differs, never when it's simply missing.
        let result = FileIntegrityChecker.checkFileIntegrity([
            .mobileProvision("0000000000000000000000000000000000000000000000000000000000000000"),
        ])
        XCTAssertFalse(result.result)
        XCTAssertTrue(result.hitChecks.isEmpty)
    }

    func testMachOCheckFlagsIncorrectExpectedHash() {
        let result = FileIntegrityChecker.checkFileIntegrity([
            .machO("SafetyNetTests", "0000000000000000000000000000000000000000000000000000000000000000"),
        ])
        #if arch(arm64)
        XCTAssertTrue(result.result)
        XCTAssertEqual(result.hitChecks.count, 1)
        #else
        // Non-ARM64 hosts (e.g. x86_64 Simulator) always return not-tampered.
        XCTAssertFalse(result.result)
        #endif
    }

    func testMultipleChecksAggregateHitsIndependently() {
        let result = FileIntegrityChecker.checkFileIntegrity([
            .bundleID("com.definitely.not.the.real.bundle.id"),
            .mobileProvision("0000000000000000000000000000000000000000000000000000000000000000"),
        ])
        XCTAssertTrue(result.result)
        XCTAssertEqual(result.hitChecks.count, 1)
    }

    func testEmptyChecksReturnsNotTampered() {
        let result = FileIntegrityChecker.checkFileIntegrity([])
        XCTAssertFalse(result.result)
        XCTAssertTrue(result.hitChecks.isEmpty)
    }
}
