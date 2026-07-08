import XCTest
@testable import SafetyNet

final class DebuggerDetectorTests: XCTestCase {

    // Test binaries built by SwiftPM always compile with DEBUG defined (and/or
    // run on the Simulator), so both guarded methods must short-circuit to a
    // safe, non-blocking result rather than performing the real sysctl checks.

    func testIsDebuggerAttachedReturnsFalseInTestEnvironment() {
        XCTAssertFalse(DebuggerDetector.isDebuggerAttached())
    }

    func testIsBeingTracedReturnsFalseInTestEnvironment() {
        XCTAssertFalse(DebuggerDetector.isBeingTraced())
    }

    func testInstallAntiDebugAtLaunchDoesNotCrash() {
        // The real work happens in a __attribute__((constructor)) before
        // main(); this call is a documented no-op integration point and
        // must be safe to invoke repeatedly.
        DebuggerDetector.installAntiDebugAtLaunch()
        DebuggerDetector.installAntiDebugAtLaunch()
    }

    func testRepeatedCallsAreConsistent() {
        for _ in 0..<5 {
            XCTAssertFalse(DebuggerDetector.isDebuggerAttached())
            XCTAssertFalse(DebuggerDetector.isBeingTraced())
        }
    }
}
