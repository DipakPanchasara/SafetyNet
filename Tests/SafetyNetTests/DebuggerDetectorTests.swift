import Darwin
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

    func testHasWatchpointReturnsFalseInTestEnvironment() {
        XCTAssertFalse(DebuggerDetector.hasWatchpoint())
    }

    func testHasPSelectFlagIsRepeatable() {
        let first = DebuggerDetector.hasPSelectFlag()
        let second = DebuggerDetector.hasPSelectFlag()
        XCTAssertEqual(first, second)
    }

    func testHasBreakpointReturnsFalseForKnownCleanLibcFunction() {
        // Opt-in diagnostic, not gated by DEBUG/Simulator (matches
        // IntegrityValidator.detectMemoryPatch's un-gated pattern). Resolve
        // a known, always-loaded libc symbol via dlsym (same technique
        // already used by this file's anti-debug code) so this exercises
        // the real ARM64 decode path against known-clean code, not a
        // short-circuit.
        guard let addr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "strlen") else {
            XCTFail("dlsym(strlen) unexpectedly returned nil")
            return
        }
        let result = DebuggerDetector.hasBreakpoint(at: UnsafeRawPointer(addr), functionSize: 64)
        XCTAssertFalse(result)
    }
}
