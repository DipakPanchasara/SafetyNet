import Darwin
import XCTest
@testable import SafetyNet

private class HookDetectorTestTarget: NSObject {
    @objc dynamic func sampleMethod() {}
}

final class HookDetectorTests: XCTestCase {

    // MARK: - isMSHooked

    func testIsMSHookedReturnsFalseForKnownCleanLibcFunction() {
        // Opt-in diagnostic, not gated by DEBUG/Simulator. Resolve a known,
        // always-loaded libc symbol via dlsym so this exercises the real
        // ARM64 decode path against known-clean code.
        guard let addr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "strlen") else {
            XCTFail("dlsym(strlen) unexpectedly returned nil")
            return
        }
        XCTAssertFalse(HookDetector.isMSHooked(at: addr))
    }

    // MARK: - isRuntimeHooked

    func testIsRuntimeHookedReturnsTrueForMethodOutsideMainBinaryWhenNotAllowlisted() {
        // sampleMethod's implementation lives in the SafetyNetTests.xctest
        // bundle, which — from _dyld_get_image_name(0)'s perspective in an
        // XCTest run — is a separate loaded image, not the "main app
        // binary" (that's the XCTest runner host, not this test bundle).
        // isRuntimeHooked correctly treats it as untrusted unless
        // allow-listed, matching upstream's own algorithm (which assumes a
        // real host app, same inherent constraint).
        let result = HookDetector.isRuntimeHooked(
            dyldAllowList: [],
            detectionClass: HookDetectorTestTarget.self,
            selector: #selector(HookDetectorTestTarget.sampleMethod),
            isClassMethod: false
        )
        XCTAssertTrue(result)
    }

    func testIsRuntimeHookedReturnsFalseWhenTestBundleIsAllowlisted() {
        // Same method as above, but with its own image explicitly
        // allow-listed — validates the dyldAllowList mechanism itself.
        let result = HookDetector.isRuntimeHooked(
            dyldAllowList: ["SafetyNetTests"],
            detectionClass: HookDetectorTestTarget.self,
            selector: #selector(HookDetectorTestTarget.sampleMethod),
            isClassMethod: false
        )
        XCTAssertFalse(result)
    }

    func testIsRuntimeHookedReturnsTrueForMissingSelector() {
        // Matches upstream: a selector that doesn't resolve to any method
        // is treated as hooked (can't prove otherwise).
        let result = HookDetector.isRuntimeHooked(
            dyldAllowList: [],
            detectionClass: HookDetectorTestTarget.self,
            selector: Selector(("thisSelectorDoesNotExistAnywhere")),
            isClassMethod: false
        )
        XCTAssertTrue(result)
    }
}
