import XCTest
@testable import SafetyNet

final class JailbreakDetectorTests: XCTestCase {

    // These tests run on the Simulator (CI and local `swift build`/`xcodebuild
    // test` both target arm64-*-ios-simulator), where `detect()` short-circuits
    // to an all-clear Result without touching the filesystem/socket/process
    // checks. This validates the simulator guard, not the real detection logic
    // (which requires a physical device to exercise meaningfully).

    func testDetectReturnsCleanResultOnSimulator() async {
        let result = await JailbreakDetector.detect()
        XCTAssertFalse(result.isJailbroken)
    }

    func testResultIsJailbrokenIsFalseWhenAllFlagsClear() {
        let result = JailbreakDetector.Result()
        XCTAssertFalse(result.isJailbroken)
    }

    func testResultIsJailbrokenIsTrueIfAnySingleFlagSet() {
        var result = JailbreakDetector.Result()
        result.filesystem = true
        XCTAssertTrue(result.isJailbroken)

        result = JailbreakDetector.Result()
        result.dylib = true
        XCTAssertTrue(result.isJailbroken)

        result = JailbreakDetector.Result()
        result.fridaPort = true
        XCTAssertTrue(result.isJailbroken)

        result = JailbreakDetector.Result()
        result.sandboxBreach = true
        XCTAssertTrue(result.isJailbroken)

        result = JailbreakDetector.Result()
        result.urlScheme = true
        XCTAssertTrue(result.isJailbroken)

        result = JailbreakDetector.Result()
        result.suspiciousProcess = true
        XCTAssertTrue(result.isJailbroken)

        result = JailbreakDetector.Result()
        result.shadowTweak = true
        XCTAssertTrue(result.isJailbroken)

        result = JailbreakDetector.Result()
        result.suspiciousSymlinks = true
        XCTAssertTrue(result.isJailbroken)

        result = JailbreakDetector.Result()
        result.suspiciousOpenPort = true
        XCTAssertTrue(result.isJailbroken)
    }

    func testDetectIsRepeatable() async {
        let first = await JailbreakDetector.detect()
        let second = await JailbreakDetector.detect()
        XCTAssertEqual(first.isJailbroken, second.isJailbroken)
    }
}
