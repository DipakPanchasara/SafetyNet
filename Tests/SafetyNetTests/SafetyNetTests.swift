import XCTest
@testable import SafetyNet

final class SafetyNetTests: XCTestCase {

    override func tearDown() {
        SafetyNet.shared.stopMonitoring()
        super.tearDown()
    }

    // MARK: - check()

    func testCheckReturnsNoneLevelInDebugOrSimulator() async {
        // SecurityOrchestrator.runChecks() short-circuits under #if DEBUG,
        // and the test binary also runs on the Simulator where the
        // underlying detectors are guarded independently.
        let event = await SafetyNet.shared.check()
        XCTAssertEqual(event.level, .none)
        XCTAssertTrue(event.reasons.isEmpty)
    }

    func testCheckIsRepeatable() async {
        let first = await SafetyNet.shared.check()
        let second = await SafetyNet.shared.check()
        XCTAssertEqual(first.level, second.level)
    }

    func testSharedInstanceIsSingleton() {
        XCTAssertTrue(SafetyNet.shared === SafetyNet.shared)
    }

    // MARK: - Monitoring lifecycle

    func testStartMonitoringDoesNotCrash() {
        SafetyNet.shared.startMonitoring { _ in
            XCTFail("onThreat should not fire in a Debug/Simulator test run")
        }
    }

    func testStopMonitoringWithoutStartDoesNotCrash() {
        SafetyNet.shared.stopMonitoring()
    }

    func testStartThenStopMonitoringDoesNotCrash() {
        SafetyNet.shared.startMonitoring { _ in }
        SafetyNet.shared.stopMonitoring()
    }

    func testStartMonitoringTwiceDoesNotCrash() {
        SafetyNet.shared.startMonitoring { _ in }
        SafetyNet.shared.startMonitoring { _ in }
        SafetyNet.shared.stopMonitoring()
    }

    // MARK: - Keychain via public facade

    func testPublicStoreRetrieveDeleteRoundTrip() throws {
        let key = "safetynet_public_api_key"
        defer { SafetyNet.shared.delete(forKey: key) }

        try SafetyNet.shared.store(secret: "hello-world", forKey: key)
        XCTAssertEqual(try SafetyNet.shared.retrieve(forKey: key), "hello-world")

        XCTAssertTrue(SafetyNet.shared.delete(forKey: key))
        XCTAssertThrowsError(try SafetyNet.shared.retrieve(forKey: key))
    }

    func testPublicWipeKeychainRemovesStoredSecret() throws {
        let key = "safetynet_public_wipe_key"
        try SafetyNet.shared.store(secret: "temp", forKey: key)
        XCTAssertTrue(SafetyNet.shared.wipeKeychain())
        XCTAssertThrowsError(try SafetyNet.shared.retrieve(forKey: key))
    }

    func testPublicRetrieveThrowsForMissingKey() {
        XCTAssertThrowsError(try SafetyNet.shared.retrieve(forKey: "safetynet_never_stored_key"))
    }
}
