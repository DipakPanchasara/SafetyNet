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
        XCTAssertEqual(event.level, ThreatLevel.none)
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

    // MARK: - check(checks:)

    func testCheckWithAllChecksReturnsNonNilLevel() async {
        let event = await SafetyNet.shared.check(checks: .all)
        XCTAssertNotNil(event.level)
        XCTAssertEqual(event.level, ThreatLevel.none)
    }

    func testCheckDefaultParameterMatchesExplicitAll() async {
        // check() with no args must remain behaviorally identical to
        // check(checks: .all) — the zero-argument compatibility guarantee
        // for existing call sites.
        let implicit = await SafetyNet.shared.check()
        let explicit = await SafetyNet.shared.check(checks: .all)
        XCTAssertEqual(implicit.level, explicit.level)
    }

    func testCheckWithPartialJailbreakSubsetReturnsNilLevel() async {
        let event = await SafetyNet.shared.check(checks: [.jailbreakFilesystem, .fridaPort])
        XCTAssertNil(event.level)
        // Debug/Simulator short-circuits every detector to a clean result,
        // so reasons must be empty here — this exercises the nil-level
        // plumbing for a partial run, not real positive detection (which
        // requires a physical, non-Debug device).
        XCTAssertTrue(event.reasons.isEmpty)
    }

    func testCheckWithPartialDebuggerOnlyReturnsNilLevel() async {
        let event = await SafetyNet.shared.check(checks: .debugger)
        XCTAssertNil(event.level)
        XCTAssertTrue(event.reasons.isEmpty)
    }

    func testCheckWithSingleIntegrityCheckReturnsNilLevel() async {
        let event = await SafetyNet.shared.check(checks: [.codeSignatureInvalid])
        XCTAssertNil(event.level)
        XCTAssertTrue(event.reasons.isEmpty)
    }

    func testCheckWithNetworkChecksReturnsNilLevel() async {
        let event = await SafetyNet.shared.check(checks: .network)
        XCTAssertNil(event.level)
        XCTAssertTrue(event.reasons.isEmpty)
    }

    func testCheckWithNewlyAddedSubSignalsReturnsNilLevel() async {
        let event = await SafetyNet.shared.check(checks: [
            .suspiciousSymlinks, .suspiciousOpenPort, .watchpointDetected, .pSelectFlagSet,
        ])
        XCTAssertNil(event.level)
        XCTAssertTrue(event.reasons.isEmpty)
    }

    // MARK: - Environment info

    func testIsSimulatorIsTrueInTestEnvironment() {
        // Test binaries always run on the Simulator.
        XCTAssertTrue(SafetyNet.shared.isSimulator)
    }

    func testIsInLockdownModeIsRepeatable() {
        let first = SafetyNet.shared.isInLockdownMode
        let second = SafetyNet.shared.isInLockdownMode
        XCTAssertEqual(first, second)
    }

    // MARK: - Opt-in diagnostics

    func testCheckFileIntegrityFlagsIncorrectBundleID() {
        let result = SafetyNet.shared.checkFileIntegrity([
            .bundleID("com.definitely.not.the.real.bundle.id"),
        ])
        XCTAssertTrue(result.result)
    }

    // MARK: - Monitoring lifecycle

    func testStartMonitoringDoesNotCrash() {
        SafetyNet.shared.startMonitoring { _ in
            XCTFail("onThreat should not fire in a Debug/Simulator test run")
        }
    }

    func testStartMonitoringWithPartialChecksDoesNotCrash() {
        SafetyNet.shared.startMonitoring(checks: [.debuggerAttached]) { _ in
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
