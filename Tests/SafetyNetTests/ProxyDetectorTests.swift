import XCTest
@testable import SafetyNet

final class ProxyDetectorTests: XCTestCase {

    // DEBUG/Simulator-guarded, matching every other scored-signal detector
    // in this codebase — a CI/simulator run has no system proxy or VPN
    // configured, so this validates the short-circuit, not real network
    // introspection.

    func testCheckSystemProxyReturnsFalseInTestEnvironment() {
        XCTAssertFalse(ProxyDetector.checkSystemProxy())
    }

    func testCheckVPNAsProxyReturnsFalseInTestEnvironment() {
        XCTAssertFalse(ProxyDetector.checkVPNAsProxy())
    }

    func testRepeatedCallsAreConsistent() {
        for _ in 0..<5 {
            XCTAssertFalse(ProxyDetector.checkSystemProxy())
            XCTAssertFalse(ProxyDetector.checkVPNAsProxy())
        }
    }
}
