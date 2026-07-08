import XCTest
@testable import SafetyNet

final class IntegrityValidatorTests: XCTestCase {

    func testValidateCodeSignatureOnSimulatorReturnsTrue() {
        // #if targetEnvironment(simulator) short-circuits to true — test
        // binaries are ad-hoc signed by the toolchain, not the real
        // csops()-backed check exercised on device.
        XCTAssertTrue(IntegrityValidator.validateCodeSignature())
    }

    func testDetectMemoryPatchReturnsFalseForUnknownExecutableName() {
        // No loaded image will ever match this name, so the function must
        // return false (no match found) rather than crash or throw.
        let result = IntegrityValidator.detectMemoryPatch(executableName: "ThisImageDoesNotExist_xyz")
        XCTAssertFalse(result)
    }

    func testDetectMemoryPatchIsRepeatable() {
        let first = IntegrityValidator.detectMemoryPatch(executableName: "xctest")
        let second = IntegrityValidator.detectMemoryPatch(executableName: "xctest")
        XCTAssertEqual(first, second)
    }

    func testValidateCodeSignatureIsRepeatable() {
        let first = IntegrityValidator.validateCodeSignature()
        let second = IntegrityValidator.validateCodeSignature()
        XCTAssertEqual(first, second)
    }
}
