import XCTest
@testable import SafetyNet

final class SecureKeychainTests: XCTestCase {

    override func tearDown() {
        // Best-effort cleanup in case a test fails before its own teardown runs
        SecureKeychain.delete(forKey: "kc_test_basic")
        SecureKeychain.delete(forKey: "kc_test_overwrite")
        SecureKeychain.delete(forKey: "kc_test_delete")
        SecureKeychain.delete(forKey: "kc_test_empty")
        SecureKeychain.delete(forKey: "kc_test_unicode")
        super.tearDown()
    }

    func testStoreThenRetrieveReturnsSameValue() throws {
        try SecureKeychain.store(secret: "super-secret-token", forKey: "kc_test_basic")
        let value = try SecureKeychain.retrieve(forKey: "kc_test_basic")
        XCTAssertEqual(value, "super-secret-token")
    }

    func testStoreOverwritesExistingValueForSameKey() throws {
        try SecureKeychain.store(secret: "first", forKey: "kc_test_overwrite")
        try SecureKeychain.store(secret: "second", forKey: "kc_test_overwrite")
        let value = try SecureKeychain.retrieve(forKey: "kc_test_overwrite")
        XCTAssertEqual(value, "second")
    }

    func testDeleteRemovesValue() throws {
        try SecureKeychain.store(secret: "temp", forKey: "kc_test_delete")
        XCTAssertTrue(SecureKeychain.delete(forKey: "kc_test_delete"))
        XCTAssertThrowsError(try SecureKeychain.retrieve(forKey: "kc_test_delete"))
    }

    func testDeleteOnMissingKeyReturnsFalseButDoesNotThrow() {
        // errSecItemNotFound -> delete() reports false, no crash/throw
        let result = SecureKeychain.delete(forKey: "kc_test_never_stored")
        XCTAssertFalse(result)
    }

    func testRetrieveMissingKeyThrows() {
        XCTAssertThrowsError(try SecureKeychain.retrieve(forKey: "kc_test_never_stored")) { error in
            guard case SecureKeychain.KeychainError.osStatus = error else {
                return XCTFail("Expected .osStatus, got \(error)")
            }
        }
    }

    func testStoreEmptyStringSucceeds() throws {
        try SecureKeychain.store(secret: "", forKey: "kc_test_empty")
        let value = try SecureKeychain.retrieve(forKey: "kc_test_empty")
        XCTAssertEqual(value, "")
    }

    func testStoreUnicodeAndEmojiRoundTrips() throws {
        let secret = "पासवर्ड-🔒-密码"
        try SecureKeychain.store(secret: secret, forKey: "kc_test_unicode")
        let value = try SecureKeychain.retrieve(forKey: "kc_test_unicode")
        XCTAssertEqual(value, secret)
    }

    func testWipeAllRemovesStoredItem() throws {
        try SecureKeychain.store(secret: "will-be-wiped", forKey: "kc_test_basic")
        XCTAssertTrue(SecureKeychain.wipeAll())
        XCTAssertThrowsError(try SecureKeychain.retrieve(forKey: "kc_test_basic"))
    }

    func testWipeAllOnEmptyKeychainStillSucceeds() {
        // errSecItemNotFound must be tolerated, not treated as failure
        XCTAssertTrue(SecureKeychain.wipeAll())
    }

    func testDifferentKeysAreIndependent() throws {
        try SecureKeychain.store(secret: "value-a", forKey: "kc_test_basic")
        try SecureKeychain.store(secret: "value-b", forKey: "kc_test_overwrite")
        XCTAssertEqual(try SecureKeychain.retrieve(forKey: "kc_test_basic"), "value-a")
        XCTAssertEqual(try SecureKeychain.retrieve(forKey: "kc_test_overwrite"), "value-b")
    }
}
