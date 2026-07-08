import Foundation
import Security

// Ported from cordova-plugin-security SecureKeychain.m.
//
// Uses .whenUnlockedThisDeviceOnly (no biometric) by default — the Cordova
// plugin switched away from biometric-gated access because retrieveSecret
// would trigger a Face ID prompt that could hang the caller's async flow
// indefinitely if the user dismissed it at the wrong moment.
public enum SecureKeychain {

    public enum KeychainError: Error {
        case osStatus(OSStatus)
        case dataDecodingFailed
    }

    private static let service = "com.safetynet.keychain"

    public static func store(secret: String, forKey key: String) throws {
        guard let data = secret.data(using: .utf8) else {
            throw KeychainError.dataDecodingFailed
        }

        // Remove stale entry to avoid errSecDuplicateItem
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        // kSecAttrAccessible (not SecAccessControlCreateWithFlags/
        // kSecAttrAccessControl) is used deliberately — SecAccessControl-based
        // items implicitly require a Keychain Sharing / access-group
        // entitlement even when no biometric flags are requested. A bare SPM
        // XCTest bundle (no host app, no provisioning) has none, so every
        // write failed with errSecMissingEntitlement (-34018) until this was
        // switched. kSecAttrAccessible alone needs no such entitlement and is
        // sufficient since no biometric/passcode gating is used here anyway.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: data,
            kSecAttrSynchronizable as String: false,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.osStatus(status)
        }
    }

    public static func retrieve(forKey key: String) throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            throw KeychainError.osStatus(status)
        }
        guard let data = result as? Data, let value = String(data: data, encoding: .utf8) else {
            throw KeychainError.dataDecodingFailed
        }
        return value
    }

    @discardableResult
    public static func delete(forKey key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        return SecItemDelete(query as CFDictionary) == errSecSuccess
    }

    /// Scoped wipe — only deletes items owned by this library's service
    /// identifier. Never touches Certificate/Key/Identity items or items
    /// from other SDKs / app extensions.
    @discardableResult
    public static func wipeAll() -> Bool {
        // Only kSecClassGenericPassword is ever written by store(), so only
        // that class needs to be wiped. kSecAttrService is not a valid match
        // attribute for kSecClassInternetPassword (that class matches on
        // kSecAttrServer instead) — including it here previously returned
        // errSecParam rather than errSecItemNotFound, incorrectly flipping
        // this method to report failure even when there was nothing to wipe.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
