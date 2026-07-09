import CFNetwork
import Foundation

// Ported from a well-known open-source iOS security-detection technique,
// split into two independently-selectable checks matching SafetyNetChecks
// .systemProxy / .vpnAsProxy (mirrors upstream's own opt-in
// considerVPNConnectionAsProxy flag).
enum ProxyDetector {

    static func checkSystemProxy() -> Bool {
        #if DEBUG || targetEnvironment(simulator)
        return false
        #else
        guard let settings = systemProxySettings() else { return false }
        return settings.keys.contains("HTTPProxy") || settings.keys.contains("HTTPSProxy")
        #endif
    }

    static func checkVPNAsProxy() -> Bool {
        #if DEBUG || targetEnvironment(simulator)
        return false
        #else
        guard let settings = systemProxySettings(),
              let scoped = settings["__SCOPED__"] as? [String: Any] else {
            return false
        }

        let vpnInterfacePrefixes = ["tap", "tun", "ppp", "ipsec", "utun"]
        for interface in scoped.keys {
            for prefix in vpnInterfacePrefixes where interface.contains(prefix) {
                secLog("VPN interface detected")
                return true
            }
        }
        return false
        #endif
    }

    private static func systemProxySettings() -> [String: Any]? {
        guard let unmanagedSettings = CFNetworkCopySystemProxySettings() else {
            return nil
        }
        return unmanagedSettings.takeRetainedValue() as? [String: Any]
    }
}
