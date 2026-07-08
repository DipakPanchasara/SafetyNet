import Foundation

// Ported from cordova-plugin-security SecurityLogging.h.
//
// Zero output in Release builds: on a jailbroken device any process can read
// another process's log output. Logging which specific check fired, a dylib
// name, or a threat score gives an attacker a guided map of exactly which
// bypasses still need to be done. This function compiles away to nothing in
// Release; only Debug builds see the log line.
func secLog(_ message: @autoclosure () -> String) {
    #if DEBUG
    print("[SEC] \(message())")
    #endif
}
