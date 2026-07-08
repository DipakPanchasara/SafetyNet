# SafetyNet

A lightweight iOS Swift Package for jailbreak detection, anti-debugging,
code-signature integrity validation, and secure Keychain storage — with zero
third-party dependencies and zero automatic side effects.

Unlike many mobile security libraries, SafetyNet **never** auto-terminates
your app, disables features, or posts notifications on its own. It only
reports a `ThreatEvent` and lets your app decide what to do. This avoids an
entire class of "why did my UI silently break" bugs caused by libraries
reacting behind your back.

## Features

- **Jailbreak detection** — filesystem checks, injected dylib scanning, Frida
  port probing, sandbox-write testing, jailbreak URL scheme detection,
  suspicious process scanning, and Shadow tweak detection.
- **Anti-debugging** — `ptrace(PT_DENY_ATTACH)` issued via a raw syscall at
  process launch (no hookable libc symbol), plus runtime debugger/trace
  detection.
- **Integrity validation** — live code-signature validation via `csops()`,
  plus an opt-in `__TEXT` segment memory-patch diagnostic.
- **Secure Keychain** — a small, scoped wrapper around Keychain storage for
  sensitive local values, isolated from the host app's own Keychain usage.
- **Debug-safe by design** — every check short-circuits to a safe value in
  Debug builds, so debugging your own app is never blocked or slowed down.

## Requirements

| Requirement | Minimum |
|---|---|
| iOS deployment target | 14.0+ |
| Xcode | 14.0+ (Swift 5.9 tools) |
| Dependencies | None — system frameworks only (`Security`, `MachO`, `Darwin`, `UIKit`) |

## Installation

### Swift Package Manager

1. In Xcode: **File → Add Package Dependencies…**
2. Enter this repository's URL (or **Add Local…** for a local checkout).
3. Select your app target and click **Add Package**.

### CocoaPods

```ruby
pod 'SafetyNet'
```

Requires `use_frameworks!` in your `Podfile` (Swift pod). The Objective-C
bridge (`SafetyNetObjC`) is pulled in automatically as a dependency.

## Usage

```swift
import SafetyNet

// One-time check, e.g. in application(_:didFinishLaunchingWithOptions:)
Task {
    let event = await SafetyNet.shared.check()
    switch event.level {
    case .none:
        break // clean device — proceed normally
    case .medium:
        break // log only — do not change UI
    case .high:
        disableSensitiveFeatures()
    case .critical:
        forceLogoutAndClearSession()
    }
}

// Optional: continuous background monitoring
SafetyNet.shared.startMonitoring { event in
    DispatchQueue.main.async { handleThreatEvent(event) }
}
SafetyNet.shared.stopMonitoring() // e.g. on logout

// Optional: secure Keychain storage
try SafetyNet.shared.store(secret: sessionToken, forKey: "auth_token")
let token = try SafetyNet.shared.retrieve(forKey: "auth_token")
SafetyNet.shared.delete(forKey: "auth_token")
SafetyNet.shared.wipeKeychain()
```

**Your app owns the response.** SafetyNet will never disable features or kill
the process on its own.

For the full step-by-step integration guide, functional/non-functional
requirements, and design rationale, see [doc/INTEGRATION.md](doc/INTEGRATION.md).

## Development

```bash
swift build
swift test

# Run a single test class or method
swift test --filter SafetyNetTests
swift test --filter JailbreakDetectorTests
swift test --filter SafetyNetTests/testCheckReturnsNoneLevelInDebugOrSimulator
```

`swift test` runs as an unsigned bare test bundle. Keychain-backed tests
(`SecureKeychainTests`) will fail with `errSecMissingEntitlement (-34018)`
unless the test target/toolchain has a Development Team / signing configured
— this is expected in a bare CLI environment (see §6 of
[doc/INTEGRATION.md](doc/INTEGRATION.md)).

## Architecture

SafetyNet is a from-scratch Swift port of a legacy Cordova plugin
(`cordova-plugin-security`), and the single most important behavioral
difference from that legacy plugin drives most of the design:

**SafetyNet never auto-reacts.** It only computes and returns a `ThreatEvent`
(`level` + `reasons`); it never disables UI, force-logs-out, posts
`NotificationCenter` notifications, or kills the process on its own. The
legacy Cordova plugin did auto-react, and that caused a production incident
(silently hung login screen) that was hard to root-cause — see
[doc/INTEGRATION.md](doc/INTEGRATION.md) §7 for the full story. When porting
further legacy behavior or adding new checks, preserve this "report only"
contract; do not reintroduce automatic side effects.

### Call chain

```
SafetyNet (public singleton API, Sources/SafetyNet/SafetyNet.swift)
  -> SecurityOrchestrator (actor, Internal/SecurityOrchestrator.swift)
       -> JailbreakDetector.detect()       (7 independent signals, scored)
       -> DebuggerDetector.isDebuggerAttached() / isBeingTraced()
       -> IntegrityValidator.validateCodeSignature()
  -> SecureKeychain (independent — not part of the scoring pipeline)
```

`SecurityOrchestrator` is an `actor` and is the only place scoring happens.
`runChecks()` sums per-signal scores into a `ThreatLevel` via thresholds
(medium 30-59, high 60-99, critical 100+) — thresholds are deliberately set
so no single check alone can reach `.critical`; multiple independent signals
must agree. When adding a new detector signal, add its score into this
function and pick a weight consistent with the existing signals in
`SecurityOrchestrator.swift`.

### The `#if DEBUG` short-circuit pattern

Every detector and the orchestrator itself no-ops to a "safe"/`.none` result
under `#if DEBUG` (and separately under `#if targetEnvironment(simulator)`
where relevant). This is intentional and required — Debug builds routinely
have a debugger attached and ad-hoc/dev code signing, which would otherwise
produce constant false-positive HIGH/CRITICAL scores and block normal
development. When adding a new check, follow the same pattern: short-circuit
to the non-threatening value under `#if DEBUG` rather than trying to make the
check "smart" about distinguishing dev from real attackers.

The one exception living outside plain `#if DEBUG` in Swift is the
anti-ptrace constructor in `Sources/SafetyNetObjC/AntiDebugBridge.m`: the
raw ARM64 `svc #0x80` syscall is wrapped in `#if !DEBUG` at the C level so
the *function itself* doesn't exist in Debug builds, not just a no-op body —
see the comment there for why a no-op body isn't safe enough.

### Signals intentionally not ported from the legacy Cordova plugin

Two legacy checks were dropped during the port because they caused false
positives in production on clean devices, and are documented in code
comments rather than silently omitted:

- **Frida memory-scan** (`_check_frida_memory`) — collided with legitimate
  SDK byte sequences (e.g. AirshipKit). Frida is still covered by the
  port-scan and dylib-scan checks in `JailbreakDetector`.
- **`detectMethodSwizzling`** — collided with legitimate `NSURLSession`
  hooking by AirshipKit/Firebase. Kept as a standalone opt-in diagnostic in
  `IntegrityValidator`, not wired into the scored `SecurityOrchestrator` path.

Do not re-add either to the scored pipeline without addressing the original
false-positive cause.

### Logging

`secLog()` (`Internal/SecurityLogging.swift`) compiles to nothing outside
`#if DEBUG`. This is deliberate: on a jailbroken device any process can read
another process's logs, so logging which specific check fired hands an
attacker a bypass roadmap. Never add a logging call (or any other
Release-visible output) that reveals which detector tripped or the computed
score.

### SecureKeychain

Independent of the threat-scoring pipeline. Uses `kSecAttrAccessible`
(`.whenUnlockedThisDeviceOnly`) rather than `SecAccessControlCreateWithFlags`
— the latter implicitly requires a Keychain Sharing entitlement even without
biometric flags, which breaks in a bare SPM test bundle. All items are
scoped under a single fixed `kSecAttrService` value so `wipeAll()` can safely
delete only SafetyNet's own items without touching the host app's other
Keychain entries.

### Module split

- `SafetyNet` (Swift) — public API, detectors, orchestration.
- `SafetyNetObjC` (Objective-C, `Sources/SafetyNetObjC/`) — a small bridge
  target used only for things Swift/Darwin can't do directly: the raw
  syscall anti-debug constructor, and re-declaring `csops()` (not exposed by
  Swift's `Darwin` module) for `IntegrityValidator`'s code-signature check.

## License

MIT — see [LICENSE](LICENSE).
