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

**Add via the repository URL:**

1. In Xcode: **File → Add Package Dependencies…**
2. Enter this repository's URL: `https://github.com/DipakPanchasara/SafetyNet.git`
3. Choose a version rule (e.g. "Up to Next Major") and click **Add Package**.
4. Select your app target under **Add to Target**, then click **Add Package**.

**Add as a local checkout:**

1. Clone the repo locally:
   ```bash
   git clone https://github.com/DipakPanchasara/SafetyNet.git
   ```
2. In Xcode: **File → Add Package Dependencies…**
3. Click **Add Local…** in the bottom-left of the dialog.
4. Navigate to and select the cloned `SafetyNet` folder (the one containing
   `Package.swift`), then click **Add Package**.
5. Select your app target under **Add to Target**, then click **Add Package**.

### CocoaPods

```ruby
pod 'SafetyNet'
```

Requires `use_frameworks!` in your `Podfile` (Swift pod). The Objective-C
bridge (`SafetyNetObjC`) is pulled in automatically as a dependency.

## Integration guide

### Step 1 — Add the package

Use SPM or CocoaPods as shown in [Installation](#installation) above.

> If your app is Cordova-based, add the package to the native iOS platform
> project at `platforms/ios/<AppName>.xcodeproj`, not the Cordova JS layer.

### Step 2 — Import SafetyNet where needed

```swift
import SafetyNet
```

### Step 3 — Run a one-time check at app launch

Call this from `application(_:didFinishLaunchingWithOptions:)` in your
`AppDelegate`, or from your `SceneDelegate`/App struct's `init`/`onAppear`:

```swift
Task {
    let event = await SafetyNet.shared.check()
    switch event.level {
    case .none:
        break // clean device — proceed normally
    case .medium:
        // log only — do not change UI (avoids tipping off an attacker)
        break
    case .high:
        // your app decides: e.g. disable sensitive features
        disableSensitiveFeatures()
    case .critical:
        // your app decides: e.g. force logout, wipe local session
        forceLogoutAndClearSession()
    }
}
```

**Your app owns the response.** SafetyNet will never disable features or kill
the process on its own — see [Architecture](#architecture) for why this
matters.

### Step 4 — (Optional) Start continuous background monitoring

```swift
SafetyNet.shared.startMonitoring { event in
    // Called on a background queue whenever level >= .medium.
    // Hop to main thread before touching UI.
    DispatchQueue.main.async {
        handleThreatEvent(event)
    }
}
```

Call `SafetyNet.shared.stopMonitoring()` when appropriate (e.g. app
termination, user logout) to cancel the background timer.

### Step 5 — (Optional) Use the Secure Keychain API

```swift
// Store
try SafetyNet.shared.store(secret: sessionToken, forKey: "auth_token")

// Retrieve
let token = try SafetyNet.shared.retrieve(forKey: "auth_token")

// Delete
SafetyNet.shared.delete(forKey: "auth_token")

// Wipe everything SafetyNet has stored (does not touch other Keychain items)
SafetyNet.shared.wipeKeychain()
```

### Step 6 — Verify Debug builds are unaffected

Build and run your app in **Debug** configuration with Xcode attached.
Confirm:
- The app launches normally with the debugger attached (no crash, no
  `PT_DENY_ATTACH` block).
- `SafetyNet.shared.check()` returns `.none` immediately.
- Breakpoints in your own app code still work.

This is expected — every detector short-circuits to a safe value under
`#if DEBUG` (see [Architecture](#architecture) below).

### Step 7 — Verify Release builds detect real threats

Archive a **Release** build and install it via TestFlight or ad-hoc, then
test on:
- A clean, non-jailbroken device → `check()` should return `.none`.
- (If available) a jailbroken test device → `check()` should return
  `.medium`, `.high`, or `.critical` depending on how many signals fire.

### Requirements this integration relies on

| ID | Requirement |
|---|---|
| FR-1 | Call `SafetyNet.shared.check()` or `startMonitoring` before allowing access to sensitive features (login, payments, transfers). |
| FR-2 | Implement your own response to `ThreatLevel.high` / `.critical` — SafetyNet does not act automatically. |
| FR-3 | Don't call SafetyNet APIs from a `@MainActor`-isolated context expecting synchronous results — `check()` is `async`. |
| FR-4 | Keychain keys used via `store(secret:forKey:)` are scoped to SafetyNet's internal service identifier and cannot collide with your app's own Keychain usage. |
| FR-5 | Pair `startMonitoring` with `stopMonitoring` to avoid an orphaned background timer outliving its use case (e.g. after logout). |

### Known environment constraint — Keychain in test targets

Any consuming app's **unit test target** that calls SafetyNet's Keychain APIs
must have a valid Development Team assigned under **Signing & Capabilities**.
Without one, `SecItemAdd`/`SecItemCopyMatching` fail with
`errSecMissingEntitlement (-34018)` because iOS scopes all Keychain items to
an access group derived from the code-signing Team ID. This is **not** an
issue in a normal signed app target (Debug or Release), only in bare test
bundles without signing configured.

### Rollout checklist

- [ ] Package added via SPM or CocoaPods
- [ ] `SafetyNet.shared.check()` called at launch, response wired to app-specific logic
- [ ] (If used) `startMonitoring`/`stopMonitoring` paired correctly around session lifecycle
- [ ] (If used) Keychain APIs adopted for sensitive local storage
- [ ] Debug build verified: Xcode attaches normally, breakpoints work, `check()` returns `.none`
- [ ] Release build verified: clean device returns `.none`; (if available) jailbroken device returns non-`.none`
- [ ] Development Team assigned to any test target exercising Keychain APIs

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
— this is expected in a bare CLI environment (see [Known environment
constraint — Keychain in test targets](#known-environment-constraint--keychain-in-test-targets)
above).

## Architecture

SafetyNet is a from-scratch Swift port of a legacy Cordova plugin
(`cordova-plugin-security`), and the single most important behavioral
difference from that legacy plugin drives most of the design:

**SafetyNet never auto-reacts.** It only computes and returns a `ThreatEvent`
(`level` + `reasons`); it never disables UI, force-logs-out, posts
`NotificationCenter` notifications, or kills the process on its own. The
legacy Cordova plugin did auto-react, and that caused a production incident
— a consuming app's login screen silently hung because a HIGH-threat
notification triggered its own UI to disable itself in a way that was very
difficult to diagnose. When porting further legacy behavior or adding new
checks, preserve this "report only" contract; do not reintroduce automatic
side effects.

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
