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

- **Jailbreak detection** — filesystem checks (90+ known paths), injected
  dylib scanning, Frida port probing, sandbox-write testing, jailbreak URL
  scheme detection, suspicious process scanning, Shadow tweak detection,
  non-standard symbolic link detection, and additional open-port scanning
  (SSH/checkra1n).
- **Anti-debugging** — `ptrace(PT_DENY_ATTACH)` issued via a raw syscall at
  process launch (no hookable libc symbol), runtime debugger/trace
  detection, watchpoint detection, and an experimental `P_SELECT` flag
  check.
- **Integrity validation** — live code-signature validation via `csops()`,
  plus opt-in `__TEXT` segment memory-patch and file-integrity (bundle ID /
  provisioning profile / Mach-O section SHA256) diagnostics.
- **Network signals** — system proxy and VPN-as-proxy detection.
- **Hook detection** — opt-in diagnostics for MSHook (Cydia
  Substrate/Substitute) trampolines, ARM64 breakpoints, and runtime method
  swizzling — detection only, SafetyNet never patches your app's memory.
- **Environment info** — simulator and iOS Lockdown Mode detection
  (informational, not scored).
- **Secure Keychain** — a small, scoped wrapper around Keychain storage for
  sensitive local values, isolated from the host app's own Keychain usage.
- **Selective checks** — run every signal, or just the ones you choose, via
  `SafetyNetChecks`. See [Selecting which checks run](#selecting-which-checks-run).
- **Debug-safe by design** — every scored check short-circuits to a safe
  value in Debug builds, so debugging your own app is never blocked or
  slowed down.

Several of these signals (symbolic links, open ports, watchpoint, P_SELECT,
proxy/VPN, MSHook/runtime-hook detection, file integrity) are ports of the
equivalent checks in a well-known open-source iOS security-detection
technique, adapted to fit SafetyNet's scoring model and read-only-only
design — see [Detection technique provenance](#detection-technique-provenance)
for exactly what was and wasn't carried over, and why.

## Requirements

| Requirement | Minimum |
|---|---|
| iOS deployment target | 14.0+ |
| Xcode | 14.0+ (Swift 5.9 tools) |
| Dependencies | None — system frameworks only (`Security`, `MachO`, `Darwin`, `UIKit`, `CFNetwork`, `CryptoKit`) |

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
    let event = await SafetyNet.shared.check() // defaults to SafetyNetChecks.all
    if let level = event.level {
        switch level {
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
    } else {
        // Only reached if you passed a non-default `checks:` selection to
        // check() — see "Selecting which checks run" below. No aggregate
        // severity is computed for partial runs; inspect event.reasons
        // yourself and decide what "positive" means for your use case.
        if !event.reasons.isEmpty {
            handlePartialCheckReasons(event.reasons)
        }
    }
}
```

**Your app owns the response.** SafetyNet will never disable features or kill
the process on its own — see [Architecture](#architecture) for why this
matters.

### Step 4 — (Optional) Start continuous background monitoring

`startMonitoring` takes a plain closure callback — not a `NotificationCenter`
notification — that you register once. With the default `checks: .all`,
`onThreat` fires on every re-check where the aggregate `level` is `.medium`
or above. If you pass a partial `checks:` selection instead (see "Selecting
which checks run" below), `level` is always `nil`, so `onThreat` fires
whenever any selected signal fired positive (`reasons` is non-empty):

```swift
// e.g. call this after login, once the user has an active session
SafetyNet.shared.startMonitoring { event in
    // Called on a background queue on a randomised interval (30-120s).
    // Hop to main thread before touching UI.
    DispatchQueue.main.async {
        if let level = event.level {
            switch level {
            case .none:
                break // won't actually be called for .none
            case .medium:
                break // log only — do not change UI
            case .high:
                disableSensitiveFeatures()
            case .critical:
                forceLogoutAndClearSession()
            }
        } else {
            // Only reached with a partial `checks:` selection.
            handlePartialCheckReasons(event.reasons)
        }
    }
}

// e.g. call this on logout, or when the session ends
SafetyNet.shared.stopMonitoring()
```

`stopMonitoring()` cancels the background timer — always pair it with
`startMonitoring` so it doesn't outlive its use case (e.g. after logout).

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
| FR-6 | If you pass a non-default `checks:` to `check()`/`startMonitoring()`, handle `event.level == nil` explicitly — do not force-unwrap `event.level`. |

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

**SafetyNet never auto-reacts.** It only computes and returns a `ThreatEvent`
(`level` + `reasons`, where `level` is `nil` for partial check selections —
see "Selecting which checks run" below) — it never disables UI, force-logs-out,
posts `NotificationCenter` notifications, or kills the process on its own.
This is a deliberate constraint: an earlier design that auto-reacted on
HIGH/CRITICAL threat caused a production incident where a consuming app's
login screen silently hung, because the auto-posted notification triggered
the host app to disable its own UI in a way that was very difficult to
diagnose. When adding new checks, preserve this "report only" contract; do
not reintroduce automatic side effects.

### Call chain

```
SafetyNet (public singleton API, Sources/SafetyNet/SafetyNet.swift)
  -> SecurityOrchestrator (actor, Internal/SecurityOrchestrator.swift)
       -> JailbreakDetector.detect()       (9 independent signals, scored)
       -> DebuggerDetector.isDebuggerAttached() / isBeingTraced() /
          hasWatchpoint() / hasPSelectFlag()
       -> IntegrityValidator.validateCodeSignature()
       -> ProxyDetector.checkSystemProxy() / checkVPNAsProxy()
  -> SecureKeychain (independent — not part of the scoring pipeline)
  -> HookDetector / FileIntegrityChecker (opt-in diagnostics, not scored)
```

### Selecting which checks run

`check()`/`startMonitoring()` accept a `checks: SafetyNetChecks = .all`
parameter — an `OptionSet` covering every individually-scored signal, with
`.jailbreak`/`.debugger`/`.integrity`/`.network` convenience group unions
and `.all` (the default) covering everything.

- **`.all` (default)** — reproduces the original behavior exactly: every
  signal runs, and `ThreatEvent.level` is populated via the scored
  thresholds described above.
- **Any partial selection** (e.g. `.debugger`, `[.fridaPort, .shadowTweak]`,
  or a single signal) — `ThreatEvent.level` is always `nil`. The medium/high/
  critical thresholds were calibrated assuming all signals could
  contribute, deliberately so no single signal can reach `.critical` alone;
  a caller-chosen subset could otherwise reach `.critical` off far fewer
  independent signals than intended. Rather than silently weaken that
  guarantee, SafetyNet declines to compute a severity for partial runs —
  `event.reasons` still reports exactly which of the *selected* checks fired
  positive, and your app decides what that combination means.

```swift
// Full assessment (default) — level is populated
let full = await SafetyNet.shared.check()

// Partial — level is always nil; inspect reasons yourself
let partial = await SafetyNet.shared.check(checks: [.fridaPort, .debuggerAttached])
```

Note: `JailbreakDetector.detect()` is monolithic — it always runs all of its
internal jailbreak checks in one pass. Selecting even a single jailbreak
sub-signal (e.g. just `.fridaPort`) still costs the same as running all of
them; only the *reported* subset in `reasons` is filtered down to what you
asked for.

`SecurityOrchestrator` is an `actor` and is the only place scoring happens.
`runChecks()` sums per-signal scores into a `ThreatLevel` via thresholds
(medium 30-59, high 60-99, critical 100+) — thresholds are deliberately set
so no single check alone can reach `.critical`; multiple independent signals
must agree. When adding a new detector signal, add its score into this
function and pick a weight consistent with the existing signals in
`SecurityOrchestrator.swift`. Current weights:

| Signal | `SafetyNetChecks` member | Weight |
|---|---|---|
| Filesystem (jailbreak paths) | `.jailbreakFilesystem` | 30 |
| Injected dylib | `.jailbreakDylib` | 50 |
| Frida port open | `.fridaPort` | 60 |
| Sandbox-write breach | `.sandboxBreach` | 40 |
| URL scheme | `.urlScheme` | 35 |
| Suspicious process | `.suspiciousProcess` | 45 |
| Shadow tweak class | `.shadowTweak` | 60 |
| Non-standard symbolic links | `.suspiciousSymlinks` | 35 |
| Suspicious open port (SSH/checkra1n) | `.suspiciousOpenPort` | 40 |
| Debugger attached | `.debuggerAttached` | 50 |
| Process traced (bad parent) | `.processTraced` | 40 |
| Watchpoint detected | `.watchpointDetected` | 40 |
| `P_SELECT` flag set (experimental upstream) | `.pSelectFlagSet` | 25 |
| Invalid code signature | `.codeSignatureInvalid` | 60 |
| System proxy configured | `.systemProxy` | 15 |
| VPN interface detected | `.vpnAsProxy` | 15 |

### Opt-in diagnostics (not scored)

A few checks need a caller-supplied target (a function address, or a
class/selector pair) and can't be run blindly as part of `.all`, so they're
plain methods you call directly instead of `SafetyNetChecks` members:

```swift
// Breakpoint at a specific function (ARM64 only)
let breakpointed = SafetyNet.shared.hasBreakpoint(at: someFunctionAddr, functionSize: nil)

// MSHookFunction (Cydia Substrate/Substitute) trampoline detection (ARM64 only)
let msHooked = SafetyNet.shared.isMSHooked(at: someFunctionAddr)

// Runtime method-swizzling detection
let hooked = SafetyNet.shared.isRuntimeHooked(
    dyldAllowList: ["MyTrustedFramework"],
    detectionClass: SomeClass.self,
    selector: #selector(SomeClass.someMethod),
    isClassMethod: false
)

// File/bundle/provisioning-profile integrity — you supply the expected values
let result = SafetyNet.shared.checkFileIntegrity([
    .bundleID("com.yourcompany.yourapp"),
    .mobileProvision("<expected sha256 hex digest>"),
    .machO("YourAppBinary", "<expected sha256 hex digest>"),
])
if result.result {
    // result.hitChecks tells you exactly which checks flagged
}

// Environment info (informational, not a threat signal)
SafetyNet.shared.isSimulator
SafetyNet.shared.isInLockdownMode
```

`hasBreakpoint`/`isMSHooked`/`isRuntimeHooked` detect only — none of them
patch or modify your app's memory, matching SafetyNet's read-only design
(see [Detection technique provenance](#detection-technique-provenance)).

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

### Signals intentionally excluded from scoring

Two checks are deliberately excluded from the scored pipeline because they
caused false positives in production on clean devices, and are documented in
code comments rather than silently omitted:

- **Frida memory-scan** (`_check_frida_memory`) — collided with legitimate
  SDK byte sequences (e.g. AirshipKit). Frida is still covered by the
  port-scan and dylib-scan checks in `JailbreakDetector`.
- **`detectMethodSwizzling`** — collided with legitimate `NSURLSession`
  hooking by AirshipKit/Firebase. Kept as a standalone opt-in diagnostic in
  `IntegrityValidator`, not wired into the scored `SecurityOrchestrator` path.

Do not re-add either to the scored pipeline without addressing the original
false-positive cause.

### Detection technique provenance

Most of the signals added after the initial jailbreak/debugger/integrity set
are ports of the equivalent checks in a well-known open-source iOS
jailbreak/anti-tampering detection technique, adapted to fit SafetyNet's
scoring model. Two things were deliberately **not** ported, both for the
same reason: they don't just detect, they patch — a fundamentally different
risk class from every other check in this codebase (all read-only), and one
this project's NFR-4 (never crash regardless of device state; no unbounded
memory writes) rules out:

- **`denyFishHook`/`denyMSHook`** (upstream) — hand-parse Mach-O load
  commands and rewrite live executable memory via `vm_protect` to "un-hook" a
  symbol or function. SafetyNet ports the *detection* halves
  (`isMSHooked`/`isRuntimeHooked`) but never the patching. One consequence:
  upstream's runtime-hook detector defensively hooks-proofs `dladdr` itself
  before using it; SafetyNet's port skips that pre-step (it's the same kind
  of live patching), so it's marginally weaker against an attacker who has
  specifically hooked `dladdr` — see the doc comment on
  `HookDetector.isRuntimeHooked`.
- **The literal `fork()`-based sandbox check** (upstream's `JailbreakChecker`)
  — calls `fork()` inside the running app to see if it succeeds. Apple
  discourages calling `fork()` from a live Swift/ObjC app since the
  Objective-C runtime and GCD aren't fork-safe; it can deadlock or crash on
  some devices. SafetyNet's existing file-write-based `checkSandbox()`
  already covers the same detection goal without that risk.

Separately, while porting the URL-scheme check, upstream's own commit
history revealed a real fixed bug worth carrying over: `cydia://` and
`activator://` were removed from upstream's scheme list after a published
App Store app was found to register `cydia://`, causing false positives in
production. SafetyNet's list now matches upstream's current (safer) set.

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
