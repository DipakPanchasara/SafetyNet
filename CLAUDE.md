# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository layout

This repo root contains two things:
- `SafetyNet/` — the actual Swift Package (all source, tests, and `Package.swift` live here, not at the repo root).
- `doc/INTEGRATION.md` — integration requirements doc for host apps consuming this package.

All build/test commands below must be run from `SafetyNet/` (where `Package.swift` lives).

## Commands

```bash
cd SafetyNet

# Build
swift build

# Run all tests
swift test

# Run a single test class or method
swift test --filter SafetyNetTests
swift test --filter JailbreakDetectorTests
swift test --filter SafetyNetTests/testCheckReturnsNoneLevelInDebugOrSimulator
```

There is no separate lint config in this repo.

Note: `swift test` runs as an unsigned bare test bundle. Keychain-backed tests
(`SecureKeychainTests`) will fail with `errSecMissingEntitlement (-34018)`
unless the test target/toolchain has a Development Team / signing configured
— this is expected in a bare CLI environment (see §6 of `doc/INTEGRATION.md`).

## Architecture

SafetyNet is a Swift Package providing jailbreak detection, anti-debugging,
code-signature/integrity validation, and secure Keychain storage for iOS
apps. It is a from-scratch Swift port of a legacy Cordova plugin
(`cordova-plugin-security`), and the single most important behavioral
difference from that legacy plugin drives most of the design:

**SafetyNet never auto-reacts.** It only computes and returns a `ThreatEvent`
(`level` + `reasons`); it never disables UI, force-logs-out, posts
`NotificationCenter` notifications, or kills the process on its own. The
legacy Cordova plugin did auto-react, and that caused a production incident
(silently hung login screen) that was hard to root-cause — see
`doc/INTEGRATION.md` §7 for the full story. When porting further legacy
behavior or adding new checks, preserve this "report only" contract; do not
reintroduce automatic side effects.

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
must agree. If you add a new detector signal, add its score into this
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

### Signals intentionally NOT ported from the legacy Cordova plugin

Two legacy checks were dropped during the port because they caused false
positives in production on clean devices, and are documented in code
comments rather than silently omitted:
- Frida memory-scan (`_check_frida_memory`) — collided with legitimate SDK
  byte sequences (e.g. AirshipKit). Frida is still covered by the port-scan
  and dylib-scan checks in `JailbreakDetector`.
- `detectMethodSwizzling` — collided with legitimate `NSURLSession` hooking
  by AirshipKit/Firebase. Kept as a standalone opt-in diagnostic in
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
