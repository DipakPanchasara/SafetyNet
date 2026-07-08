# SafetyNet — Integration Requirements Document

## 1. Purpose

This document defines the requirements and step-by-step procedure to integrate the
**SafetyNet** Swift Package into an existing iOS application (native Swift/ObjC,
Cordova, React Native, or any other framework that ships a native iOS target).

SafetyNet provides jailbreak detection, anti-debugging, code-signature/integrity
validation, and secure Keychain storage as a reusable library with zero dependency
on Cordova. Unlike the legacy `cordova-plugin-security`, SafetyNet **never**
auto-terminates the app or auto-posts notifications — it only reports a
`ThreatEvent` and lets the host app decide what to do.

---

## 2. Prerequisites

| Requirement | Minimum |
|---|---|
| iOS deployment target | 14.0+ |
| Xcode | 14.0+ (Swift 5.9 tools) |
| Swift Package Manager | built-in to Xcode — no CocoaPods/Carthage needed |
| Host app signing | Valid Development Team assigned (required for Keychain features to work — see §6) |

Frameworks used internally (all system frameworks, no third-party deps):
`Security.framework`, `MachO`, `Darwin`, `UIKit`.

---

## 3. Step-by-Step Integration

### Step 1 — Add the package to your Xcode project

1. Open your app's `.xcodeproj` / `.xcworkspace` in Xcode.
2. Go to **File → Add Package Dependencies…**
3. Click **Add Local…** and select the folder:
   `/Users/dipakpanchasara/Project/Ruthwik/Bank App/jailbrack/SafetyNet`
4. Select your app target under **Add to Target**, then click **Add Package**.

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

**Requirement: your app owns the response.** SafetyNet will never disable
features or kill the process on its own — see §7 for why this matters.

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

Call `SafetyNet.shared.stopMonitoring()` when appropriate (e.g. app termination,
user logout) to cancel the background timer.

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
  PT_DENY_ATTACH block).
- `SafetyNet.shared.check()` returns `.none` immediately.
- Breakpoints in your own app code still work.

This is expected — every detector short-circuits to a safe value under
`#if DEBUG`, matching the pattern documented in the main project's
[CLAUDE.md](../CLAUDE.md).

### Step 7 — Verify Release builds detect real threats

Archive a **Release** build and install it via TestFlight or ad-hoc, then test on:
- A clean, non-jailbroken device → `check()` should return `.none`.
- (If available) a jailbroken test device → `check()` should return `.medium`,
  `.high`, or `.critical` depending on how many signals fire.

---

## 4. Functional Requirements

| ID | Requirement |
|---|---|
| FR-1 | The host app must call `SafetyNet.shared.check()` or `startMonitoring` before allowing access to sensitive features (login, payments, transfers). |
| FR-2 | The host app must implement its own response to `ThreatLevel.high` / `.critical` — SafetyNet does not act automatically. |
| FR-3 | The host app must not call any SafetyNet API from a `@MainActor`-isolated context expecting synchronous results — `check()` is `async`. |
| FR-4 | Keychain keys used via `store(secret:forKey:)` are scoped to SafetyNet's internal service identifier and cannot collide with the host app's own Keychain usage. |
| FR-5 | `startMonitoring` must be paired with `stopMonitoring` to avoid an orphaned background timer outliving its use case (e.g. after logout). |

---

## 5. Non-Functional Requirements

| ID | Requirement |
|---|---|
| NFR-1 | Zero behavior change in Debug builds — no security check may block a developer's debugging session. |
| NFR-2 | No console/log output revealing detected threat reasons in Release builds (`secLog` is a no-op outside `#if DEBUG`). |
| NFR-3 | No network calls, no third-party analytics, no telemetry of any kind. |
| NFR-4 | All detectors must complete without crashing regardless of device state (jailbroken, rooted, memory-patched, etc.) — no direct memory dereference without bounds checking. |

---

## 6. Known Environment Constraint — Keychain in Test Targets

Any consuming app's **unit test target** that calls SafetyNet's Keychain APIs
must have a valid Development Team assigned under
**Signing & Capabilities**. Without one, `SecItemAdd`/`SecItemCopyMatching`
fail with `errSecMissingEntitlement (-34018)` because iOS scopes all Keychain
items to an access group derived from the code-signing Team ID — this applies
even to SafetyNet's own `SafetyNetTests` target during development.

This is **not** an issue in a normal signed app target (Debug or Release),
only in bare test bundles without signing configured.

---

## 7. Design Rationale — Why SafetyNet Never Auto-Reacts

The legacy `cordova-plugin-security` (see
[`SecurityPlugin/`](../SecurityPlugin)) auto-posted a
`SecurityThreatHighNotification` on HIGH threat and auto-terminated the
process on CRITICAL threat. In production, this caused the SVB Go banking
app's login screen to silently hang — the notification triggered the host
app to disable its own login UI in a way that was very difficult to diagnose,
and required extensive debugging across the whole `DebuggerDetector.m` /
`SecurityOrchestrator.m` call chain to root-cause.

SafetyNet's `check()` and `startMonitoring(onThreat:)` **only report** the
assessed `ThreatEvent`. The host app is always responsible for the actual
response (disabling UI, logging out, wiping session data). This removes an
entire class of "why did my login break" bugs from any app that adopts this
library.

---

## 8. Rollout Checklist

- [ ] Package added via Xcode → Add Package Dependencies → local path
- [ ] `SafetyNet.shared.check()` called at launch, response wired to app-specific logic
- [ ] (If used) `startMonitoring`/`stopMonitoring` paired correctly around session lifecycle
- [ ] (If used) Keychain APIs adopted for sensitive local storage
- [ ] Debug build verified: Xcode attaches normally, breakpoints work, `check()` returns `.none`
- [ ] Release build verified: clean device returns `.none`; (if available) jailbroken device returns non-`.none`
- [ ] Development Team assigned to any test target exercising Keychain APIs
