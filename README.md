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

Add SafetyNet via Swift Package Manager:

1. In Xcode: **File → Add Package Dependencies…**
2. Enter this repository's URL (or **Add Local…** for a local checkout).
3. Select your app target and click **Add Package**.

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
```

See [CLAUDE.md](CLAUDE.md) for architecture notes and further development
guidance.

## License

MIT — see [LICENSE](LICENSE).
