#ifndef SafetyNetObjC_h
#define SafetyNetObjC_h

#include <sys/types.h>

// Documented no-op integration point — the actual PT_DENY_ATTACH syscall
// runs from a __attribute__((constructor)) in AntiDebugBridge.m, which fires
// before main() and before this function could ever be called. Swift calls
// this at launch anyway so the anti-debug install site is explicit in the
// public API surface, matching the pattern used by the Cordova plugin.
void safetynet_install_anti_debug(void);

// csops() — iOS kernel syscall that returns live code-signing flags.
// Not exposed by Swift's Darwin module, so it is re-declared here and
// called from Swift via the SafetyNetObjC C interop bridge.
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

#endif /* SafetyNetObjC_h */
