#import "SafetyNetObjC.h"

// Ported from cordova-plugin-security DebuggerDetector.m.
//
// Inline ARM64 assembly issues the ptrace syscall directly to the kernel via
// SVC #0x80. There is no symbol to patch, no function pointer to intercept,
// and no C library indirection — Frida cannot hook a raw syscall the way it
// can hook dlsym("ptrace"). This is why the call is not written as
// ptrace(PT_DENY_ATTACH, ...) in C — that goes through a hookable libc symbol.
//
// Syscall encoding (ARM64 XNU):
//   x16 = syscall number  -> 26 (SYS_ptrace)
//   x0  = request         -> 31 (PT_DENY_ATTACH)
//   x1  = pid             -> 0  (self)
//   x2  = addr            -> 0  (unused)
//   x3  = data            -> 0  (unused)
//   svc #0x80             -> XNU syscall gate
//
// Wrapped in #if !DEBUG so the function does not exist at all in Debug
// builds — not just the assembly inside. A constructor that merely no-ops
// its body still runs before main() and can still interfere with other
// SDKs' constructor chains during development; removing the function
// entirely is the only guard that is actually safe in Debug.
#if !DEBUG
__attribute__((visibility("hidden")))
__attribute__((constructor))
static void _safetynet_anti_debug_early(void) {
#if !TARGET_IPHONE_SIMULATOR
#if defined(__arm64__) || defined(__aarch64__)
    __asm__ __volatile__ (
        "mov x0, #31  \n"   // PT_DENY_ATTACH
        "mov x1, #0   \n"   // pid = 0 (self)
        "mov x2, #0   \n"   // addr = NULL
        "mov x3, #0   \n"   // data = 0
        "mov x16, #26 \n"   // SYS_ptrace
        "svc #0x80    \n"   // XNU syscall gate — no symbol, no hook surface
        :                   // no outputs
        :                   // no inputs
        : "x0", "x1", "x2", "x3", "x16", "memory", "cc"
    );
#endif // __arm64__
#endif // !TARGET_IPHONE_SIMULATOR
}
#endif // !DEBUG

void safetynet_install_anti_debug(void) {
    // The __attribute__((constructor)) already ran before main().
    // This function exists so Swift callers have a documented integration
    // point — the actual work is already done by the time this is called.
}
