import Foundation
import MachO

// Ported from a well-known open-source iOS security-detection technique.
// Detection only — the upstream technique's live memory-patching
// counterparts (an MSHook-denial routine and a fishhook-denial routine)
// are intentionally NOT ported: they hand-parse Mach-O load commands and
// rewrite executable memory via vm_protect, a fundamentally different risk
// class from every other detector in SafetyNet (all read-only). See
// README's Architecture section for the "SafetyNet never auto-reacts" /
// all-read-only rationale this preserves.
//
// Both checks below need a caller-supplied target (a function address or a
// class/selector pair), so — like IntegrityValidator.detectMemoryPatch —
// they are opt-in diagnostics, not wired into the scored
// SecurityOrchestrator pipeline.
enum HookDetector {

    // MARK: - MSHook detection
    //
    // Ported from the equivalent MSHook detection check in the same
    // upstream technique. Decodes the first ARM64 instruction(s) at the
    // given function address to detect the trampoline pattern
    // MSHookFunction (Cydia Substrate/Substitute) installs when hooking a
    // C function: either an `ldr x16, #8 / br x16 / <address>` sequence,
    // or an `adrp x17 / add x17 / br x17` sequence. Detection only — does
    // not patch anything.

    static func isMSHooked(at functionAddr: UnsafeMutableRawPointer) -> Bool {
        #if arch(arm64)
        guard let first = MSHookInstruction.translate(at: functionAddr) else {
            return false
        }
        switch first {
        case .ldrX16:
            if case .brX16 = MSHookInstruction.translate(at: functionAddr + 4) {
                return true
            }
            return false
        case .adrpX17:
            if case .addX17 = MSHookInstruction.translate(at: functionAddr + 4),
               case .brX17 = MSHookInstruction.translate(at: functionAddr + 8) {
                return true
            }
            return false
        default:
            return false
        }
        #else
        return false
        #endif
    }

    // MARK: - Runtime hook detection
    //
    // Ported from the equivalent runtime-hook detection check in the same
    // upstream technique. Resolves the given method's implementation
    // pointer and checks which image (dylib/framework) it lives in via
    // dladdr: system frameworks and your own app binary are trusted,
    // anything else (unless explicitly allow-listed) is treated as an
    // injected hook.
    //
    // Deviation from upstream: the upstream technique calls a
    // fishhook-denial routine once before using dladdr, to stop an
    // attacker who has hooked dladdr itself from defeating this very
    // detector. That pre-step is live memory patching and is intentionally
    // not ported here (see the file-level comment above) — this check is
    // therefore slightly weaker than upstream's against an attacker who
    // has specifically hooked dladdr, in exchange for keeping SafetyNet
    // entirely read-only.
    static func isRuntimeHooked(
        dyldAllowList: [String],
        detectionClass: AnyClass,
        selector: Selector,
        isClassMethod: Bool
    ) -> Bool {
        let method = isClassMethod
            ? class_getClassMethod(detectionClass, selector)
            : class_getInstanceMethod(detectionClass, selector)

        guard let method else {
            // Method not found — treat as hooked, matching upstream.
            return true
        }

        let imp = method_getImplementation(method)
        var info = Dl_info()

        guard dladdr(UnsafeRawPointer(imp), &info) == 1, let dliFname = info.dli_fname else {
            return false
        }

        let impDyldPath = String(cString: dliFname).lowercased()

        // At a system framework.
        if impDyldPath.contains("/system/library") {
            return false
        }

        // At the app's own binary.
        if let mainImageName = _dyld_get_image_name(0) {
            let binaryPath = String(cString: mainImageName).lowercased()
            if impDyldPath.contains(binaryPath) {
                return false
            }
        }

        // At an explicitly allow-listed framework.
        if let impFramework = impDyldPath.components(separatedBy: "/").last {
            return !dyldAllowList.map({ $0.lowercased() }).contains(impFramework)
        }

        // At an injected framework.
        return true
    }
}

#if arch(arm64)
// ARM64 instruction decoding for MSHook trampoline detection. Ported from
// the equivalent instruction-decoding logic in the same upstream technique.
private enum MSHookInstruction {
    case ldrX16
    case brX16
    case adrpX17(pageBase: UInt64)
    case addX17(pageOffset: UInt64)
    case brX17

    static func translate(at functionAddr: UnsafeMutableRawPointer) -> MSHookInstruction? {
        let arm = functionAddr.assumingMemoryBound(to: UInt32.self).pointee

        // ldr xt, #imm (literal)
        let ldrRegisterLiteral = (arm & (255 << 24)) >> 24
        if ldrRegisterLiteral == 0b0101_1000 {
            let rt = arm & 31
            let imm19 = (arm & (((1 << 19) - 1) << 5)) >> 5
            if rt == 16 && (imm19 << 2) == 8 {
                return .ldrX16
            }
        }

        // br
        let br = arm >> 10
        if br == 0b1101_0110_0001_1111_0000_00 {
            let brRn = (arm & (31 << 5)) >> 5
            if brRn == 16 { return .brX16 }
            if brRn == 17 { return .brX17 }
        }

        // adrp
        let adrpOp = arm >> 31
        let adrp = (arm & (31 << 24)) >> 24
        let rd = arm & (31 << 0)
        if adrpOp == 1 && adrp == 16 && rd == 17 {
            return .adrpX17(pageBase: adrpPageBase(functionAddr))
        }

        // add (64-bit immediate form)
        let add = arm >> 24
        if add == 0b1001_0001 {
            let addRn = (arm & (31 << 5)) >> 5
            let addRd = arm & 31
            let addImm12 = UInt32((arm & (((1 << 12) - 1) << 10)) >> 10)
            let shift = (arm & (3 << 22)) >> 22
            let imm: UInt64
            switch shift {
            case 0: imm = UInt64(addImm12)
            case 1: imm = UInt64(addImm12 << 12)
            default: return nil
            }
            if addRn == 17 && addRd == 17 {
                return .addX17(pageOffset: imm)
            }
        }

        return nil
    }

    private static func adrpPageBase(_ functionAddr: UnsafeMutableRawPointer) -> UInt64 {
        let arm = functionAddr.assumingMemoryBound(to: UInt32.self).pointee

        func signExtend(_ value: Int64) -> Int64 {
            let isNegative = value >> 32 == 1
            return isNegative ? (((1 << 31) - 1) << 33) | value : value
        }

        let immlo = (arm >> 29) & 3
        let immhiMask = UInt32(((1 << 19) - 1) << 5)
        let immhi = (arm & immhiMask) >> 5
        let imm = Int64((immhi << 2 | immlo)) << 12
        let pcBase = (UInt(bitPattern: functionAddr) >> 12) << 12
        return UInt64(Int64(pcBase) + signExtend(imm))
    }
}
#endif
