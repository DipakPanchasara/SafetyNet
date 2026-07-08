import Darwin
import Foundation
import MachO
import SafetyNetObjC

// Ported from cordova-plugin-security IntegrityValidator.m.
//
// Note: detectMethodSwizzling is intentionally not ported into the scored
// path. In the Cordova plugin it caused false positives because AirshipKit /
// Firebase legitimately hook NSURLSession, and it was removed from scoring
// there too. It is kept here as a standalone diagnostic method callers may
// use at their own risk, matching the pattern in SecurityPlugin.m.
enum IntegrityValidator {

    private static let CS_OPS_STATUS: UInt32 = 0
    private static let CS_VALID: UInt32 = 0x0000_0001
    private static let CS_ADHOC: UInt32 = 0x0000_0002

    static func validateCodeSignature() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        var flags: UInt32 = 0
        let rc = csops(getpid(), Self.CS_OPS_STATUS, &flags, MemoryLayout<UInt32>.size)
        guard rc == 0 else {
            secLog("Code signature check failed — csops returned error")
            return false
        }

        guard (flags & Self.CS_VALID) != 0 else {
            secLog("Code signature invalid — CS_VALID not set")
            return false
        }

        #if !DEBUG
        if (flags & Self.CS_ADHOC) != 0 {
            secLog("Code signature invalid — ad-hoc signed in Release build")
            return false
        }
        #endif

        return true
        #endif
    }

    /// Checks the host app's own __TEXT segment protection flags.
    /// A patched binary typically has write permission added to __TEXT,
    /// which should always be read+execute only.
    static func detectMemoryPatch(executableName: String) -> Bool {
        let count = _dyld_image_count()
        var header: UnsafePointer<mach_header>?

        for i in 0..<count {
            guard let namePtr = _dyld_get_image_name(i) else { continue }
            let name = String(cString: namePtr)
            if name.contains(executableName) {
                header = _dyld_get_image_header(i)
                break
            }
        }
        guard let header else { return false }

        return header.withMemoryRebound(to: mach_header_64.self, capacity: 1) { header64 -> Bool in
            guard header64.pointee.magic == MH_MAGIC_64 else { return false }

            var cursor = UnsafeRawPointer(header64) + MemoryLayout<mach_header_64>.size
            for _ in 0..<header64.pointee.ncmds {
                let lc = cursor.assumingMemoryBound(to: load_command.self)
                if lc.pointee.cmd == UInt32(LC_SEGMENT_64) {
                    let seg = cursor.assumingMemoryBound(to: segment_command_64.self)
                    let segName = withUnsafeBytes(of: seg.pointee.segname) { rawBuffer -> String in
                        let ptr = rawBuffer.baseAddress!.assumingMemoryBound(to: CChar.self)
                        return String(cString: ptr)
                    }
                    if segName == "__TEXT" {
                        let expected = VM_PROT_READ | VM_PROT_EXECUTE
                        if seg.pointee.initprot != expected {
                            return true
                        }
                    }
                }
                cursor += Int(lc.pointee.cmdsize)
            }
            return false
        }
    }
}
