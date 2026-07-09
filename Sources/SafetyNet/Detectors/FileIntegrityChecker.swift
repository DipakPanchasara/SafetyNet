import CryptoKit
import Foundation
import MachO

// Ported from the equivalent file-integrity check in a well-known
// open-source iOS security-detection technique. Unlike every other
// detector in SafetyNet, these checks need the host app to
// supply its own expected values (bundle ID, provisioning-profile hash,
// Mach-O section hash) — there's nothing SafetyNet can know on its own to
// compare against. So, matching how upstream treats this too, it's a
// standalone opt-in API, not wired into the scored SecurityOrchestrator
// pipeline.
//
// Implementation deviation from upstream: upstream hashes with
// `CommonCrypto`; this port uses `CryptoKit.SHA256` instead (Apple's modern
// hashing API, available since iOS 13 — well within this package's iOS
// 14+ deployment target). Same algorithm, same hex digest output for the
// same input — a hashing implementation detail, not a behavior change.

/// Possible checks made during `checkFileIntegrity` analysis.
public enum FileIntegrityCheck {
    /// Compare current bundle ID with a specified bundle ID.
    case bundleID(String)

    /// Compare the current SHA256 hex digest of `embedded.mobileprovision`
    /// with a specified hash value. Use
    /// `shasum -a 256 /path/to/embedded.mobileprovision` on macOS to get
    /// the expected value.
    case mobileProvision(String)

    /// Compare the current SHA256 hex digest of an executable's
    /// `__TEXT,__text` section with a specified (image name, hash value).
    /// Only works on dynamic libraries and arm64.
    case machO(String, String)
}

/// Result of `checkFileIntegrity` — whether tampering was detected, and
/// which specific checks flagged it.
public typealias FileIntegrityCheckResult = (result: Bool, hitChecks: [FileIntegrityCheck])

enum FileIntegrityChecker {

    static func checkFileIntegrity(_ checks: [FileIntegrityCheck]) -> FileIntegrityCheckResult {
        var hitChecks: [FileIntegrityCheck] = []
        var result = false

        for check in checks {
            switch check {
            case .bundleID(let expectedBundleID):
                if checkBundleID(expectedBundleID) {
                    result = true
                    hitChecks.append(check)
                }
            case .mobileProvision(let expectedSha256Value):
                if checkMobileProvision(expectedSha256Value.lowercased()) {
                    result = true
                    hitChecks.append(check)
                }
            case .machO(let imageName, let expectedSha256Value):
                if checkMachO(imageName, with: expectedSha256Value.lowercased()) {
                    result = true
                    hitChecks.append(check)
                }
            }
        }

        return (result, hitChecks)
    }

    private static func checkBundleID(_ expectedBundleID: String) -> Bool {
        expectedBundleID != Bundle.main.bundleIdentifier
    }

    private static func checkMobileProvision(_ expectedSha256Value: String) -> Bool {
        guard let path = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision"),
              let data = FileManager.default.contents(atPath: path) else {
            return false
        }

        let digest = SHA256.hash(data: data)
        let hex = digest.map { String(format: "%02hhx", $0) }.joined()
        return hex != expectedSha256Value
    }

    private static func checkMachO(_ imageName: String, with expectedSha256Value: String) -> Bool {
        #if arch(arm64)
        guard let hashValue = MachOTextSectionHasher.sha256HexDigest(imageName: imageName) else {
            return false
        }
        return hashValue != expectedSha256Value
        #else
        return false
        #endif
    }
}

#if arch(arm64)
// MARK: - Mach-O __TEXT,__text section hashing
//
// Ported from the equivalent upstream Mach-O text-section hashing logic.
// Walks LC_SEGMENT_64 load commands to
// find __TEXT/__text, then hashes its raw bytes.
private enum MachOTextSectionHasher {

    static func sha256HexDigest(imageName: String) -> String? {
        guard let (header, slide) = findImage(named: imageName) else { return nil }
        guard let section = findTextSection(header: header, slide: slide) else { return nil }
        guard let startAddr = UnsafeRawPointer(bitPattern: UInt(section.addr)) else { return nil }

        let buffer = UnsafeRawBufferPointer(start: startAddr, count: Int(section.size))
        let digest = SHA256.hash(data: Data(buffer))
        return digest.map { String(format: "%02hhx", $0) }.joined()
    }

    private static func findImage(named imageName: String) -> (header: UnsafePointer<mach_header>, slide: Int)? {
        for index in 0..<_dyld_image_count() {
            guard let cName = _dyld_get_image_name(index),
                  String(cString: cName).contains(imageName),
                  let header = _dyld_get_image_header(index) else { continue }
            return (header, _dyld_get_image_vmaddr_slide(index))
        }
        return nil
    }

    private struct TextSection {
        var addr: UInt64
        var size: UInt64
    }

    private static func findTextSection(header: UnsafePointer<mach_header>, slide: Int) -> TextSection? {
        guard var curCmd = UnsafeRawPointer(bitPattern: UInt(bitPattern: header) + UInt(MemoryLayout<mach_header_64>.size)) else {
            return nil
        }

        for _ in 0..<header.pointee.ncmds {
            let segCmd = curCmd.assumingMemoryBound(to: segment_command_64.self)

            if segCmd.pointee.cmd == LC_SEGMENT_64 {
                let segName = segmentName(segCmd.pointee.segname)

                if segName == "__TEXT" {
                    for sectionIndex in 0..<segCmd.pointee.nsects {
                        let sectionPtr = curCmd
                            .advanced(by: MemoryLayout<segment_command_64>.size + Int(sectionIndex) * MemoryLayout<section_64>.size)
                            .assumingMemoryBound(to: section_64.self)

                        if segmentName(sectionPtr.pointee.sectname) == "__text" {
                            let addr = UInt64(slide) + sectionPtr.pointee.addr
                            return TextSection(addr: addr, size: sectionPtr.pointee.size)
                        }
                    }
                }
            }

            curCmd = curCmd.advanced(by: Int(segCmd.pointee.cmdsize))
        }

        return nil
    }

    private static func segmentName(_ tuple: (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8)) -> String {
        withUnsafeBytes(of: tuple) { rawBuffer -> String in
            let ptr = rawBuffer.baseAddress!.assumingMemoryBound(to: CChar.self)
            return String(cString: ptr)
        }
    }
}
#endif
