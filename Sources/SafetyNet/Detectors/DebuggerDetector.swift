import Darwin
import Foundation
import MachO
import SafetyNetObjC

// Ported from cordova-plugin-security DebuggerDetector.m, later extended
// with additional signals ported from a well-known open-source iOS
// security-detection technique.
enum DebuggerDetector {

    static func installAntiDebugAtLaunch() {
        // The __attribute__((constructor)) in AntiDebugBridge.m already ran
        // before main(). This call exists as a documented integration point.
        safetynet_install_anti_debug()
    }

    static func isDebuggerAttached() -> Bool {
        #if DEBUG || targetEnvironment(simulator)
        return false
        #else
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = sysctl(&mib, 4, &info, &size, nil, 0)
        guard result == 0 else { return false }
        return (info.kp_proc.p_flag & P_TRACED) != 0
        #endif
    }

    static func isBeingTraced() -> Bool {
        #if DEBUG || targetEnvironment(simulator)
        return false
        #else
        // Legitimate parent = SpringBoard or launchd, not lldb/Xcode
        let ppid = getppid()
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, ppid]
        let result = sysctl(&mib, 4, &info, &size, nil, 0)
        guard result == 0 else { return false }

        let parentName = withUnsafeBytes(of: info.kp_proc.p_comm) { rawBuffer -> String in
            let ptr = rawBuffer.baseAddress!.assumingMemoryBound(to: CChar.self)
            return String(cString: ptr)
        }
        let legitimateParents: Set<String> = ["launchd", "SpringBoard", "backboardd"]
        return !legitimateParents.contains(parentName)
        #endif
    }

    // MARK: - Watchpoint detection
    //
    // Ported from the equivalent upstream watchpoint check. Scans every
    // thread's ARM debug state for a non-zero watch register — a
    // debugger placing a watchpoint (e.g. to catch a value change) sets
    // this. ARM64-only, matching upstream.

    static func hasWatchpoint() -> Bool {
        #if DEBUG || targetEnvironment(simulator)
        return false
        #elseif arch(arm64)
        var threads: thread_act_array_t?
        var threadCount: mach_msg_type_number_t = 0
        var found = false

        guard task_threads(mach_task_self_, &threads, &threadCount) == KERN_SUCCESS,
              let threadList = threads else {
            return false
        }

        var threadStat = arm_debug_state64_t()
        let capacity = MemoryLayout<arm_debug_state64_t>.size / MemoryLayout<natural_t>.size
        let threadStatPointer = withUnsafeMutablePointer(to: &threadStat) {
            $0.withMemoryRebound(to: natural_t.self, capacity: capacity) { $0 }
        }
        var count = mach_msg_type_number_t(
            MemoryLayout<arm_debug_state64_t>.size / MemoryLayout<UInt32>.size
        )

        for threadIndex in 0..<threadCount where thread_get_state(
            threadList[Int(threadIndex)],
            ARM_DEBUG_STATE64,
            threadStatPointer,
            &count
        ) == KERN_SUCCESS {
            found = threadStatPointer.withMemoryRebound(to: arm_debug_state64_t.self, capacity: 1) {
                $0
            }.pointee.__wvr.0 != 0
            if found { break }
        }

        vm_deallocate(
            mach_task_self_,
            vm_address_t(UInt(bitPattern: threadList)),
            vm_size_t(threadCount * UInt32(MemoryLayout<thread_act_t>.size))
        )

        return found
        #else
        return false
        #endif
    }

    // MARK: - P_SELECT flag check
    //
    // Ported from the equivalent upstream P_SELECT check. Upstream marks
    // this check "EXPERIMENTAL" — kept here with the same caveat and a
    // correspondingly low score weight in SecurityOrchestrator.

    static func hasPSelectFlag() -> Bool {
        #if DEBUG || targetEnvironment(simulator)
        return false
        #else
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = sysctl(&mib, 4, &info, &size, nil, 0)
        guard result == 0 else { return false }
        return (info.kp_proc.p_flag & P_SELECT) != 0
        #endif
    }

    // MARK: - Breakpoint detection (opt-in diagnostic)
    //
    // Ported from the equivalent upstream breakpoint check. Needs
    // a caller-supplied function address, so — like
    // IntegrityValidator.detectMemoryPatch — this is not wired into the
    // scored SecurityOrchestrator pipeline; call it directly for a specific
    // function you want to check. ARM64-only, matching upstream.

    static func hasBreakpoint(at functionAddr: UnsafeRawPointer, functionSize: vm_size_t?) -> Bool {
        #if arch(arm64)
        let funcAddr = vm_address_t(UInt(bitPattern: functionAddr))

        var vmStart: vm_address_t = funcAddr
        var vmSize: vm_size_t = 0
        let vmRegionInfo = UnsafeMutablePointer<Int32>.allocate(
            capacity: MemoryLayout<vm_region_basic_info_64>.size / 4
        )
        defer { vmRegionInfo.deallocate() }

        var vmRegionInfoCount: mach_msg_type_number_t = mach_msg_type_number_t(VM_REGION_BASIC_INFO_64)
        var objectName: mach_port_t = 0

        let ret = vm_region_64(
            mach_task_self_, &vmStart, &vmSize, VM_REGION_BASIC_INFO_64,
            vmRegionInfo, &vmRegionInfoCount, &objectName
        )
        guard ret == KERN_SUCCESS else { return false }

        let vmRegion = vmRegionInfo.withMemoryRebound(to: vm_region_basic_info_64.self, capacity: 1) { $0 }

        guard vmRegion.pointee.protection == (VM_PROT_READ | VM_PROT_EXECUTE) else {
            return false
        }

        let armBreakpointOpcode: UInt32 = 0xe7ffdefe
        let arm64BreakpointOpcode: UInt32 = 0xd4200000
        let instructionBegin = functionAddr.bindMemory(to: UInt32.self, capacity: 1)
        var judgeSize = vmSize - (funcAddr - vmStart)
        if let size = functionSize, size < judgeSize {
            judgeSize = size
        }

        for offset in 0..<(judgeSize / 4) {
            let instruction = instructionBegin.advanced(by: Int(offset)).pointee
            if instruction == armBreakpointOpcode || instruction == arm64BreakpointOpcode {
                return true
            }
        }

        return false
        #else
        return false
        #endif
    }
}
