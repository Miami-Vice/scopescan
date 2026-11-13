import Foundation
import Darwin

/// Detects an attached debugger by asking the kernel whether this process is
/// being traced.
///
/// `P_TRACED` is set for anything using `ptrace`-style attachment, including
/// Xcode and Frida. This is a tamper *signal*, not proof of compromise — a
/// legitimate debugging session sets it too.
enum DebuggerDetector {
    static func isAttached() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]

        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        guard result == 0 else { return false }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
}
