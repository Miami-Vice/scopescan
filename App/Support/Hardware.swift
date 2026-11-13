import Foundation
import Darwin

/// Reads the hardware model identifier (e.g. "iPhone16,1") via `sysctlbyname`.
///
/// `UIDevice` only offers a user-facing model name, which collapses every iPhone
/// into "iPhone", so the sysctl is the only useful identifier available to a
/// sandboxed app.
enum Hardware {
    static func identifier() -> String {
        var size = 0
        guard sysctlbyname("hw.machine", nil, &size, nil, 0) == 0, size > 0 else {
            return "unknown"
        }

        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname("hw.machine", &buffer, &size, nil, 0) == 0 else {
            return "unknown"
        }
        return String(cString: buffer)
    }
}
