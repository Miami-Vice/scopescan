import Foundation
import UIKit

/// Looks for evidence that this device's code-signing and sandbox guarantees
/// have been removed.
///
/// Every check here is read-only and detection-only. A false positive would be
/// worse than a missed detection, so each indicator reports the concrete artifact
/// it found rather than a vague verdict.
@MainActor
enum JailbreakDetector {
    /// Paths that exist only on a jailbroken filesystem. On a stock device the
    /// sandbox makes all of these unreachable, so a positive is meaningful.
    private static let suspiciousPaths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/var/jb",
        "/var/lib/dpkg/status",
        "/var/lib/cydia",
        "/private/var/lib/apt",
        "/etc/apt",
        "/usr/sbin/sshd"
    ]

    /// Substrings of images that only appear when injection is active.
    private static let suspiciousImages = [
        "Substrate",
        "Substitute",
        "libhooker",
        "TweakInject",
        "Cydia",
        "Frida"
    ]

    /// Package-manager schemes, declared in LSApplicationQueriesSchemes.
    private static let suspiciousSchemes = ["cydia", "sileo", "zbra"]

    static func indicators() -> [String] {
        var found: [String] = []

        for path in suspiciousPaths where FileManager.default.fileExists(atPath: path) {
            found.append("path exists: \(path)")
        }

        for scheme in suspiciousSchemes {
            if let url = URL(string: "\(scheme)://"), UIApplication.shared.canOpenURL(url) {
                found.append("url scheme resolves: \(scheme)://")
            }
        }

        if let injected = getenv("DYLD_INSERT_LIBRARIES") {
            let value = String(cString: injected)
            if !value.isEmpty {
                found.append("DYLD_INSERT_LIBRARIES is set")
            }
        }

        var reportedImages = Set<String>()
        for index in 0..<_dyld_image_count() {
            guard let rawName = _dyld_get_image_name(index) else { continue }
            let name = String(cString: rawName)
            for marker in suspiciousImages where name.localizedCaseInsensitiveContains(marker) {
                guard !reportedImages.contains(marker) else { continue }
                reportedImages.insert(marker)
                found.append("loaded image: \(name)")
            }
        }

        return found
    }
}
