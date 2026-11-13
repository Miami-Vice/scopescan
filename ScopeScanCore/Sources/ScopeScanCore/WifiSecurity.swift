import Foundation

/// The security posture of the local Wi-Fi link, as reported by the system.
public enum WifiSecurity: String, Codable, Sendable, CaseIterable {
    case open
    case wep
    case wpa
    case wpa2
    case wpa3
    case enterprise
    case unknown

    public var displayName: String {
        switch self {
        case .open: return "Open (no encryption)"
        case .wep: return "WEP"
        case .wpa: return "WPA"
        case .wpa2: return "WPA2"
        case .wpa3: return "WPA3"
        case .enterprise: return "WPA2/WPA3 Enterprise"
        case .unknown: return "Unknown"
        }
    }

    public var isEncrypted: Bool { self != .open }

    /// WEP has been breakable in minutes since 2001, and an open network has no
    /// protection at all. WPA (TKIP) is also deprecated, but is not reported as
    /// weak here because it is still meaningfully better than nothing.
    public var isWeak: Bool { self == .open || self == .wep }
}
