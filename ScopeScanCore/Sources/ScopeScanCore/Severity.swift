import Foundation

/// Qualitative severity of a finding.
///
/// Ordered from least to most severe so that `>` comparisons and
/// `max(by:)` behave intuitively.
public enum Severity: String, CaseIterable, Codable, Sendable, Comparable {
    case info
    case low
    case medium
    case high
    case critical

    public var rank: Int {
        switch self {
        case .info: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    public var displayName: String {
        switch self {
        case .info: return "Info"
        case .low: return "Low"
        case .medium: return "Medium"
        case .high: return "High"
        case .critical: return "Critical"
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        lhs.rank < rhs.rank
    }
}
