import Foundation

/// A single weakness or exposure discovered by ScopeScan.
///
/// Findings are deliberately descriptive rather than exploitative: they record
/// what was observed, why it matters, and how to fix it. No finding implies an
/// exploit was developed or executed.
public struct Finding: Identifiable, Codable, Sendable, Hashable {
    public enum Category: String, Codable, Sendable, CaseIterable {
        case devicePosture
        case networkExposure
        case transportSecurity
        case serviceFingerprint

        public var displayName: String {
            switch self {
            case .devicePosture: return "Device posture"
            case .networkExposure: return "Network exposure"
            case .transportSecurity: return "Transport security"
            case .serviceFingerprint: return "Service fingerprint"
            }
        }
    }

    public let id: UUID
    public let title: String
    public let severity: Severity
    public let category: Category
    /// What was actually observed, verbatim where possible.
    public let evidence: String
    /// Concrete steps the owner can take to close the exposure.
    public let remediation: String
    public let references: [URL]
    public let discoveredAt: Date
    /// Nil for findings about this device itself, as opposed to a host on the LAN.
    public let host: String?
    public let port: UInt16?

    public init(
        id: UUID = UUID(),
        title: String,
        severity: Severity,
        category: Category,
        evidence: String,
        remediation: String,
        references: [URL] = [],
        discoveredAt: Date = Date(),
        host: String? = nil,
        port: UInt16? = nil
    ) {
        self.id = id
        self.title = title
        self.severity = severity
        self.category = category
        self.evidence = evidence
        self.remediation = remediation
        self.references = references
        self.discoveredAt = discoveredAt
        self.host = host
        self.port = port
    }
}

public extension Array where Element == Finding {
    /// Most severe first, then alphabetical for stable presentation.
    func sortedBySeverity() -> [Finding] {
        sorted { lhs, rhs in
            if lhs.severity != rhs.severity {
                return lhs.severity > rhs.severity
            }
            return lhs.title.localizedCompare(rhs.title) == .orderedAscending
        }
    }

    var highestSeverity: Severity? {
        self.map(\.severity).max()
    }
}
