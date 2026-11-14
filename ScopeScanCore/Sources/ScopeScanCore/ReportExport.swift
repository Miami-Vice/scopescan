import Foundation

/// How IPv4 addresses appear in an exported report.
public enum AddressRedaction: String, Codable, Sendable, Hashable, CaseIterable {
    /// Addresses appear exactly as scanned.
    case none
    /// The last octet is hidden: `192.168.12.157` becomes `192.168.12.x`.
    case maskLastOctet
    /// Each host gets a label that is stable within this export: `host-1`, `host-2`.
    case pseudonyms

    public var displayName: String {
        switch self {
        case .none: return "Full addresses"
        case .maskLastOctet: return "Mask last octet"
        case .pseudonyms: return "Pseudonyms"
        }
    }
}

/// A report in a form that is safe to share: stable, versioned, and free of
/// anything the redaction mode asks to hide.
public struct ReportExport: Codable, Sendable, Equatable {
    public static let formatVersion = 1

    public struct Host: Codable, Sendable, Equatable {
        public let address: String
        public let label: String?
        public let ports: [Port]
    }

    public struct Port: Codable, Sendable, Equatable {
        public let port: UInt16
        public let name: String
        public let detail: String?
    }

    public struct Finding: Codable, Sendable, Equatable {
        public let title: String
        public let severity: Severity
        public let category: String
        public let evidence: String
        public let remediation: String
        public let host: String?
        public let port: UInt16?
    }

    public let formatVersion: Int
    public let network: String
    public let startedAt: Date
    public let durationSeconds: Double
    public let redaction: AddressRedaction
    public let scannedHostCount: Int
    public let hostsUp: Int
    public let refusedProbeCount: Int
    public let wasCancelled: Bool
    public let hosts: [Host]
    public let findings: [Finding]
    /// Bonjour instance names are device identifiers, so they are only kept
    /// when addresses are kept too. Service types are always included.
    public let bonjourServices: [String]
}

/// Builds a `ReportExport` from a scan, applying one redaction mode everywhere
/// an address can appear: host lists, labels, finding evidence and remediation.
public enum ReportExporter {
    public static func export(_ report: ScanReport, redaction: AddressRedaction) -> ReportExport {
        let mapping = AddressMapping(addresses: report.hosts.map(\.address), redaction: redaction)

        let hosts = report.hosts.map { host in
            ReportExport.Host(
                address: mapping.replacement(for: host.address.description),
                label: host.label.map { label in
                    redaction == .none ? mapping.redact(label) : withoutAnnouncedName(label)
                },
                ports: host.openPorts.map { port in
                    ReportExport.Port(
                        port: port,
                        name: ServiceCatalog.name(for: port),
                        detail: host.details[port].map(mapping.redact)
                    )
                }
            )
        }

        let findings = report.findings.map { finding in
            ReportExport.Finding(
                title: finding.title,
                severity: finding.severity,
                category: finding.category.displayName,
                evidence: mapping.redact(finding.evidence),
                remediation: finding.remediation,
                host: finding.host.map(mapping.replacement(for:)),
                port: finding.port
            )
        }

        let bonjour: [String] = report.bonjour.map { service in
            redaction == .none ? "\(service.name) (\(service.displayType))" : service.displayType
        }

        return ReportExport(
            formatVersion: ReportExport.formatVersion,
            network: mapping.redact(report.cidr),
            startedAt: report.startedAt,
            durationSeconds: report.duration,
            redaction: redaction,
            scannedHostCount: report.scannedHostCount,
            hostsUp: report.hostsUp,
            refusedProbeCount: report.refusedProbeCount,
            wasCancelled: report.wasCancelled,
            hosts: hosts,
            findings: findings,
            bonjourServices: bonjour
        )
    }

    /// `Named by Bonjour: Living Room TV` keeps only the fact that a name was
    /// announced. The name itself identifies a person's device.
    static func withoutAnnouncedName(_ label: String) -> String {
        let prefix = "Named by Bonjour"
        return label.hasPrefix(prefix) ? prefix : label
    }

    public static func json(_ export: ReportExport) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(export)
    }
}

/// One mapping from address text to its replacement, applied to every string.
struct AddressMapping {
    private let replacements: [(address: String, replacement: String)]
    private let byAddress: [String: String]

    init(addresses: [IPv4Address], redaction: AddressRedaction) {
        let unique = Array(Set(addresses)).sorted()
        var pairs: [(String, String)] = []
        for (index, address) in unique.enumerated() {
            let text = address.description
            let replacement: String
            switch redaction {
            case .none:
                replacement = text
            case .maskLastOctet:
                replacement = Self.masked(text)
            case .pseudonyms:
                replacement = "host-\(index + 1)"
            }
            pairs.append((text, replacement))
        }
        // Longest first, so 192.168.12.157 is replaced before its prefix 192.168.12.1.
        self.replacements = pairs
            .sorted { $0.0.count > $1.0.count }
            .map { (address: $0.0, replacement: $0.1) }
        self.byAddress = Dictionary(uniqueKeysWithValues: pairs.map { ($0.0, $0.1) })
    }

    func replacement(for address: String) -> String {
        byAddress[address] ?? address
    }

    func redact(_ text: String) -> String {
        var result = text
        for (address, replacement) in replacements {
            result = result.replacingOccurrences(of: address, with: replacement)
        }
        return result
    }

    private static func masked(_ text: String) -> String {
        guard let dot = text.lastIndex(of: ".") else { return text }
        return String(text[..<dot]) + ".x"
    }
}
