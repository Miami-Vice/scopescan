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

    public struct BonjourEntry: Codable, Sendable, Equatable {
        /// The name the device announced. Nil once the export is redacted.
        public let name: String?
        public let type: String
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
    public let bonjourServices: [BonjourEntry]

    /// A copy with `mode` applied. Only a full export can be redacted: once
    /// addresses are masked they cannot be recovered, so a redacted export
    /// returns itself unchanged.
    public func redacted(_ mode: AddressRedaction) -> ReportExport {
        guard redaction == .none, mode != .none else { return self }

        let mapping = AddressMapping(addresses: hosts.map(\.address), redaction: mode)

        return ReportExport(
            formatVersion: formatVersion,
            network: mapping.redact(network),
            startedAt: startedAt,
            durationSeconds: durationSeconds,
            redaction: mode,
            scannedHostCount: scannedHostCount,
            hostsUp: hostsUp,
            refusedProbeCount: refusedProbeCount,
            wasCancelled: wasCancelled,
            hosts: hosts.map { host in
                Host(
                    address: mapping.replacement(for: host.address),
                    label: host.label.map(ReportExporter.redactLabel(_:)),
                    ports: host.ports.map { port in
                        Port(port: port.port, name: port.name, detail: port.detail.map(mapping.redact))
                    }
                )
            },
            findings: findings.map { finding in
                Finding(
                    title: finding.title,
                    severity: finding.severity,
                    category: finding.category,
                    evidence: mapping.redact(finding.evidence),
                    remediation: finding.remediation,
                    host: finding.host.map(mapping.replacement(for:)),
                    port: finding.port
                )
            },
            bonjourServices: bonjourServices.map { BonjourEntry(name: nil, type: $0.type) }
        )
    }
}

/// Builds a `ReportExport` from a scan. A scan is always exported in full first
/// and then redacted, so every mode goes through one code path.
public enum ReportExporter {
    public static func export(_ report: ScanReport, redaction: AddressRedaction) -> ReportExport {
        full(report).redacted(redaction)
    }

    /// The unredacted form. This is what the app stores on the device.
    public static func full(_ report: ScanReport) -> ReportExport {
        ReportExport(
            formatVersion: ReportExport.formatVersion,
            network: report.cidr,
            startedAt: report.startedAt,
            durationSeconds: report.duration,
            redaction: .none,
            scannedHostCount: report.scannedHostCount,
            hostsUp: report.hostsUp,
            refusedProbeCount: report.refusedProbeCount,
            wasCancelled: report.wasCancelled,
            hosts: report.hosts.map { host in
                ReportExport.Host(
                    address: host.address.description,
                    label: host.label,
                    ports: host.openPorts.map { port in
                        ReportExport.Port(
                            port: port,
                            name: ServiceCatalog.name(for: port),
                            detail: host.details[port]
                        )
                    }
                )
            },
            findings: report.findings.map { finding in
                ReportExport.Finding(
                    title: finding.title,
                    severity: finding.severity,
                    category: finding.category.displayName,
                    evidence: finding.evidence,
                    remediation: finding.remediation,
                    host: finding.host,
                    port: finding.port
                )
            },
            bonjourServices: report.bonjour.map {
                ReportExport.BonjourEntry(name: $0.name, type: $0.displayType)
            }
        )
    }

    public static func json(_ export: ReportExport) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(export)
    }

    /// `Named by Bonjour: Living Room TV` keeps only the fact that a name was
    /// announced. The name itself identifies a person's device.
    static func redactLabel(_ label: String) -> String {
        let prefix = "Named by Bonjour"
        return label.hasPrefix(prefix) ? prefix : label
    }

}

/// One mapping from address text to its replacement, applied to every string.
struct AddressMapping {
    private let replacements: [(address: String, replacement: String)]
    private let byAddress: [String: String]

    init(addresses: [String], redaction: AddressRedaction) {
        let unique = Array(Set(addresses)).sorted { lhs, rhs in
            (IPv4Address(lhs)?.rawValue ?? 0) < (IPv4Address(rhs)?.rawValue ?? 0)
        }
        var pairs: [(String, String)] = []
        for (index, text) in unique.enumerated() {
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
