import Foundation

/// A host that answered during a sweep.
///
/// `openPorts` may be empty: a host that resets connections is up even when
/// none of the catalogued ports are listening, and hiding it would misrepresent
/// the network.
public struct HostReport: Identifiable, Sendable, Hashable {
    public let address: IPv4Address
    public let openPorts: [UInt16]
    /// What each open port said about itself, e.g. `SSH 2.0, OpenSSH_9.6`.
    public let details: [UInt16: String]
    /// A guess at what the host is, from `HostLabel`.
    public let label: String?

    public var id: IPv4Address { address }

    public init(
        address: IPv4Address,
        openPorts: [UInt16],
        details: [UInt16: String] = [:],
        label: String? = nil
    ) {
        self.address = address
        self.openPorts = openPorts
        self.details = details
        self.label = label
    }
}

/// A Bonjour service advertised on the network.
///
/// Service results are inventory, not findings: a printer announcing itself is
/// normal. The interesting part is what the inventory reveals about devices the
/// owner may not have known were present.
public struct BonjourService: Identifiable, Sendable, Hashable {
    public let name: String
    /// The raw service type, e.g. `_http._tcp`.
    public let type: String
    public let domain: String

    public var id: String { "\(name)|\(type)|\(domain)" }

    public init(name: String, type: String, domain: String) {
        self.name = name
        self.type = type
        self.domain = domain
    }

    /// `_http._tcp` reads as `http (TCP)`.
    public var displayType: String {
        let trimmed = type.hasPrefix("_") ? String(type.dropFirst()) : type
        guard let separator = trimmed.range(of: "._") else { return trimmed }
        let service = String(trimmed[..<separator.lowerBound])
        let transport = String(trimmed[separator.upperBound...]).uppercased()
        return "\(service) (\(transport))"
    }
}

/// What a Bonjour enumeration found, and whether the permission blocked it.
public struct BonjourDiscovery: Sendable, Hashable {
    public let services: [BonjourService]
    public let denied: Bool
    /// The name each announcing device gave itself, keyed by its address.
    public let namesByAddress: [IPv4Address: String]

    public init(
        services: [BonjourService] = [],
        denied: Bool = false,
        namesByAddress: [IPv4Address: String] = [:]
    ) {
        self.services = services
        self.denied = denied
        self.namesByAddress = namesByAddress
    }

    public static let none = BonjourDiscovery()
}

/// Progress through a sweep, delivered after each host completes.
public struct ScanProgress: Sendable, Hashable {
    public let hostsCompleted: Int
    public let hostCount: Int
    public let hostsUp: Int
    public let openPortCount: Int

    public init(hostsCompleted: Int, hostCount: Int, hostsUp: Int, openPortCount: Int) {
        self.hostsCompleted = hostsCompleted
        self.hostCount = hostCount
        self.hostsUp = hostsUp
        self.openPortCount = openPortCount
    }

    public var fraction: Double {
        guard hostCount > 0 else { return 0 }
        return min(1, Double(hostsCompleted) / Double(hostCount))
    }
}

/// The complete result of one scan.
public struct ScanReport: Sendable {
    public let cidr: String
    public let startedAt: Date
    public let duration: TimeInterval
    /// How many hosts were actually probed; less than the scope size when the
    /// scan was cancelled.
    public let scannedHostCount: Int
    /// Hosts that answered, sorted by address.
    public let hosts: [HostReport]
    public let openPorts: [OpenPort]
    public let findings: [Finding]
    public let bonjour: [BonjourService]
    /// Probes the system refused with a permission error. Non-zero means the
    /// results are incomplete, not that the network is quiet.
    public let refusedProbeCount: Int
    /// The first refused probe, for the report: host, port and error code.
    public let firstRefusal: String?
    public let wasCancelled: Bool

    public var localNetworkDenied: Bool { refusedProbeCount > 0 }

    public init(
        cidr: String,
        startedAt: Date,
        duration: TimeInterval,
        scannedHostCount: Int,
        hosts: [HostReport],
        openPorts: [OpenPort],
        findings: [Finding],
        bonjour: [BonjourService] = [],
        refusedProbeCount: Int = 0,
        firstRefusal: String? = nil,
        wasCancelled: Bool = false
    ) {
        self.cidr = cidr
        self.startedAt = startedAt
        self.duration = duration
        self.scannedHostCount = scannedHostCount
        self.hosts = hosts
        self.openPorts = openPorts
        self.findings = findings
        self.bonjour = bonjour
        self.refusedProbeCount = refusedProbeCount
        self.firstRefusal = firstRefusal
        self.wasCancelled = wasCancelled
    }

    public var hostsUp: Int { hosts.count }
}
