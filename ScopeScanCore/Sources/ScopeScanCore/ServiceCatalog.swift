import Foundation

/// A TCP service ScopeScan knows how to name and judge.
///
/// The catalog is intentionally small. A full 65535-port sweep would be slow,
/// noisy and mostly empty; this covers the services that actually expose data,
/// credentials or administration on a home or small-office network.
public struct ServiceDefinition: Identifiable, Hashable, Sendable {
    public let port: UInt16
    public let name: String
    /// Nil means the service is inventoried but is not itself a finding.
    public let severity: Severity?
    public let remediation: String

    public var id: UInt16 { port }

    public init(port: UInt16, name: String, severity: Severity? = nil, remediation: String = "") {
        self.port = port
        self.name = name
        self.severity = severity
        self.remediation = remediation
    }
}

/// The fixed set of ports ScopeScan probes, and what it says about them.
public enum ServiceCatalog {
    /// Probed first to decide whether a host is up.
    ///
    /// A refused connection is still an answer — the host's TCP stack replied —
    /// so these doubles as the cheapest liveness signal an unprivileged app has.
    public static let discoveryPorts: [UInt16] = [80, 443, 22, 445]

    /// Everything the inventory reports. Contains `discoveryPorts`.
    public static let services: [ServiceDefinition] = [
        ServiceDefinition(
            port: 21,
            name: "FTP",
            severity: .high,
            remediation: "Disable FTP or replace it with SFTP/FTPS. FTP sends credentials and file contents in clear text, so anyone on this network can read them."
        ),
        ServiceDefinition(
            port: 22,
            name: "SSH",
            severity: .low,
            remediation: "If remote shell access is not needed, disable it. Otherwise restrict it to trusted hosts and prefer key authentication over passwords."
        ),
        ServiceDefinition(
            port: 23,
            name: "Telnet",
            severity: .critical,
            remediation: "Disable Telnet and use SSH instead. Telnet transmits everything, including the login, unencrypted."
        ),
        ServiceDefinition(port: 80, name: "HTTP"),
        ServiceDefinition(port: 139, name: "NetBIOS"),
        ServiceDefinition(port: 443, name: "HTTPS"),
        ServiceDefinition(
            port: 445,
            name: "SMB file sharing",
            severity: .high,
            remediation: "Turn off file sharing on this host, or restrict it to trusted users and devices. SMB has a long history of remotely exploitable flaws."
        ),
        ServiceDefinition(
            port: 548,
            name: "AFP file sharing",
            severity: .medium,
            remediation: "Disable Apple Filing Protocol sharing if it is not in use, or limit it to trusted devices."
        ),
        ServiceDefinition(
            port: 631,
            name: "IPP printing",
            severity: .low,
            remediation: "Restrict the printer's web/print interface to trusted devices. Unauthenticated print access can be used to waste supplies or read queued jobs."
        ),
        ServiceDefinition(port: 5000, name: "HTTP (alt)"),
        ServiceDefinition(
            port: 3389,
            name: "RDP",
            severity: .high,
            remediation: "Disable Remote Desktop if it is not needed, and never expose it beyond the local network. RDP is a common initial-access target."
        ),
        ServiceDefinition(
            port: 5900,
            name: "VNC",
            severity: .high,
            remediation: "Disable screen sharing or require authentication and restrict it to trusted hosts. Unauthenticated VNC gives full control of the desktop."
        ),
        ServiceDefinition(port: 8080, name: "HTTP (alt)"),
        ServiceDefinition(port: 8443, name: "HTTPS (alt)"),
        ServiceDefinition(
            port: 9100,
            name: "Raw printing",
            severity: .medium,
            remediation: "Restrict raw port 9100 to trusted devices. It accepts print jobs with no authentication."
        )
    ]

    /// Every port the inventory probes, discovery ports first.
    public static var inventoryPorts: [UInt16] {
        var seen = Set<UInt16>()
        return (discoveryPorts + services.map(\.port)).filter { seen.insert($0).inserted }
    }

    public static func service(for port: UInt16) -> ServiceDefinition? {
        services.first { $0.port == port }
    }

    public static func name(for port: UInt16) -> String {
        service(for: port)?.name ?? "port \(port)"
    }
}
