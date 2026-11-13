import Foundation

/// One TCP port that accepted a connection on one host.
public struct OpenPort: Hashable, Sendable {
    public let host: String
    public let port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }
}

/// Turns open ports into findings.
///
/// Deliberately as pure as `PostureEvaluator`: the scan engine collects, this
/// judges. What is reported is an exposed service, never an exploit — the only
/// claim made is that a TCP connection succeeded and what normally listens
/// there.
public struct ExposureEvaluator: Sendable {
    public struct Policy: Sendable {
        public var services: [UInt16: ServiceDefinition]

        public init(services: [ServiceDefinition] = ServiceCatalog.services) {
            self.services = Dictionary(uniqueKeysWithValues: services.map { ($0.port, $0) })
        }
    }

    public var policy: Policy

    public init(policy: Policy = Policy()) {
        self.policy = policy
    }

    public func evaluate(_ openPorts: [OpenPort]) -> [Finding] {
        var seen = Set<OpenPort>()
        var findings: [Finding] = []

        for open in openPorts {
            guard seen.insert(open).inserted else { continue }
            guard let service = policy.services[open.port],
                  let severity = service.severity
            else {
                continue
            }

            findings.append(
                Finding(
                    title: "\(service.name) is reachable",
                    severity: severity,
                    category: .networkExposure,
                    evidence: "\(open.host) accepted a TCP connection on port \(open.port) (\(service.name)).",
                    remediation: service.remediation,
                    host: open.host,
                    port: open.port
                )
            )
        }

        return findings.sortedBySeverity()
    }
}
