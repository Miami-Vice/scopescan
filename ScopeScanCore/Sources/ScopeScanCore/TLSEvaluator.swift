import Foundation

/// TLS protocol versions in increasing order of strength.
public enum TLSVersion: Int, Comparable, Sendable, CaseIterable {
    case unknown = 0
    case tls10 = 1
    case tls11 = 2
    case tls12 = 3
    case tls13 = 4

    public static func < (lhs: TLSVersion, rhs: TLSVersion) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var displayName: String {
        switch self {
        case .unknown: return "unknown"
        case .tls10: return "TLS 1.0"
        case .tls11: return "TLS 1.1"
        case .tls12: return "TLS 1.2"
        case .tls13: return "TLS 1.3"
        }
    }
}

/// The public-key family of a certificate. Minimum key sizes differ by family.
public enum KeyAlgorithm: String, Sendable, Hashable {
    case rsa
    case ellipticCurve
    case unknown
}

/// What a TLS handshake against one port revealed.
public struct TLSObservation: Sendable, Hashable {
    public let host: String
    public let port: UInt16
    public let version: TLSVersion
    /// Expiry of the leaf certificate, if it could be read.
    public let leafNotAfter: Date?
    public let leafKeyAlgorithm: KeyAlgorithm
    /// RSA modulus length or EC curve size, in bits.
    public let leafKeyBits: Int?
    public let leafSubject: String?
    /// Whether the device's trust store accepts the presented chain.
    public let chainTrusted: Bool

    public init(
        host: String,
        port: UInt16,
        version: TLSVersion,
        leafNotAfter: Date?,
        leafKeyAlgorithm: KeyAlgorithm = .unknown,
        leafKeyBits: Int?,
        leafSubject: String?,
        chainTrusted: Bool
    ) {
        self.host = host
        self.port = port
        self.version = version
        self.leafNotAfter = leafNotAfter
        self.leafKeyAlgorithm = leafKeyAlgorithm
        self.leafKeyBits = leafKeyBits
        self.leafSubject = leafSubject
        self.chainTrusted = chainTrusted
    }

    /// How the certificate is named in a finding. iOS reports a certificate
    /// with no common name as its serial number, which is not a name a person
    /// can recognise, so an all-digit subject reads as unnamed.
    public var subjectDescription: String {
        guard let subject = leafSubject?.trimmingCharacters(in: .whitespaces),
              !subject.isEmpty,
              !subject.allSatisfy(\.isNumber)
        else {
            return "an unnamed certificate"
        }
        return "a certificate for \"\(subject)\""
    }

    /// The smallest key this device should accept without a finding, or nil
    /// when the family is unknown and no judgement can be made.
    public var minimumAcceptableKeyBits: Int? {
        switch leafKeyAlgorithm {
        case .rsa: return 2048
        case .ellipticCurve: return 256
        case .unknown: return nil
        }
    }
}

/// Judges a TLS observation. Like `ExposureEvaluator`, it reports what was
/// seen and how to fix it, and never claims an attack was attempted.
public struct TLSEvaluator: Sendable {
    /// Certificates expiring inside this window are flagged before they lapse.
    public static let expiryWarningWindow: TimeInterval = 30 * 24 * 60 * 60

    public var now: Date

    public init(now: Date = Date()) {
        self.now = now
    }

    public func evaluate(_ observation: TLSObservation) -> [Finding] {
        var findings: [Finding] = []
        let location = "\(observation.host):\(observation.port)"

        if observation.version != .unknown, observation.version < .tls12 {
            findings.append(
                finding(
                    title: "Outdated TLS version",
                    severity: .high,
                    evidence: "\(location) negotiated \(observation.version.displayName).",
                    remediation: "Disable TLS 1.0 and 1.1 on this service and require TLS 1.2 or later.",
                    observation: observation
                )
            )
        }

        if let notAfter = observation.leafNotAfter {
            if notAfter < now {
                findings.append(
                    finding(
                        title: "Certificate has expired",
                        severity: .high,
                        evidence: "The certificate for \(location) expired on \(notAfter.formatted(date: .abbreviated, time: .omitted)).",
                        remediation: "Renew the certificate. Clients that check expiry will refuse the connection.",
                        observation: observation
                    )
                )
            } else if notAfter.timeIntervalSince(now) < Self.expiryWarningWindow {
                findings.append(
                    finding(
                        title: "Certificate expires soon",
                        severity: .low,
                        evidence: "The certificate for \(location) expires on \(notAfter.formatted(date: .abbreviated, time: .omitted)).",
                        remediation: "Renew the certificate before it expires.",
                        observation: observation
                    )
                )
            }
        }

        if let bits = observation.leafKeyBits,
           let minimum = observation.minimumAcceptableKeyBits,
           bits < minimum {
            findings.append(
                finding(
                    title: "Weak certificate key",
                    severity: .high,
                    evidence: "The certificate for \(location) uses a \(bits)-bit \(observation.leafKeyAlgorithm.rawValue) key, below the \(minimum)-bit minimum.",
                    remediation: "Replace the certificate with one using an RSA key of at least 2048 bits, or an elliptic-curve key of at least 256 bits.",
                    observation: observation
                )
            )
        }

        if !observation.chainTrusted {
            findings.append(
                finding(
                    title: "Certificate is not trusted by this device",
                    severity: .low,
                    evidence: "\(location) presented \(observation.subjectDescription) that this device does not trust.",
                    remediation: "Expected for self-signed or private-CA devices on a home network. Confirm the certificate belongs to the device you intend, and avoid sending credentials over it if it does not.",
                    observation: observation
                )
            )
        }

        return findings.sortedBySeverity()
    }

    private func finding(
        title: String,
        severity: Severity,
        evidence: String,
        remediation: String,
        observation: TLSObservation
    ) -> Finding {
        Finding(
            title: title,
            severity: severity,
            category: .transportSecurity,
            evidence: evidence,
            remediation: remediation,
            host: observation.host,
            port: observation.port
        )
    }
}
