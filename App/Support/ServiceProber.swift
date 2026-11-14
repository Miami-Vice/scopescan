import Foundation
import Network
import Security
import ScopeScanCore

/// Reads what an open port says about itself: an SSH identification line, an
/// HTTP response head, or the TLS handshake and certificate.
///
/// Each read is one bounded exchange. Nothing is logged in, nothing is sent
/// beyond a HEAD request, and every read stops at a size or time limit.
enum ServiceProber {
    struct Outcome: Sendable {
        let address: IPv4Address
        let port: UInt16
        let detail: String?
        let tls: TLSObservation?
    }

    static let sshPorts: Set<UInt16> = [22]
    static let httpPorts: Set<UInt16> = [80, 5000, 8080]
    static let tlsPorts: Set<UInt16> = [443, 8443]

    static func handles(_ port: UInt16) -> Bool {
        sshPorts.contains(port) || httpPorts.contains(port) || tlsPorts.contains(port)
    }

    static func probe(_ address: IPv4Address, port: UInt16, timeout: TimeInterval = 4) async -> Outcome {
        let host = address.description

        if sshPorts.contains(port) {
            let bytes = await exchange(host: host, port: port, limit: 255, timeout: timeout, request: []) { buffer in
                buffer.contains(0x0A)
            }
            let detail = bytes.flatMap { SSHBannerParser.parse($0)?.summary }
            return Outcome(address: address, port: port, detail: detail, tls: nil)
        }

        if httpPorts.contains(port) {
            let request = Array("HEAD / HTTP/1.0\r\nHost: \(host)\r\nUser-Agent: ScopeScan\r\nConnection: close\r\n\r\n".utf8)
            let bytes = await exchange(
                host: host,
                port: port,
                limit: HTTPResponseParser.maximumHeadLength,
                timeout: timeout,
                request: request
            ) { buffer in
                containsHeaderEnd(buffer)
            }
            let detail = bytes.flatMap { HTTPResponseParser.parse($0)?.summary }
            return Outcome(address: address, port: port, detail: detail, tls: nil)
        }

        if tlsPorts.contains(port) {
            let observation = await observeTLS(host: host, port: port, timeout: timeout)
            return Outcome(address: address, port: port, detail: observation?.version.displayName, tls: observation)
        }

        return Outcome(address: address, port: port, detail: nil, tls: nil)
    }

    // MARK: - Plain exchange

    /// Sends an optional request and reads until `stop` says the buffer is
    /// enough, the peer closes, the limit is reached, or the deadline passes.
    /// Whatever arrived is returned; nil means nothing arrived at all.
    private static func exchange(
        host: String,
        port: UInt16,
        limit: Int,
        timeout: TimeInterval,
        request: [UInt8],
        stop: @escaping @Sendable ([UInt8]) -> Bool
    ) async -> [UInt8]? {
        let queue = DispatchQueue(label: "dev.scopescan.service-exchange")
        let connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port) ?? .http,
            using: .tcp
        )
        let buffer = ByteBuffer()

        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<[UInt8]?, Never>) in
                let once = ResumeOnce()

                func finish() {
                    guard once.claim() else { return }
                    connection.cancel()
                    let bytes = buffer.bytes(limit: limit)
                    continuation.resume(returning: bytes.isEmpty ? nil : bytes)
                }

                func receiveNext() {
                    connection.receive(minimumIncompleteLength: 1, maximumLength: limit) { data, _, isComplete, error in
                        if let data { buffer.append(data) }
                        if isComplete || error != nil || buffer.count >= limit || stop(buffer.bytes(limit: limit)) {
                            finish()
                        } else {
                            receiveNext()
                        }
                    }
                }

                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        if !request.isEmpty {
                            connection.send(content: Data(request), completion: .contentProcessed { _ in })
                        }
                        receiveNext()
                    case .failed, .cancelled:
                        finish()
                    default:
                        break
                    }
                }

                connection.start(queue: queue)
                queue.asyncAfter(deadline: .now() + timeout) { finish() }
            }
        } onCancel: {
            connection.cancel()
        }
    }

    private static func containsHeaderEnd(_ bytes: [UInt8]) -> Bool {
        guard bytes.count >= 4 else { return false }
        for index in 0...(bytes.count - 4) where bytes[index] == 0x0D
            && bytes[index + 1] == 0x0A
            && bytes[index + 2] == 0x0D
            && bytes[index + 3] == 0x0A {
            return true
        }
        return false
    }

    // MARK: - TLS

    /// Completes a handshake that accepts any certificate, so an untrusted or
    /// expired certificate can still be observed and reported. The trust
    /// decision is recorded, not enforced.
    private static func observeTLS(host: String, port: UInt16, timeout: TimeInterval) async -> TLSObservation? {
        let capture = TLSCapture()
        let tlsOptions = NWProtocolTLS.Options()
        let security = tlsOptions.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(security, .TLSv10)
        sec_protocol_options_set_verify_block(
            security,
            { _, trust, complete in
                let secTrust = sec_trust_copy_ref(trust)
                let trusted = SecTrustEvaluateWithError(secTrust, nil)
                capture.record(secTrust, trusted: trusted)
                complete(true)
            },
            DispatchQueue(label: "dev.scopescan.tls-verify")
        )

        let connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port) ?? .https,
            using: NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        )
        let queue = DispatchQueue(label: "dev.scopescan.tls-probe")

        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<TLSObservation?, Never>) in
                let once = ResumeOnce()

                func finish() {
                    guard once.claim() else { return }
                    let metadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata
                    let observation = metadata.flatMap { metadata in
                        makeObservation(
                            host: host,
                            port: port,
                            negotiated: sec_protocol_metadata_get_negotiated_tls_protocol_version(
                                metadata.securityProtocolMetadata
                            ),
                            capture: capture
                        )
                    }
                    connection.cancel()
                    continuation.resume(returning: observation)
                }

                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready, .failed, .cancelled:
                        finish()
                    default:
                        break
                    }
                }

                connection.start(queue: queue)
                queue.asyncAfter(deadline: .now() + timeout) { finish() }
            }
        } onCancel: {
            connection.cancel()
        }
    }

    private static func makeObservation(
        host: String,
        port: UInt16,
        negotiated: tls_protocol_version_t,
        capture: TLSCapture
    ) -> TLSObservation? {
        guard let trust = capture.trust else { return nil }

        let leaf = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first
        let der = leaf.map { [UInt8](SecCertificateCopyData($0) as Data) }

        var algorithm = KeyAlgorithm.unknown
        var keyBits: Int?
        if let leaf, let key = SecCertificateCopyKey(leaf),
           let attributes = SecKeyCopyAttributes(key) as? [String: Any] {
            keyBits = attributes[kSecAttrKeySizeInBits as String] as? Int
            switch attributes[kSecAttrKeyType as String] as? String {
            case kSecAttrKeyTypeRSA as String:
                algorithm = .rsa
            case kSecAttrKeyTypeECSECPrimeRandom as String:
                algorithm = .ellipticCurve
            default:
                break
            }
        }

        return TLSObservation(
            host: host,
            port: port,
            version: version(of: negotiated),
            leafNotAfter: der.flatMap { X509Validity.notAfter(certificateDER: $0) },
            leafKeyAlgorithm: algorithm,
            leafKeyBits: keyBits,
            leafSubject: leaf.flatMap { SecCertificateCopySubjectSummary($0) as String? },
            chainTrusted: capture.trusted
        )
    }

    private static func version(of negotiated: tls_protocol_version_t) -> TLSVersion {
        switch negotiated {
        case .TLSv10: return .tls10
        case .TLSv11: return .tls11
        case .TLSv12: return .tls12
        case .TLSv13: return .tls13
        default: return .unknown
        }
    }
}

/// Bytes received so far. Written on the connection queue, read from the
/// continuation, so access is guarded.
private final class ByteBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [UInt8] = []

    func append(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        storage.append(contentsOf: data)
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return storage.count
    }

    func bytes(limit: Int) -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        return Array(storage.prefix(limit))
    }
}

/// The trust evaluation the verify block recorded during the handshake.
private final class TLSCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var storedTrust: SecTrust?
    private var storedTrusted = false

    func record(_ trust: SecTrust, trusted: Bool) {
        lock.lock()
        defer { lock.unlock() }
        storedTrust = trust
        storedTrusted = trusted
    }

    var trust: SecTrust? {
        lock.lock()
        defer { lock.unlock() }
        return storedTrust
    }

    var trusted: Bool {
        lock.lock()
        defer { lock.unlock() }
        return storedTrusted
    }
}
