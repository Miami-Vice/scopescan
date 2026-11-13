import Foundation
import Network

/// A single TCP connect attempt.
///
/// A connect attempt is the only reachability primitive iOS grants an
/// unprivileged app: no ICMP, no raw sockets, no SYN scanning. Everything the
/// scanner reports has to be built on this.
enum TCPProbe {
    /// Performs one connect attempt and describes the outcome in a form that is
    /// safe to show a user and useful to paste into a bug report.
    static func connect(host: String, port: UInt16, timeout: TimeInterval = 2.0) async -> String {
        let resumeOnce = ResumeOnce()

        return await withCheckedContinuation { (continuation: CheckedContinuation<String, Never>) in
            let queue = DispatchQueue(label: "dev.scopescan.tcp-probe")
            let connection = NWConnection(
                host: NWEndpoint.Host(host),
                port: NWEndpoint.Port(rawValue: port) ?? .http,
                using: .tcp
            )

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if resumeOnce.claim() {
                        continuation.resume(returning: "connected")
                        connection.cancel()
                    }
                case .waiting(let error):
                    // On iOS this usually means the Local Network permission was denied.
                    if resumeOnce.claim() {
                        continuation.resume(returning: "waiting: \(error.localizedDescription)")
                        connection.cancel()
                    }
                case .failed(let error):
                    if resumeOnce.claim() {
                        continuation.resume(returning: "failed: \(error.localizedDescription)")
                    }
                case .cancelled:
                    if resumeOnce.claim() {
                        continuation.resume(returning: "cancelled")
                    }
                default:
                    break
                }
            }

            connection.start(queue: queue)

            queue.asyncAfter(deadline: .now() + timeout) {
                if resumeOnce.claim() {
                    continuation.resume(returning: "timeout after \(timeout)s")
                    connection.cancel()
                }
            }
        }
    }
}

/// `NWConnection` can report several terminal states in quick succession, and a
/// `CheckedContinuation` traps if resumed twice.
final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var resumed = false

    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !resumed else { return false }
        resumed = true
        return true
    }
}
