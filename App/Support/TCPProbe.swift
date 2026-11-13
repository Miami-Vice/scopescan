import Foundation
import Network

/// A single TCP connect attempt.
///
/// A connect attempt is the only reachability primitive iOS grants an
/// unprivileged app: no ICMP, no raw sockets, no SYN scanning. Everything the
/// scanner reports has to be built on this.
enum TCPProbe {
    /// One connect attempt, classified for the scanner. Cancelling the calling
    /// task cancels the connection and resolves to `.cancelled`.
    static func outcome(host: String, port: UInt16, timeout: TimeInterval = 1.5) async -> PortOutcome {
        let resumeOnce = ResumeOnce()
        let connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port) ?? .http,
            using: .tcp
        )

        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<PortOutcome, Never>) in
                let queue = DispatchQueue(label: "dev.scopescan.port-probe")

                func finish(_ outcome: PortOutcome) {
                    guard resumeOnce.claim() else { return }
                    continuation.resume(returning: outcome)
                    connection.cancel()
                }

                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        finish(.open)
                    case .waiting(let error):
                        finish(classify(error, waiting: true))
                    case .failed(let error):
                        finish(classify(error, waiting: false))
                    case .cancelled:
                        finish(.cancelled)
                    default:
                        break
                    }
                }

                connection.start(queue: queue)

                queue.asyncAfter(deadline: .now() + timeout) {
                    finish(.timedOut)
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }

    /// Maps the POSIX and DNS errors Network.framework reports onto outcomes.
    /// A refused connection is the host answering, so it is not a failure.
    private static func classify(_ error: NWError, waiting: Bool) -> PortOutcome {
        if case .posix(let code) = error {
            switch code {
            case .ECONNREFUSED:
                return .closed
            case .EHOSTUNREACH, .ENETUNREACH, .EHOSTDOWN, .ENETDOWN:
                return .unreachable
            case .ETIMEDOUT:
                return .timedOut
            case .EPERM, .EACCES:
                return .denied
            default:
                break
            }
        }
        // Waiting usually means no route yet, or the Local Network prompt is
        // unanswered. Report it as unreachable rather than guessing denial.
        return waiting ? .unreachable : .failed(error.localizedDescription)
    }

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
