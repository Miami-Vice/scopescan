import Foundation

/// The result of one TCP connect attempt.
///
/// The distinction that matters for scanning is between *no answer* and a
/// *negative answer*: a host that refuses a connection has still proved it is
/// alive, because its TCP stack replied. iOS grants no ICMP and no raw sockets,
/// so a refused connection is the cheapest liveness signal available.
public enum PortOutcome: Sendable, Hashable {
    /// The connection completed. Something is listening.
    case open
    /// The host answered with a reset. It is up; nothing is listening here.
    case closed
    /// The system refused the connection with a permission error, usually the
    /// Local Network permission. The detail records the exact error code.
    case denied(String)
    /// The address or network could not be reached.
    case unreachable
    /// No answer before the deadline.
    case timedOut
    /// The task was cancelled before an answer arrived.
    case cancelled
    /// Any other transport failure, with a description safe to show a user.
    case failed(String)

    /// Whether the probe produced evidence that the host exists.
    public var indicatesHostIsUp: Bool {
        switch self {
        case .open, .closed: return true
        default: return false
        }
    }

    /// Whether the probe was blocked by the Local Network permission rather
    /// than by the network.
    public var isPermissionDenied: Bool {
        if case .denied = self { return true }
        return false
    }

    public var description: String {
        switch self {
        case .open: return "connected"
        case .closed: return "refused (host is up)"
        case .denied(let detail): return "permission error (\(detail))"
        case .unreachable: return "unreachable"
        case .timedOut: return "timed out"
        case .cancelled: return "cancelled"
        case .failed(let detail): return "failed: \(detail)"
        }
    }
}
