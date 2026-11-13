import Foundation

/// The validated set of hosts a scan is allowed to touch.
///
/// Constructing a `ScanScope` is the enforcement point for the app's
/// authorization model: loopback, link-local, multicast and reserved space are
/// refused, and the size is capped so a typo cannot turn into a /8 sweep.
public struct ScanScope: Hashable, Sendable {
    /// 1024 hosts keeps a full sweep under the watchdog and battery budget.
    public static let maximumHostCount = 1024
    /// Smallest permitted prefix, i.e. the largest permitted network (/22).
    public static let minimumPrefixLength = 22

    public let network: IPv4Network
    public let hosts: [IPv4Address]

    public init(cidr: String) throws {
        guard let network = IPv4Network(cidr: cidr) else {
            throw ScopeError.malformedCIDR(cidr)
        }
        try self.init(network: network)
    }

    public init(network: IPv4Network) throws {
        guard network.prefixLength >= Self.minimumPrefixLength else {
            throw ScopeError.prefixTooLarge(
                prefixLength: network.prefixLength,
                minimumPrefixLength: Self.minimumPrefixLength
            )
        }

        let base = network.networkAddress
        guard !base.isUnspecifiedOrThisNetwork,
              !base.isLoopback,
              !base.isLinkLocal,
              !base.isMulticast,
              !base.isReserved
        else {
            throw ScopeError.unusableNetwork(network.description)
        }

        let hosts = network.hostAddresses()
        guard hosts.count <= Self.maximumHostCount else {
            throw ScopeError.prefixTooLarge(
                prefixLength: network.prefixLength,
                minimumPrefixLength: Self.minimumPrefixLength
            )
        }

        self.network = network
        self.hosts = hosts
    }

    /// Builds a scope around the network this device is currently on.
    /// Defaults to a /24, which is what almost every consumer router hands out.
    public init(hostAddress: IPv4Address, prefixLength: Int = 24) throws {
        guard let network = IPv4Network(address: hostAddress, prefixLength: prefixLength) else {
            throw ScopeError.malformedCIDR("\(hostAddress)/\(prefixLength)")
        }
        try self.init(network: network)
    }

    public var hostCount: Int { hosts.count }
    public var cidr: String { network.description }
}

public enum ScopeError: Error, Equatable, Sendable {
    /// The text was not a CIDR block at all.
    case malformedCIDR(String)
    /// The requested network is bigger than the app is willing to sweep.
    case prefixTooLarge(prefixLength: Int, minimumPrefixLength: Int)
    /// Loopback, link-local, multicast and reserved space are never scanned.
    case unusableNetwork(String)
}

extension ScopeError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .malformedCIDR(let text):
            return "\"\(text)\" is not a valid CIDR block. Try something like 192.168.1.0/24."
        case .prefixTooLarge(let prefix, let minimum):
            return "/\(prefix) is larger than the \(ScanScope.maximumHostCount)-host limit. Use /\(minimum) or smaller."
        case .unusableNetwork(let cidr):
            return "\(cidr) is loopback, link-local, multicast or reserved and will not be scanned."
        }
    }
}
