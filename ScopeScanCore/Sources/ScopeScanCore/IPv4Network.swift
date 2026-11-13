import Foundation

/// An IPv4 CIDR block. The stored address is not required to be the network
/// address; `networkAddress` masks it down.
public struct IPv4Network: Hashable, Sendable, CustomStringConvertible {
    public let address: IPv4Address
    public let prefixLength: Int

    public init?(address: IPv4Address, prefixLength: Int) {
        guard (0...32).contains(prefixLength) else { return nil }
        self.address = address
        self.prefixLength = prefixLength
    }

    /// Parses "192.168.1.0/24".
    public init?(cidr: String) {
        let parts = cidr.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let address = IPv4Address(String(parts[0])),
              let prefix = Int(parts[1]),
              (0...32).contains(prefix)
        else {
            return nil
        }
        self.init(address: address, prefixLength: prefix)
    }

    public var mask: UInt32 {
        prefixLength == 0 ? 0 : UInt32.max << UInt32(32 - prefixLength)
    }

    public var networkAddress: IPv4Address {
        IPv4Address(rawValue: address.rawValue & mask)
    }

    public var broadcastAddress: IPv4Address {
        IPv4Address(rawValue: networkAddress.rawValue | ~mask)
    }

    /// Number of assignable hosts, accounting for the /31 and /32 edge cases
    /// (RFC 3021 point-to-point links).
    public var hostCount: Int {
        switch prefixLength {
        case 32: return 1
        case 31: return 2
        default: return Int(broadcastAddress.rawValue - networkAddress.rawValue - 1)
        }
    }

    public func contains(_ host: IPv4Address) -> Bool {
        (host.rawValue & mask) == networkAddress.rawValue
    }

    /// Every assignable host in the network, excluding network and broadcast
    /// addresses. Allocates; callers should bound the prefix first.
    public func hostAddresses() -> [IPv4Address] {
        switch prefixLength {
        case 32:
            return [networkAddress]
        case 31:
            return [networkAddress, broadcastAddress]
        default:
            let first = networkAddress.rawValue &+ 1
            let last = broadcastAddress.rawValue &- 1
            guard last >= first else { return [] }
            return (first...last).map { IPv4Address(rawValue: $0) }
        }
    }

    public var description: String {
        "\(networkAddress)/\(prefixLength)"
    }
}
