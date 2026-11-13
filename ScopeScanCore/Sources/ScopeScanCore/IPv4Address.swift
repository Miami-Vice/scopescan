import Foundation

/// A 32-bit IPv4 address stored in host byte order.
public struct IPv4Address: Hashable, Comparable, Codable, Sendable, CustomStringConvertible {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// Parses dotted-quad notation. Rejects anything a user is likely to have
    /// meant as something else: leading signs, whitespace, hex, wrong arity.
    public init?(_ string: String) {
        let parts = string.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }

        var value: UInt32 = 0
        for part in parts {
            guard (1...3).contains(part.count),
                  part.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let octet = UInt8(part)
            else {
                return nil
            }
            value = (value << 8) | UInt32(octet)
        }
        self.rawValue = value
    }

    public var description: String {
        let octets = [24, 16, 8, 0].map { shift in
            String((rawValue >> UInt32(shift)) & 0xFF)
        }
        return octets.joined(separator: ".")
    }

    public static func < (lhs: IPv4Address, rhs: IPv4Address) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    /// Returns nil when the addition would overflow the address space.
    public func adding(_ offset: UInt32) -> IPv4Address? {
        let (sum, overflow) = rawValue.addingReportingOverflow(offset)
        return overflow ? nil : IPv4Address(rawValue: sum)
    }

    public var firstOctet: UInt8 { UInt8(rawValue >> 24) }

    public var isUnspecifiedOrThisNetwork: Bool { firstOctet == 0 }
    public var isLoopback: Bool { firstOctet == 127 }
    public var isLinkLocal: Bool {
        firstOctet == 169 && UInt8((rawValue >> 16) & 0xFF) == 254
    }
    public var isMulticast: Bool { (UInt8(224)...UInt8(239)).contains(firstOctet) }
    public var isReserved: Bool { firstOctet >= 240 }

    public var isPrivate: Bool {
        switch (firstOctet, UInt8((rawValue >> 16) & 0xFF)) {
        case (10, _):
            return true
        case (172, 16...31):
            return true
        case (192, 168):
            return true
        default:
            return false
        }
    }

    // MARK: - Codable

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)
        guard let parsed = IPv4Address(text) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Not a valid IPv4 address: \(text)"
            )
        }
        self = parsed
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}
