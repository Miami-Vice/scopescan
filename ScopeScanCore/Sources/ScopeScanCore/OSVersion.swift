import Foundation

/// A semantic iOS version, e.g. `27.0.1`.
///
/// Kept separate from `OperatingSystemVersion` so the posture rules stay
/// platform-free and testable off-device.
public struct OSVersion: Hashable, Comparable, Codable, Sendable, CustomStringConvertible {
    public let major: Int
    public let minor: Int
    public let patch: Int

    public init(_ major: Int, _ minor: Int = 0, _ patch: Int = 0) {
        self.major = major
        self.minor = minor
        self.patch = patch
    }

    /// Parses "27.0.1" or "18.4". Rejects anything with non-numeric segments.
    public init?(string: String) {
        let parts = string.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...3).contains(parts.count) else { return nil }

        var numbers: [Int] = []
        for part in parts {
            guard part.allSatisfy({ $0.isASCII && $0.isNumber }), let value = Int(part) else {
                return nil
            }
            numbers.append(value)
        }

        self.init(
            numbers[0],
            numbers.count > 1 ? numbers[1] : 0,
            numbers.count > 2 ? numbers[2] : 0
        )
    }

    public var description: String { "\(major).\(minor).\(patch)" }

    public static func < (lhs: OSVersion, rhs: OSVersion) -> Bool {
        if lhs.major != rhs.major { return lhs.major < rhs.major }
        if lhs.minor != rhs.minor { return lhs.minor < rhs.minor }
        return lhs.patch < rhs.patch
    }

    /// How many major releases behind the reference version this is. Never negative.
    public func majorReleasesBehind(_ reference: OSVersion) -> Int {
        max(0, reference.major - major)
    }
}
