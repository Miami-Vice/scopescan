import Foundation

/// An SSH identification string, e.g. `SSH-2.0-OpenSSH_9.6`.
///
/// Reading the banner needs no credentials and no key exchange: the server
/// announces itself before any authentication takes place.
public struct SSHBanner: Equatable, Sendable {
    public let protocolVersion: String
    public let software: String

    public var summary: String { "SSH \(protocolVersion), \(software)" }
}

public enum SSHBannerParser {
    /// RFC 4253 caps the identification line at 255 bytes including CRLF.
    public static let maximumLength = 255

    /// Parses the first line of bytes received from an SSH server. Returns nil
    /// for anything that is not an SSH identification string.
    public static func parse(_ bytes: [UInt8]) -> SSHBanner? {
        let window = bytes.prefix(maximumLength)
        guard let newline = window.firstIndex(of: 0x0A) else { return nil }

        var line = Array(window[..<newline])
        if line.last == 0x0D { line.removeLast() }
        guard line.allSatisfy(isPrintableASCII) else { return nil }

        let text = String(decoding: line, as: UTF8.self)
        guard text.hasPrefix("SSH-") else { return nil }

        // SSH-protoversion-softwareversion [SP comments]
        let parts = text.split(separator: "-", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count == 3 else { return nil }

        let protocolVersion = String(parts[1])
        let software = String(parts[2])
        guard !protocolVersion.isEmpty, !software.isEmpty else { return nil }

        return SSHBanner(protocolVersion: protocolVersion, software: software)
    }

    static func isPrintableASCII(_ byte: UInt8) -> Bool {
        byte >= 0x20 && byte < 0x7F
    }
}
