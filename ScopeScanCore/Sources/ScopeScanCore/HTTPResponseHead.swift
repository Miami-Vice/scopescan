import Foundation

/// The status line and `Server` header of an HTTP response.
///
/// Only the head is read. The body is never parsed or stored.
public struct HTTPResponseHead: Equatable, Sendable {
    public let statusCode: Int
    public let reason: String
    public let server: String?

    public var summary: String {
        let base = "HTTP \(statusCode)"
        guard let server else { return base }
        return "\(base), Server: \(server)"
    }
}

public enum HTTPResponseParser {
    /// Headers beyond this are ignored. A real response head is far smaller,
    /// and an unbounded read would let a hostile server tie up the scanner.
    public static let maximumHeadLength = 8192
    /// Longest header value kept for display.
    public static let maximumValueLength = 128

    public static func parse(_ bytes: [UInt8]) -> HTTPResponseHead? {
        let window = Array(bytes.prefix(maximumHeadLength))
        let head = endOfHead(in: window).map { Array(window[..<$0]) } ?? window

        let lines = splitLines(head)
        guard let statusLine = lines.first, statusLine.allSatisfy(isPrintableASCII) else { return nil }

        let status = String(decoding: statusLine, as: UTF8.self).split(separator: " ", maxSplits: 2)
        guard status.count >= 2,
              status[0].hasPrefix("HTTP/1."),
              let code = Int(status[1]),
              (100...599).contains(code)
        else {
            return nil
        }
        let reason = status.count == 3 ? String(status[2]) : ""

        var server: String?
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: 0x3A) else { continue }
            let name = String(decoding: line[..<colon], as: UTF8.self)
            guard name.lowercased() == "server" else { continue }

            let value = String(decoding: line[(colon + 1)...], as: UTF8.self)
                .trimmingCharacters(in: .whitespaces)
            guard !value.isEmpty, value.allSatisfy(\.isASCII) else { continue }
            server = String(value.prefix(maximumValueLength))
            break
        }

        return HTTPResponseHead(statusCode: code, reason: reason, server: server)
    }

    private static func endOfHead(in bytes: [UInt8]) -> Int? {
        guard bytes.count >= 4 else { return nil }
        for index in 0...(bytes.count - 4) where bytes[index] == 0x0D
            && bytes[index + 1] == 0x0A
            && bytes[index + 2] == 0x0D
            && bytes[index + 3] == 0x0A {
            return index
        }
        return nil
    }

    private static func splitLines(_ bytes: [UInt8]) -> [[UInt8]] {
        var lines: [[UInt8]] = []
        var current: [UInt8] = []
        for byte in bytes {
            if byte == 0x0A {
                if current.last == 0x0D { current.removeLast() }
                lines.append(current)
                current = []
            } else {
                current.append(byte)
            }
        }
        if !current.isEmpty { lines.append(current) }
        return lines
    }

    private static func isPrintableASCII(_ byte: UInt8) -> Bool {
        byte >= 0x20 && byte < 0x7F
    }
}
