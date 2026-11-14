import Foundation

/// Reads the validity period from a DER-encoded X.509 certificate.
///
/// iOS does not expose certificate expiry through its public Security APIs,
/// so the date is read straight from the bytes the server sent. Only the
/// fields needed for `notAfter` are decoded; everything else is skipped.
public enum X509Validity {
    /// The `notAfter` time, or nil if the input is not a recognisable certificate.
    public static func notAfter(certificateDER der: [UInt8]) -> Date? {
        var outer = DERReader(der[...])
        guard let certificate = outer.next(), certificate.tag == 0x30 else { return nil }

        var certificateBody = DERReader(certificate.value)
        guard let tbs = certificateBody.next(), tbs.tag == 0x30 else { return nil }

        var fields = DERReader(tbs.value)
        guard var element = fields.next() else { return nil }
        // The version is an optional explicit [0] field before the serial number.
        if element.tag == 0xA0 {
            guard let serial = fields.next() else { return nil }
            element = serial
        }
        // `element` is the serial number. Skip the signature algorithm and issuer.
        guard fields.next() != nil, fields.next() != nil else { return nil }

        guard let validity = fields.next(), validity.tag == 0x30 else { return nil }
        var times = DERReader(validity.value)
        guard times.next() != nil, let notAfterElement = times.next() else { return nil }

        return parseTime(notAfterElement)
    }

    private static func parseTime(_ element: DERElement) -> Date? {
        let text = Array(element.value)
        let utc = TimeZone(identifier: "UTC")!

        var components = DateComponents()
        components.timeZone = utc

        switch element.tag {
        case 0x17:
            // UTCTime: YYMMDDHHMMSSZ. Two-digit years below 50 mean 20YY.
            guard text.count == 13, text[12] == UInt8(ascii: "Z"),
                  let yy = digits(text, 0, 2),
                  let rest = parseRest(text, offset: 2)
            else { return nil }
            components.year = yy < 50 ? 2000 + yy : 1900 + yy
            apply(rest, to: &components)
        case 0x18:
            // GeneralizedTime: YYYYMMDDHHMMSSZ.
            guard text.count == 15, text[14] == UInt8(ascii: "Z"),
                  let year = digits(text, 0, 4),
                  let rest = parseRest(text, offset: 4)
            else { return nil }
            components.year = year
            apply(rest, to: &components)
        default:
            return nil
        }

        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = utc
        return calendar.date(from: components)
    }

    /// Month, day, hour, minute, second read from fixed offsets.
    private struct Rest {
        let month: Int
        let day: Int
        let hour: Int
        let minute: Int
        let second: Int
    }

    private static func parseRest(_ text: [UInt8], offset: Int) -> Rest? {
        guard let month = digits(text, offset, 2),
              let day = digits(text, offset + 2, 2),
              let hour = digits(text, offset + 4, 2),
              let minute = digits(text, offset + 6, 2),
              let second = digits(text, offset + 8, 2),
              (1...12).contains(month),
              (1...31).contains(day),
              hour < 24, minute < 60, second < 61
        else {
            return nil
        }
        return Rest(month: month, day: day, hour: hour, minute: minute, second: second)
    }

    private static func apply(_ rest: Rest, to components: inout DateComponents) {
        components.month = rest.month
        components.day = rest.day
        components.hour = rest.hour
        components.minute = rest.minute
        components.second = rest.second
    }

    private static func digits(_ text: [UInt8], _ offset: Int, _ count: Int) -> Int? {
        guard offset + count <= text.count else { return nil }
        var value = 0
        for byte in text[offset..<(offset + count)] {
            guard byte >= UInt8(ascii: "0"), byte <= UInt8(ascii: "9") else { return nil }
            value = value * 10 + Int(byte - UInt8(ascii: "0"))
        }
        return value
    }
}

/// One tag-length-value element from a DER stream.
struct DERElement {
    let tag: UInt8
    let value: ArraySlice<UInt8>
}

/// Reads successive DER elements. Indefinite lengths are not valid DER and are
/// rejected, as are lengths that run past the end of the input.
struct DERReader {
    private var bytes: ArraySlice<UInt8>

    init(_ bytes: ArraySlice<UInt8>) {
        self.bytes = bytes
    }

    mutating func next() -> DERElement? {
        guard bytes.count >= 2 else { return nil }
        let tag = bytes[bytes.startIndex]
        var index = bytes.startIndex + 1

        let first = bytes[index]
        index += 1

        var length = 0
        if first < 0x80 {
            length = Int(first)
        } else {
            let count = Int(first & 0x7F)
            guard (1...4).contains(count), index + count <= bytes.endIndex else { return nil }
            for _ in 0..<count {
                length = (length << 8) | Int(bytes[index])
                index += 1
            }
        }

        guard length <= bytes.endIndex - index else { return nil }
        let value = bytes[index..<(index + length)]
        bytes = bytes[(index + length)...]
        return DERElement(tag: tag, value: value)
    }
}
