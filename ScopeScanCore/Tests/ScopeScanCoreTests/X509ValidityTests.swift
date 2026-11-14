import XCTest
@testable import ScopeScanCore

final class X509ValidityTests: XCTestCase {
    private func tlv(_ tag: UInt8, _ body: [UInt8]) -> [UInt8] {
        if body.count < 0x80 {
            return [tag, UInt8(body.count)] + body
        }
        precondition(body.count <= 0xFF, "test helper only builds short bodies")
        return [tag, 0x81, UInt8(body.count)] + body
    }

    private func text(_ string: String) -> [UInt8] {
        Array(string.utf8)
    }

    /// A certificate with the fields that precede validity, then the validity
    /// SEQUENCE, then a placeholder subject.
    private func certificate(
        notBefore: [UInt8],
        notAfter: [UInt8],
        version: Bool = true
    ) -> [UInt8] {
        var tbs: [UInt8] = []
        if version {
            tbs += tlv(0xA0, tlv(0x02, [0x02]))
        }
        tbs += tlv(0x02, [0x01])                       // serial number
        tbs += tlv(0x30, [])                           // signature algorithm
        tbs += tlv(0x30, [])                           // issuer
        tbs += tlv(0x30, tlv(notBefore[0], Array(notBefore[1...])) + tlv(notAfter[0], Array(notAfter[1...])))
        tbs += tlv(0x30, [])                           // subject
        return tlv(0x30, tlv(0x30, tbs) + tlv(0x30, []))
    }

    private func utc(_ string: String) -> [UInt8] {
        [0x17] + text(string)
    }

    private func generalized(_ string: String) -> [UInt8] {
        [0x18] + text(string)
    }

    private func date(_ year: Int, _ month: Int, _ day: Int, _ hour: Int, _ minute: Int, _ second: Int) -> Date {
        var components = DateComponents(year: year, month: month, day: day, hour: hour, minute: minute, second: second)
        components.timeZone = TimeZone(identifier: "UTC")
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar.date(from: components)!
    }

    func testReadsUTCTimeNotAfter() {
        let der = certificate(
            notBefore: utc("240101000000Z"),
            notAfter: utc("261231235959Z")
        )
        XCTAssertEqual(X509Validity.notAfter(certificateDER: der), date(2026, 12, 31, 23, 59, 59))
    }

    func testReadsGeneralizedTimeNotAfter() {
        let der = certificate(
            notBefore: utc("240101000000Z"),
            notAfter: generalized("20991231235959Z")
        )
        XCTAssertEqual(X509Validity.notAfter(certificateDER: der), date(2099, 12, 31, 23, 59, 59))
    }

    func testUTCTimeYearPivotAt50() {
        let past = certificate(notBefore: utc("000101000000Z"), notAfter: utc("491231000000Z"))
        XCTAssertEqual(X509Validity.notAfter(certificateDER: past), date(2049, 12, 31, 0, 0, 0))

        let older = certificate(notBefore: utc("000101000000Z"), notAfter: utc("500101000000Z"))
        XCTAssertEqual(X509Validity.notAfter(certificateDER: older), date(1950, 1, 1, 0, 0, 0))
    }

    func testWorksWithoutVersionField() {
        let der = certificate(
            notBefore: utc("240101000000Z"),
            notAfter: utc("270101000000Z"),
            version: false
        )
        XCTAssertEqual(X509Validity.notAfter(certificateDER: der), date(2027, 1, 1, 0, 0, 0))
    }

    func testRejectsNonSequence() {
        XCTAssertNil(X509Validity.notAfter(certificateDER: [0x02, 0x01, 0x05]))
        XCTAssertNil(X509Validity.notAfter(certificateDER: []))
    }

    func testRejectsTruncatedCertificate() {
        let der = certificate(notBefore: utc("240101000000Z"), notAfter: utc("261231235959Z"))
        for length in stride(from: 0, to: der.count, by: 7) {
            XCTAssertNil(X509Validity.notAfter(certificateDER: Array(der.prefix(length))), "length \(length)")
        }
    }

    func testRejectsMalformedTime() {
        XCTAssertNil(X509Validity.notAfter(certificateDER: certificate(
            notBefore: utc("240101000000Z"),
            notAfter: utc("26123123595ZZ")
        )))
        XCTAssertNil(X509Validity.notAfter(certificateDER: certificate(
            notBefore: utc("240101000000Z"),
            notAfter: utc("261331235959Z")
        )))
        XCTAssertNil(X509Validity.notAfter(certificateDER: certificate(
            notBefore: utc("240101000000Z"),
            notAfter: utc("2612AB235959Z")
        )))
    }

    func testRejectsIndefiniteLength() {
        var reader = DERReader([0x30, 0x80, 0x00, 0x00][...])
        XCTAssertNil(reader.next())
    }
}
