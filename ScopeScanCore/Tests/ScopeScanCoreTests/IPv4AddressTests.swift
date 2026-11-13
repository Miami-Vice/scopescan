import XCTest
@testable import ScopeScanCore

final class IPv4AddressTests: XCTestCase {
    func testParsesDottedQuad() throws {
        let address = try XCTUnwrap(IPv4Address("192.168.1.37"))
        XCTAssertEqual(address.rawValue, 0xC0A80125)
        XCTAssertEqual(address.description, "192.168.1.37")
    }

    func testRejectsMalformedInput() {
        let invalid = [
            "",
            "192.168.1",
            "192.168.1.1.1",
            "256.1.1.1",
            "a.b.c.d",
            "+1.2.3.4",
            "-1.2.3.4",
            "1.2.3.",
            ".1.2.3",
            "1.2.3.4 ",
            " 1.2.3.4",
            "0x1.2.3.4",
            "0001.2.3.4",
            "1..3.4"
        ]
        for text in invalid {
            XCTAssertNil(IPv4Address(text), "expected \(text.debugDescription) to be rejected")
        }
    }

    func testBoundaryAddresses() throws {
        XCTAssertEqual(try XCTUnwrap(IPv4Address("0.0.0.0")).rawValue, 0)
        XCTAssertEqual(try XCTUnwrap(IPv4Address("255.255.255.255")).rawValue, UInt32.max)
        XCTAssertEqual(try XCTUnwrap(IPv4Address("255.255.255.255")).description, "255.255.255.255")
    }

    func testClassification() throws {
        let privateClassA = try XCTUnwrap(IPv4Address("10.1.2.3"))
        let privateClassB = try XCTUnwrap(IPv4Address("172.16.0.1"))
        let privateClassC = try XCTUnwrap(IPv4Address("192.168.0.1"))
        let publicAddress = try XCTUnwrap(IPv4Address("8.8.8.8"))

        XCTAssertTrue(privateClassA.isPrivate)
        XCTAssertTrue(privateClassB.isPrivate)
        XCTAssertTrue(privateClassC.isPrivate)
        XCTAssertFalse(publicAddress.isPrivate)

        XCTAssertTrue(try XCTUnwrap(IPv4Address("127.0.0.1")).isLoopback)
        XCTAssertTrue(try XCTUnwrap(IPv4Address("169.254.10.10")).isLinkLocal)
        XCTAssertTrue(try XCTUnwrap(IPv4Address("224.0.0.251")).isMulticast)
        XCTAssertTrue(try XCTUnwrap(IPv4Address("240.0.0.1")).isReserved)
        XCTAssertTrue(try XCTUnwrap(IPv4Address("0.0.0.0")).isUnspecifiedOrThisNetwork)
    }

    func testOrdering() throws {
        let first = try XCTUnwrap(IPv4Address("10.0.0.1"))
        let second = try XCTUnwrap(IPv4Address("10.0.0.2"))
        let third = try XCTUnwrap(IPv4Address("10.0.1.0"))

        XCTAssertLessThan(first, second)
        XCTAssertLessThan(second, third)
        XCTAssertEqual([third, first, second].sorted(), [first, second, third])
    }

    func testAddingClampsAtOverflow() throws {
        let address = try XCTUnwrap(IPv4Address("255.255.255.255"))
        XCTAssertNil(address.adding(1))

        let base = try XCTUnwrap(IPv4Address("192.168.1.254"))
        XCTAssertEqual(base.adding(1)?.description, "192.168.1.255")
    }

    func testCodableUsesStringRepresentation() throws {
        let address = try XCTUnwrap(IPv4Address("192.168.1.37"))
        let data = try JSONEncoder().encode(address)
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "\"192.168.1.37\"")
        XCTAssertEqual(try JSONDecoder().decode(IPv4Address.self, from: data), address)
    }
}
