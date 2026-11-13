import XCTest
@testable import ScopeScanCore

final class IPv4NetworkTests: XCTestCase {
    func testParsesCIDR() throws {
        let network = try XCTUnwrap(IPv4Network(cidr: "192.168.1.0/24"))
        XCTAssertEqual(network.prefixLength, 24)
        XCTAssertEqual(network.networkAddress.description, "192.168.1.0")
        XCTAssertEqual(network.broadcastAddress.description, "192.168.1.255")
        XCTAssertEqual(network.hostCount, 254)
        XCTAssertEqual(network.description, "192.168.1.0/24")
    }

    func testMasksHostBitsFromAddress() throws {
        // A host address inside the block still yields the network base.
        let network = try XCTUnwrap(IPv4Network(cidr: "192.168.1.37/24"))
        XCTAssertEqual(network.networkAddress.description, "192.168.1.0")
    }

    func testRejectsInvalidCIDR() {
        let invalid = [
            "192.168.1.0",
            "192.168.1.0/33",
            "192.168.1.0/-1",
            "192.168.1.0/abc",
            "192.168.1.0/24/8",
            "not a cidr/24"
        ]
        for text in invalid {
            XCTAssertNil(IPv4Network(cidr: text), "expected \(text.debugDescription) to be rejected")
        }
    }

    func testSlashThirtyOneAndThirtyTwo() throws {
        let pointToPoint = try XCTUnwrap(IPv4Network(cidr: "10.0.0.0/31"))
        XCTAssertEqual(pointToPoint.hostCount, 2)
        XCTAssertEqual(pointToPoint.hostAddresses().map(\.description), ["10.0.0.0", "10.0.0.1"])

        let single = try XCTUnwrap(IPv4Network(cidr: "10.0.0.7/32"))
        XCTAssertEqual(single.hostCount, 1)
        XCTAssertEqual(single.hostAddresses().map(\.description), ["10.0.0.7"])
    }

    func testHostAddressesExcludeNetworkAndBroadcast() throws {
        let network = try XCTUnwrap(IPv4Network(cidr: "10.0.5.0/29"))
        let hosts = network.hostAddresses().map(\.description)
        XCTAssertEqual(hosts, [
            "10.0.5.1", "10.0.5.2", "10.0.5.3", "10.0.5.4",
            "10.0.5.5", "10.0.5.6"
        ])
        XCTAssertEqual(hosts.count, network.hostCount)
    }

    func testContains() throws {
        let network = try XCTUnwrap(IPv4Network(cidr: "172.16.0.0/12"))
        XCTAssertTrue(network.contains(try XCTUnwrap(IPv4Address("172.31.255.254"))))
        XCTAssertFalse(network.contains(try XCTUnwrap(IPv4Address("172.32.0.1"))))
    }

    func testSlashZeroMask() throws {
        let network = try XCTUnwrap(IPv4Network(cidr: "0.0.0.0/0"))
        XCTAssertEqual(network.mask, 0)
        XCTAssertTrue(network.contains(try XCTUnwrap(IPv4Address("8.8.8.8"))))
    }
}
