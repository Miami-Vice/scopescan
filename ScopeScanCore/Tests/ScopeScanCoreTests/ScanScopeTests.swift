import XCTest
@testable import ScopeScanCore

final class ScanScopeTests: XCTestCase {
    func testAcceptsHomeNetwork() throws {
        let scope = try ScanScope(cidr: "192.168.1.0/24")
        XCTAssertEqual(scope.hostCount, 254)
        XCTAssertEqual(scope.cidr, "192.168.1.0/24")
        XCTAssertEqual(scope.hosts.first?.description, "192.168.1.1")
        XCTAssertEqual(scope.hosts.last?.description, "192.168.1.254")
    }

    func testRefusesNetworkLargerThanCap() {
        XCTAssertThrowsError(try ScanScope(cidr: "10.0.0.0/16")) { error in
            XCTAssertEqual(
                error as? ScopeError,
                .prefixTooLarge(prefixLength: 16, minimumPrefixLength: ScanScope.minimumPrefixLength)
            )
        }
    }

    func testAcceptsLargestPermittedNetwork() throws {
        let scope = try ScanScope(cidr: "10.0.0.0/22")
        XCTAssertEqual(scope.hostCount, 1022)
        XCTAssertLessThanOrEqual(scope.hostCount, ScanScope.maximumHostCount)
    }

    func testRefusesUnusableNetworks() {
        let unusable = [
            "127.0.0.0/24",   // loopback
            "169.254.0.0/24", // link-local
            "224.0.0.0/24",   // multicast
            "240.0.0.0/24",   // reserved
            "0.0.0.0/24"      // this-network
        ]
        for cidr in unusable {
            XCTAssertThrowsError(try ScanScope(cidr: cidr), "expected \(cidr) to be refused")
        }
    }

    func testRefusesMalformedInput() {
        XCTAssertThrowsError(try ScanScope(cidr: "hello")) { error in
            XCTAssertEqual(error as? ScopeError, .malformedCIDR("hello"))
        }
    }

    func testDerivesScopeFromHostAddress() throws {
        let host = try XCTUnwrap(IPv4Address("192.168.4.83"))
        let scope = try ScanScope(hostAddress: host)
        XCTAssertEqual(scope.cidr, "192.168.4.0/24")
        XCTAssertTrue(scope.hosts.contains(host))
    }

    func testErrorMessagesAreHumanReadable() {
        XCTAssertNotNil(ScopeError.malformedCIDR("nope").errorDescription)
        XCTAssertNotNil(
            ScopeError.prefixTooLarge(prefixLength: 8, minimumPrefixLength: 22).errorDescription
        )
        XCTAssertNotNil(ScopeError.unusableNetwork("127.0.0.0/24").errorDescription)
    }
}
