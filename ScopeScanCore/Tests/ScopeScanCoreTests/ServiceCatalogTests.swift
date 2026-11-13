import XCTest
@testable import ScopeScanCore

final class ServiceCatalogTests: XCTestCase {
    func testInventoryStartsWithDiscoveryPorts() {
        XCTAssertEqual(Array(ServiceCatalog.inventoryPorts.prefix(ServiceCatalog.discoveryPorts.count)),
                       ServiceCatalog.discoveryPorts)
    }

    func testInventoryHasNoDuplicates() {
        let ports = ServiceCatalog.inventoryPorts
        XCTAssertEqual(ports.count, Set(ports).count)
    }

    func testEveryDiscoveryPortIsDescribed() {
        for port in ServiceCatalog.discoveryPorts {
            XCTAssertNotNil(ServiceCatalog.service(for: port), "no definition for discovery port \(port)")
        }
    }

    func testEveryServiceIsInTheInventory() {
        let inventory = Set(ServiceCatalog.inventoryPorts)
        for service in ServiceCatalog.services {
            XCTAssertTrue(inventory.contains(service.port), "\(service.name) is missing from the inventory")
        }
    }

    func testPortsAreInRange() {
        XCTAssertTrue(ServiceCatalog.inventoryPorts.allSatisfy { $0 > 0 })
        XCTAssertLessThanOrEqual(ServiceCatalog.inventoryPorts.count, 32)
    }

    func testNamesForKnownAndUnknownPorts() {
        XCTAssertEqual(ServiceCatalog.name(for: 445), "SMB file sharing")
        XCTAssertEqual(ServiceCatalog.name(for: 65000), "port 65000")
        XCTAssertNil(ServiceCatalog.service(for: 65000))
    }

    func testRiskyServicesCarryRemediation() {
        for service in ServiceCatalog.services where service.severity != nil {
            XCTAssertFalse(service.remediation.isEmpty, "\(service.name) has a severity but no remediation")
        }
    }
}
