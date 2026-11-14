import XCTest
@testable import ScopeScanCore

final class HostLabelTests: XCTestCase {
    func testThisDeviceWinsOverEverything() {
        XCTAssertEqual(HostLabel.describe(openPorts: [80, 445], isGateway: true, isThisDevice: true), "This device")
    }

    func testGatewayIsLabelledRouter() {
        XCTAssertEqual(HostLabel.describe(openPorts: [80], isGateway: true, isThisDevice: false), "Likely router")
    }

    func testFileSharingPortsSuggestWindowsOrNAS() {
        XCTAssertEqual(
            HostLabel.describe(openPorts: [139, 445], isGateway: false, isThisDevice: false),
            "Likely Windows PC or NAS (file sharing)"
        )
    }

    func testPrinterPorts() {
        XCTAssertEqual(HostLabel.describe(openPorts: [631], isGateway: false, isThisDevice: false), "Likely printer")
        XCTAssertEqual(HostLabel.describe(openPorts: [9100], isGateway: false, isThisDevice: false), "Likely printer")
    }

    func testWebOnlyHostIsWebDevice() {
        XCTAssertEqual(HostLabel.describe(openPorts: [443], isGateway: false, isThisDevice: false), "Likely web device")
    }

    func testNoOpenPortsGivesNoLabel() {
        XCTAssertNil(HostLabel.describe(openPorts: [], isGateway: false, isThisDevice: false))
    }

    func testFileSharingOutranksWebPorts() {
        XCTAssertEqual(
            HostLabel.describe(openPorts: [80, 445], isGateway: false, isThisDevice: false),
            "Likely Windows PC or NAS (file sharing)"
        )
    }
}
