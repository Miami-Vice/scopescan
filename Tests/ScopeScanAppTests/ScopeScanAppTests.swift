import XCTest
import ScopeScanCore
@testable import ScopeScan

final class ScopeScanAppTests: XCTestCase {
    /// Proves the app target links the core package and that a scope survives
    /// the trip through the module boundary.
    func testAppTargetLinksCore() throws {
        XCTAssertFalse(CoreInfo.version.isEmpty)

        let scope = try ScanScope(cidr: "192.168.1.0/24")
        XCTAssertEqual(scope.hostCount, 254)
    }
}
