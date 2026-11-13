import XCTest
@testable import ScopeScanCore

final class OSVersionTests: XCTestCase {
    func testParsesDotSeparatedVersions() throws {
        let full = try XCTUnwrap(OSVersion(string: "27.0.1"))
        XCTAssertEqual(full.major, 27)
        XCTAssertEqual(full.minor, 0)
        XCTAssertEqual(full.patch, 1)

        let short = try XCTUnwrap(OSVersion(string: "18.4"))
        XCTAssertEqual(short.major, 18)
        XCTAssertEqual(short.minor, 4)
        XCTAssertEqual(short.patch, 0)
    }

    func testRejectsMalformedVersions() {
        for text in ["", "abc", "27.", ".1", "27.0.1.2", "27.x", "27..1", "-27"] {
            XCTAssertNil(OSVersion(string: text), "expected \(text.debugDescription) to be rejected")
        }
    }

    func testOrdering() throws {
        let older = try XCTUnwrap(OSVersion(string: "16.7.2"))
        let newer = try XCTUnwrap(OSVersion(string: "17.0"))
        XCTAssertLessThan(older, newer)
        XCTAssertEqual([newer, older].sorted(), [older, newer])
    }

    func testMajorReleasesBehind() {
        XCTAssertEqual(OSVersion(25, 4).majorReleasesBehind(OSVersion(27, 0)), 2)
        XCTAssertEqual(OSVersion(27, 0).majorReleasesBehind(OSVersion(27, 1)), 0)
        XCTAssertEqual(OSVersion(28, 0).majorReleasesBehind(OSVersion(27, 0)), 0)
    }
}
