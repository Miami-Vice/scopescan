import XCTest
@testable import ScopeScanCore

final class FindingTests: XCTestCase {
    private func makeFinding(_ title: String, _ severity: Severity) -> Finding {
        Finding(
            title: title,
            severity: severity,
            category: .transportSecurity,
            evidence: "evidence",
            remediation: "fix it"
        )
    }

    func testSeverityOrdering() {
        XCTAssertLessThan(Severity.info, Severity.low)
        XCTAssertLessThan(Severity.medium, Severity.high)
        XCTAssertLessThan(Severity.high, Severity.critical)
        XCTAssertEqual(Severity.allCases.max(), .critical)
    }

    func testSortsBySeverityThenTitle() {
        let findings = [
            makeFinding("Zeta", .low),
            makeFinding("Alpha", .critical),
            makeFinding("Beta", .medium),
            makeFinding("Gamma", .low)
        ]
        XCTAssertEqual(
            findings.sortedBySeverity().map(\.title),
            ["Alpha", "Beta", "Gamma", "Zeta"]
        )
    }

    func testHighestSeverity() {
        XCTAssertNil([Finding]().highestSeverity)
        XCTAssertEqual(
            [makeFinding("a", .low), makeFinding("b", .high)].highestSeverity,
            .high
        )
    }

    func testCodableRoundTrip() throws {
        let original = Finding(
            title: "TLS 1.0 accepted",
            severity: .high,
            category: .transportSecurity,
            evidence: "Negotiated TLSv1 (0x0301)",
            remediation: "Disable TLS 1.0 on the service.",
            references: [URL(string: "https://example.com/rfc8996")!],
            host: "192.168.1.1",
            port: 443
        )

        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(Finding.self, from: data)
        XCTAssertEqual(decoded, original)
    }
}
