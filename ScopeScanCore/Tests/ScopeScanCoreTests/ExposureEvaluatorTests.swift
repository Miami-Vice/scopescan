import XCTest
@testable import ScopeScanCore

final class ExposureEvaluatorTests: XCTestCase {
    private let evaluator = ExposureEvaluator()

    func testOpenAdminServiceBecomesFinding() {
        let findings = evaluator.evaluate([OpenPort(host: "192.168.1.10", port: 23)])

        XCTAssertEqual(findings.count, 1)
        guard let finding = findings.first else { return XCTFail("no finding produced") }
        XCTAssertEqual(finding.severity, .critical)
        XCTAssertEqual(finding.category, .networkExposure)
        XCTAssertEqual(finding.host, "192.168.1.10")
        XCTAssertEqual(finding.port, 23)
        XCTAssertEqual(finding.title, "Telnet is reachable")
        XCTAssertTrue(finding.evidence.contains("port 23"))
        XCTAssertFalse(finding.remediation.isEmpty)
    }

    func testPlainWebPortsAreInventoriedButNotFindings() {
        let findings = evaluator.evaluate([
            OpenPort(host: "192.168.1.10", port: 80),
            OpenPort(host: "192.168.1.11", port: 443)
        ])

        XCTAssertTrue(findings.isEmpty)
    }

    func testDuplicateOpenPortsProduceOneFinding() {
        let port = OpenPort(host: "192.168.1.10", port: 445)
        let findings = evaluator.evaluate([port, port, port])

        XCTAssertEqual(findings.count, 1)
    }

    func testSamePortOnDifferentHostsProducesOneFindingEach() {
        let findings = evaluator.evaluate([
            OpenPort(host: "192.168.1.10", port: 22),
            OpenPort(host: "192.168.1.11", port: 22)
        ])

        XCTAssertEqual(findings.count, 2)
        XCTAssertEqual(Set(findings.compactMap(\.host)), ["192.168.1.10", "192.168.1.11"])
    }

    func testUnknownPortIsIgnored() {
        let findings = evaluator.evaluate([OpenPort(host: "192.168.1.10", port: 65000)])
        XCTAssertTrue(findings.isEmpty)
    }

    func testFindingsAreSortedMostSevereFirst() {
        let findings = evaluator.evaluate([
            OpenPort(host: "192.168.1.10", port: 22),
            OpenPort(host: "192.168.1.11", port: 21),
            OpenPort(host: "192.168.1.12", port: 23)
        ])

        XCTAssertEqual(findings.map(\.severity), [.critical, .high, .low])
    }

    func testPolicyCanBeNarrowed() {
        let policy = ExposureEvaluator.Policy(services: [
            ServiceDefinition(port: 445, name: "SMB", severity: .high, remediation: "Disable it.")
        ])
        let evaluator = ExposureEvaluator(policy: policy)

        XCTAssertTrue(evaluator.evaluate([OpenPort(host: "192.168.1.10", port: 22)]).isEmpty)
        XCTAssertEqual(evaluator.evaluate([OpenPort(host: "192.168.1.10", port: 445)]).count, 1)
    }
}
