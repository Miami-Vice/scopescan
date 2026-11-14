import XCTest
@testable import ScopeScanCore

final class TLSEvaluatorTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func observation(
        version: TLSVersion = .tls13,
        notAfterOffset: TimeInterval? = 365 * 24 * 60 * 60,
        algorithm: KeyAlgorithm = .rsa,
        keyBits: Int? = 2048,
        trusted: Bool = true
    ) -> TLSObservation {
        TLSObservation(
            host: "192.168.12.1",
            port: 443,
            version: version,
            leafNotAfter: notAfterOffset.map { now.addingTimeInterval($0) },
            leafKeyAlgorithm: algorithm,
            leafKeyBits: keyBits,
            leafSubject: "router.local",
            chainTrusted: trusted
        )
    }

    private func evaluate(_ observation: TLSObservation) -> [Finding] {
        TLSEvaluator(now: now).evaluate(observation)
    }

    func testHealthyEndpointHasNoFindings() {
        XCTAssertTrue(evaluate(observation()).isEmpty)
    }

    func testOldProtocolIsHigh() {
        let findings = evaluate(observation(version: .tls10))
        XCTAssertEqual(findings.map(\.title), ["Outdated TLS version"])
        XCTAssertEqual(findings.first?.severity, .high)
        XCTAssertEqual(findings.first?.category, .transportSecurity)
    }

    func testTLS12IsAcceptable() {
        XCTAssertTrue(evaluate(observation(version: .tls12)).isEmpty)
    }

    func testUnknownVersionIsNotReportedAsOutdated() {
        XCTAssertTrue(evaluate(observation(version: .unknown)).isEmpty)
    }

    func testExpiredCertificateIsHigh() {
        let findings = evaluate(observation(notAfterOffset: -1))
        XCTAssertEqual(findings.map(\.title), ["Certificate has expired"])
        XCTAssertEqual(findings.first?.severity, .high)
    }

    func testCertificateExpiringSoonIsLow() {
        let findings = evaluate(observation(notAfterOffset: 10 * 24 * 60 * 60))
        XCTAssertEqual(findings.map(\.title), ["Certificate expires soon"])
        XCTAssertEqual(findings.first?.severity, .low)
    }

    func testCertificateOutsideWarningWindowIsQuiet() {
        XCTAssertTrue(evaluate(observation(notAfterOffset: 90 * 24 * 60 * 60)).isEmpty)
    }

    func testWeakKeyIsHigh() {
        let findings = evaluate(observation(keyBits: 1024))
        XCTAssertEqual(findings.map(\.title), ["Weak certificate key"])
        XCTAssertEqual(findings.first?.severity, .high)
    }

    func testEllipticCurveKeyOfPlausibleSizeIsQuiet() {
        XCTAssertTrue(evaluate(observation(algorithm: .ellipticCurve, keyBits: 256)).isEmpty)
    }

    func testWeakEllipticCurveKeyIsHigh() {
        let findings = evaluate(observation(algorithm: .ellipticCurve, keyBits: 192))
        XCTAssertEqual(findings.map(\.title), ["Weak certificate key"])
    }

    func testUnknownKeyFamilyIsNotJudgedBySize() {
        XCTAssertTrue(evaluate(observation(algorithm: .unknown, keyBits: 512)).isEmpty)
    }

    func testUntrustedChainIsLowAndNamesTheSubject() {
        let findings = evaluate(observation(trusted: false))
        XCTAssertEqual(findings.map(\.title), ["Certificate is not trusted by this device"])
        XCTAssertEqual(findings.first?.severity, .low)
        XCTAssertTrue(findings.first?.evidence.contains("router.local") == true)
    }

    func testFindingsCarryHostAndPort() {
        for finding in evaluate(observation(version: .tls10, trusted: false)) {
            XCTAssertEqual(finding.host, "192.168.12.1")
            XCTAssertEqual(finding.port, 443)
        }
    }

    func testFindingsAreSortedMostSevereFirst() {
        let findings = evaluate(observation(version: .tls10, notAfterOffset: 5 * 24 * 60 * 60, trusted: false))
        XCTAssertEqual(findings.map(\.severity), [.high, .low, .low])
    }
}
