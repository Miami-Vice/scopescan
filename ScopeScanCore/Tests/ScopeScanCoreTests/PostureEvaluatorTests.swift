import XCTest
@testable import ScopeScanCore

final class PostureEvaluatorTests: XCTestCase {
    private let evaluator = PostureEvaluator(policy: .init(recommendedOS: OSVersion(27, 0)))

    /// A device with nothing wrong with it.
    private var cleanDevice: PostureObservation {
        PostureObservation(
            deviceModel: "iPhone17,2",
            osVersion: OSVersion(27, 0, 1),
            passcodeEnrolled: true,
            biometryAvailable: true,
            fileProtectionAvailable: true,
            isVPNActive: false,
            isDebuggerAttached: false,
            wifiSecurity: .wpa3,
            jailbreakIndicators: []
        )
    }

    private func titles(_ findings: [Finding]) -> [String] {
        findings.map(\.title)
    }

    func testCleanDeviceProducesNoFindings() {
        XCTAssertTrue(evaluator.evaluate(cleanDevice).isEmpty)
    }

    func testMissingPasscodeIsCritical() {
        var device = cleanDevice
        device.passcodeEnrolled = false
        device.biometryAvailable = false

        let findings = evaluator.evaluate(device)
        XCTAssertEqual(findings.first?.severity, .critical)
        XCTAssertEqual(findings.first?.title, "No passcode set")
        // Biometry-unavailable must not also fire when there is no passcode at all:
        // it is a symptom, not a separate weakness.
        XCTAssertFalse(titles(findings).contains("Biometric unlock unavailable"))
    }

    func testJailbreakIndicatorsAreCriticalAndCarryEvidence() {
        var device = cleanDevice
        device.jailbreakIndicators = ["cydia:// resolved", "writable /private/etc"]

        let findings = evaluator.evaluate(device)
        let finding = try? XCTUnwrap(findings.first { $0.title == "Jailbreak indicators present" })
        XCTAssertEqual(finding?.severity, .critical)
        XCTAssertEqual(finding?.evidence, "cydia:// resolved; writable /private/etc")
    }

    func testOSVersionSeverityEscalatesWithDistance() {
        var oneBehind = cleanDevice
        oneBehind.osVersion = OSVersion(26, 5)
        XCTAssertEqual(
            evaluator.evaluate(oneBehind).first { $0.title.contains("behind") }?.severity,
            .medium
        )

        var twoBehind = cleanDevice
        twoBehind.osVersion = OSVersion(25, 0)
        XCTAssertEqual(
            evaluator.evaluate(twoBehind).first { $0.title.contains("behind") }?.severity,
            .high
        )
    }

    func testCurrentVersionProducesNoUpdateFinding() {
        var device = cleanDevice
        device.osVersion = OSVersion(27, 0)
        XCTAssertTrue(evaluator.evaluate(device).isEmpty)
    }

    func testFileProtectionUnavailableIsHigh() {
        var device = cleanDevice
        device.fileProtectionAvailable = false
        XCTAssertEqual(evaluator.evaluate(device).first?.severity, .high)
    }

    func testOpenAndWEPWifiAreHigh() {
        for security in [WifiSecurity.open, .wep] {
            var device = cleanDevice
            device.wifiSecurity = security
            let finding = evaluator.evaluate(device).first { $0.category == .networkExposure }
            XCTAssertEqual(finding?.severity, .high, "\(security) should be high")
        }
    }

    func testStrongWifiIsNotReported() throws {
        for security in [WifiSecurity.wpa2, .wpa3, .enterprise] {
            var device = cleanDevice
            device.wifiSecurity = security
            XCTAssertTrue(evaluator.evaluate(device).isEmpty, "\(security) should not be flagged")
        }
    }

    func testDebuggerIsMedium() {
        var device = cleanDevice
        device.isDebuggerAttached = true
        let finding = evaluator.evaluate(device).first { $0.title.contains("Debugger") }
        XCTAssertEqual(finding?.severity, .medium)
    }

    func testVPNIsInformationalOnly() {
        var device = cleanDevice
        device.isVPNActive = true
        let findings = evaluator.evaluate(device)
        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.severity, .info)
    }

    func testUndeterminedChecksDoNotBecomePasses() {
        // Everything unknown: no findings, because nothing was observed. The UI
        // must present these as "unavailable", never as passing.
        let unknown = PostureObservation()
        XCTAssertTrue(evaluator.evaluate(unknown).isEmpty)
    }

    func testFindingsAreOrderedBySeverity() {
        var device = cleanDevice
        device.passcodeEnrolled = false
        device.isDebuggerAttached = true
        device.isVPNActive = true

        let severities = evaluator.evaluate(device).map(\.severity)
        XCTAssertEqual(severities, severities.sorted(by: >))
    }
}
