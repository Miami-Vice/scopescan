import XCTest
@testable import ScopeScanCore

final class ReportExportTests: XCTestCase {
    private let started = Date(timeIntervalSince1970: 1_800_000_000)

    private func sampleReport(findings: [Finding]? = nil) -> ScanReport {
        let router = IPv4Address("192.168.12.1")!
        let pc = IPv4Address("192.168.12.157")!
        let openPorts = [
            OpenPort(host: pc.description, port: 445),
            OpenPort(host: pc.description, port: 8443)
        ]
        let findings = ExposureEvaluator().evaluate(openPorts)
        return ScanReport(
            cidr: "192.168.12.0/24",
            startedAt: started,
            duration: 76,
            scannedHostCount: 253,
            hosts: [
                HostReport(address: router, openPorts: [80], details: [80: "HTTP 200, Server: lighttpd"], label: "Likely router"),
                HostReport(
                    address: pc,
                    openPorts: [445, 8443],
                    details: [8443: "TLS 1.2"],
                    label: "Named by Bonjour: Living Room TV"
                )
            ],
            openPorts: openPorts,
            findings: findings ?? ExposureEvaluator().evaluate(openPorts),
            bonjour: [BonjourService(name: "Living Room TV", type: "_airplay._tcp", domain: "local.")],
            refusedProbeCount: 0,
            firstRefusal: nil,
            wasCancelled: false
        )
    }

    func testNoRedactionKeepsAddressesAndNames() {
        let export = ReportExporter.export(sampleReport(), redaction: .none)

        XCTAssertEqual(export.hosts.map(\.address), ["192.168.12.1", "192.168.12.157"])
        XCTAssertEqual(export.network, "192.168.12.0/24")
        XCTAssertEqual(export.bonjourServices.map(\.name), ["Living Room TV"])
        XCTAssertEqual(export.bonjourServices.map(\.type), ["airplay (TCP)"])
        XCTAssertTrue(export.findings.contains { $0.evidence.contains("192.168.12.157") })
    }

    func testMaskLastOctetHidesHostPartButKeepsHostsDistinct() throws {
        let export = ReportExporter.export(sampleReport(), redaction: .maskLastOctet)

        XCTAssertEqual(export.hosts.map(\.address), ["192.168.12.x (host 1)", "192.168.12.x (host 2)"])
        let finding = try XCTUnwrap(export.findings.first { $0.host != nil })
        XCTAssertEqual(finding.host, "192.168.12.x (host 2)")
        XCTAssertTrue(finding.evidence.contains("192.168.12.x (host 2)"))
        XCTAssertFalse(finding.evidence.contains("157"))
        XCTAssertEqual(export.network, "192.168.12.0/24")
    }

    func testPseudonymsDoNotCorruptLongerAddresses() throws {
        let export = ReportExporter.export(sampleReport(), redaction: .pseudonyms)

        XCTAssertEqual(export.hosts.map(\.address), ["host-1", "host-2"])
        let evidence = export.findings.map(\.evidence).joined(separator: " ")
        XCTAssertTrue(evidence.contains("host-2"), evidence)
        XCTAssertFalse(evidence.contains("host-1"), evidence)
        XCTAssertFalse(evidence.contains("57"), evidence)
    }

    func testPseudonymsAreStableForTheSameReport() {
        let first = ReportExporter.export(sampleReport(), redaction: .pseudonyms)
        let second = ReportExporter.export(sampleReport(), redaction: .pseudonyms)
        XCTAssertEqual(first.hosts, second.hosts)
    }

    func testRedactedLabelsDropAnnouncedNames() throws {
        let redacted = ReportExporter.export(sampleReport(), redaction: .pseudonyms)
        XCTAssertEqual(redacted.hosts.last?.label, "Named by Bonjour")

        let full = ReportExporter.export(sampleReport(), redaction: .none)
        XCTAssertEqual(full.hosts.last?.label, "Named by Bonjour: Living Room TV")
    }

    func testRedactedJSONContainsNoScannedAddresses() throws {
        for mode in [AddressRedaction.maskLastOctet, .pseudonyms] {
            let data = try ReportExporter.json(ReportExporter.export(sampleReport(), redaction: mode))
            let text = String(decoding: data, as: UTF8.self)
            XCTAssertFalse(text.contains("192.168.12.157"), "\(mode) leaked the full address")
            XCTAssertFalse(text.contains("Living Room TV"), "\(mode) leaked a device name")
            XCTAssertFalse(text.contains("192.168.12.1\""), "\(mode) leaked the router address")
        }
    }

    func testFullExportKeepsBonjourNames() throws {
        let data = try ReportExporter.json(ReportExporter.export(sampleReport(), redaction: .none))
        XCTAssertTrue(String(decoding: data, as: UTF8.self).contains("Living Room TV"))
    }

    func testStoredFullExportRedactsLikeADirectExport() {
        let full = ReportExporter.full(sampleReport())
        for mode in AddressRedaction.allCases {
            XCTAssertEqual(
                full.redacted(mode),
                ReportExporter.export(sampleReport(), redaction: mode),
                "\(mode) differs between stored and direct export"
            )
        }
    }

    func testRedactedExportCannotBeRedactedAgain() {
        let masked = ReportExporter.export(sampleReport(), redaction: .maskLastOctet)
        XCTAssertEqual(masked.redacted(.pseudonyms), masked)
        XCTAssertEqual(masked.redacted(.none), masked)
    }

    func testFullExportRedactedToFullIsUnchanged() {
        let full = ReportExporter.full(sampleReport())
        XCTAssertEqual(full.redacted(.none), full)
    }

    func testRedactedBonjourListKeepsOnlyServiceTypes() {
        let export = ReportExporter.export(sampleReport(), redaction: .pseudonyms)
        XCTAssertEqual(export.bonjourServices.map(\.type), ["airplay (TCP)"])
        XCTAssertEqual(export.bonjourServices.map(\.name), [nil])
    }

    func testPseudonymExportWithholdsTheSubnet() {
        let export = ReportExporter.export(sampleReport(), redaction: .pseudonyms)
        XCTAssertEqual(export.network, "redacted/24")
    }

    func testFindingForAddressWithoutAHostRowIsStillRedacted() {
        let finding = Finding(
            title: "Test finding",
            severity: .low,
            category: .networkExposure,
            evidence: "192.168.12.200 answered on port 80",
            remediation: "None",
            host: "192.168.12.200"
        )

        for mode in [AddressRedaction.maskLastOctet, .pseudonyms] {
            let export = ReportExporter.export(sampleReport(findings: [finding]), redaction: mode)
            let text = String(decoding: (try? ReportExporter.json(export)) ?? Data(), as: UTF8.self)
            XCTAssertFalse(text.contains("192.168.12.200"), "\(mode) leaked a finding-only address")
        }
    }

    func testJSONRoundTripsAndIsVersioned() throws {
        let export = ReportExporter.export(sampleReport(), redaction: .maskLastOctet)
        let data = try ReportExporter.json(export)
        let decoded = try JSONDecoder.iso8601.decode(ReportExport.self, from: data)

        XCTAssertEqual(decoded, export)
        XCTAssertEqual(decoded.formatVersion, ReportExport.formatVersion)
    }
}

private extension JSONDecoder {
    static var iso8601: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
