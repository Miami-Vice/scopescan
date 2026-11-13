import XCTest
@testable import ScopeScanCore

final class SweepEngineTests: XCTestCase {
    /// A fake network: each host maps ports to outcomes; anything unlisted times out.
    private func network(_ table: [IPv4Address: [UInt16: PortOutcome]]) -> SweepEngine.Probe {
        { host, port in
            table[host]?[port] ?? .timedOut
        }
    }

    private func address(_ text: String) -> IPv4Address {
        IPv4Address(text)!
    }

    func testSilentHostsAreNotReported() async throws {
        let scope = try ScanScope(cidr: "192.168.1.0/24")
        let result = await SweepEngine().sweep(scope: scope, probe: network([:]))

        XCTAssertEqual(result.scannedHostCount, 254)
        XCTAssertTrue(result.hosts.isEmpty)
        XCTAssertFalse(result.localNetworkDenied)
        XCTAssertFalse(result.wasCancelled)
    }

    func testRefusedDiscoveryPortMarksHostUpWithNoOpenPorts() async throws {
        let scope = try ScanScope(cidr: "192.168.1.0/24")
        let host = address("192.168.1.20")
        let result = await SweepEngine().sweep(
            scope: scope,
            probe: network([host: [80: .closed]])
        )

        XCTAssertEqual(result.hosts, [HostReport(address: host, openPorts: [])])
    }

    func testOpenPortsAreInventoriedOnLiveHosts() async throws {
        let scope = try ScanScope(cidr: "192.168.1.0/24")
        let host = address("192.168.1.10")
        let result = await SweepEngine().sweep(
            scope: scope,
            probe: network([host: [80: .closed, 445: .open, 9100: .open]])
        )

        XCTAssertEqual(result.hosts.count, 1)
        XCTAssertEqual(result.hosts.first?.openPorts, [445, 9100])
    }

    func testOpenDiscoveryPortIsRecordedWhenProbeStopsEarly() async throws {
        let scope = try ScanScope(cidr: "192.168.1.0/30")
        let host = address("192.168.1.1")
        let result = await SweepEngine().sweep(
            scope: scope,
            probe: network([host: [80: .open, 22: .open]])
        )

        XCTAssertEqual(result.hosts.first?.openPorts, [22, 80])
    }

    func testOnlyLiveHostsGetInventoryProbes() async throws {
        let scope = try ScanScope(cidr: "192.168.1.0/24")
        let live = address("192.168.1.5")
        let counter = ProbeCounter()
        let probe: SweepEngine.Probe = { host, port in
            await counter.record(host)
            return host == live && port == 80 ? .closed : .timedOut
        }

        _ = await SweepEngine().sweep(scope: scope, probe: probe)

        let perHost = await counter.counts
        XCTAssertEqual(perHost[live], SweepEngine().inventoryPorts.count)
        XCTAssertLessThanOrEqual(perHost[address("192.168.1.6")] ?? 0, ServiceCatalog.discoveryPorts.count)
    }

    func testLocalNetworkDenialStopsTheSweep() async throws {
        let scope = try ScanScope(cidr: "192.168.1.0/24")
        let result = await SweepEngine(concurrency: 4).sweep(
            scope: scope,
            probe: { _, _ in .denied }
        )

        XCTAssertTrue(result.localNetworkDenied)
        XCTAssertTrue(result.hosts.isEmpty)
        XCTAssertLessThan(result.scannedHostCount, scope.hostCount)
    }

    func testDenialIsNotReportedAsUserCancellation() async throws {
        let scope = try ScanScope(cidr: "192.168.1.0/24")
        let result = await SweepEngine(concurrency: 4).sweep(
            scope: scope,
            probe: { _, _ in .denied }
        )

        XCTAssertTrue(result.localNetworkDenied)
        XCTAssertFalse(result.wasCancelled)
    }

    func testConcurrencyIsBounded() async throws {
        let scope = try ScanScope(cidr: "192.168.1.0/24")
        let tracker = InFlightTracker()
        let engine = SweepEngine(concurrency: 5)

        _ = await engine.sweep(scope: scope, probe: { _, _ in
            await tracker.enter()
            await Task.yield()
            await tracker.leave()
            return .timedOut
        })

        let peak = await tracker.peak
        XCTAssertLessThanOrEqual(peak, 5)
        XCTAssertGreaterThan(peak, 0)
    }

    func testProgressReportsEveryHost() async throws {
        let scope = try ScanScope(cidr: "192.168.1.0/28")
        let recorder = ProgressRecorder()

        _ = await SweepEngine().sweep(
            scope: scope,
            probe: network([:]),
            progress: { recorder.record($0) }
        )

        let values = recorder.values
        XCTAssertEqual(values.count, scope.hostCount)
        XCTAssertEqual(values.last?.hostsCompleted, scope.hostCount)
        XCTAssertEqual(values.last?.fraction, 1)
    }

    func testCancellationBeforeStartScansNothing() async throws {
        let scope = try ScanScope(cidr: "192.168.1.0/24")
        let task = Task {
            await SweepEngine().sweep(scope: scope, probe: { _, _ in .timedOut })
        }
        task.cancel()
        let result = await task.value

        XCTAssertTrue(result.wasCancelled)
        XCTAssertLessThan(result.scannedHostCount, scope.hostCount)
    }
}

private actor ProbeCounter {
    private(set) var counts: [IPv4Address: Int] = [:]

    func record(_ host: IPv4Address) {
        counts[host, default: 0] += 1
    }
}

private actor InFlightTracker {
    private var inFlight = 0
    private(set) var peak = 0

    func enter() {
        inFlight += 1
        peak = max(peak, inFlight)
    }

    func leave() {
        inFlight -= 1
    }
}

private final class ProgressRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [ScanProgress] = []

    func record(_ progress: ScanProgress) {
        lock.lock()
        defer { lock.unlock() }
        storage.append(progress)
    }

    var values: [ScanProgress] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}
