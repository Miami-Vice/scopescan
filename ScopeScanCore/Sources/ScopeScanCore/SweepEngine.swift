import Foundation

/// The raw result of sweeping a scope, before findings or Bonjour are attached.
public struct SweepResult: Sendable, Hashable {
    /// Hosts that were probed to completion, whether or not they answered.
    public let scannedHostCount: Int
    /// Hosts that answered, sorted by address.
    public let hosts: [HostReport]
    /// Probes the system refused with a permission error. They are not counted
    /// as silence, so a non-zero value means the results are incomplete.
    public let refusedProbeCount: Int
    /// The first permission error seen, for the report.
    public let firstRefusal: String?
    public let wasCancelled: Bool

    public var localNetworkDenied: Bool { refusedProbeCount > 0 }

    public init(
        scannedHostCount: Int,
        hosts: [HostReport],
        refusedProbeCount: Int,
        firstRefusal: String?,
        wasCancelled: Bool
    ) {
        self.scannedHostCount = scannedHostCount
        self.hosts = hosts
        self.refusedProbeCount = refusedProbeCount
        self.firstRefusal = firstRefusal
        self.wasCancelled = wasCancelled
    }
}

/// Two-phase TCP sweep over a `ScanScope`.
///
/// Phase one probes a handful of discovery ports on every host and stops at the
/// first answer. Phase two inventories the remaining ports, but only on hosts
/// that proved they exist. Silent addresses cost a few probes instead of the
/// full catalog, which keeps a /24 inside a sensible time budget.
///
/// The socket work is injected as `probe`, so this type stays pure and can be
/// exercised on any platform with a fake network.
public struct SweepEngine: Sendable {
    public typealias Probe = @Sendable (IPv4Address, UInt16) async -> PortOutcome

    public var concurrency: Int
    public var discoveryPorts: [UInt16]
    public var inventoryPorts: [UInt16]

    /// 32 in flight keeps the phone responsive and well clear of iOS limits on
    /// simultaneous sockets.
    public init(
        concurrency: Int = 32,
        discoveryPorts: [UInt16] = ServiceCatalog.discoveryPorts,
        inventoryPorts: [UInt16] = ServiceCatalog.inventoryPorts
    ) {
        self.concurrency = max(1, concurrency)
        self.discoveryPorts = discoveryPorts
        self.inventoryPorts = inventoryPorts
    }

    /// `excluding` lists addresses that are never probed, typically this
    /// device's own interfaces. iOS refuses connections to a device's own
    /// address, which would otherwise look like a permission failure.
    public func sweep(
        scope: ScanScope,
        excluding: Set<IPv4Address> = [],
        probe: @escaping Probe,
        progress: @escaping @Sendable (ScanProgress) -> Void = { _ in }
    ) async -> SweepResult {
        let targets = scope.hosts.filter { !excluding.contains($0) }
        let total = targets.count
        var iterator = targets.makeIterator()
        var reports: [HostReport] = []
        var scanned = 0
        var openCount = 0
        var refused = 0
        var firstRefusal: String?

        await withTaskGroup(of: HostResult.self) { group in
            for _ in 0..<min(concurrency, total) {
                guard let host = iterator.next() else { break }
                group.addTask { await sweepHost(host, probe: probe) }
            }

            while let result = await group.next() {
                if !result.skipped {
                    scanned += 1
                    if let report = result.report {
                        reports.append(report)
                        openCount += report.openPorts.count
                    }
                }
                refused += result.refusedProbes
                firstRefusal = firstRefusal ?? result.firstRefusal

                progress(
                    ScanProgress(
                        hostsCompleted: scanned,
                        hostCount: total,
                        hostsUp: reports.count,
                        openPortCount: openCount
                    )
                )

                if Task.isCancelled {
                    group.cancelAll()
                    continue
                }
                if let host = iterator.next() {
                    group.addTask { await sweepHost(host, probe: probe) }
                }
            }
        }

        return SweepResult(
            scannedHostCount: scanned,
            hosts: reports.sorted { $0.address < $1.address },
            refusedProbeCount: refused,
            firstRefusal: firstRefusal,
            wasCancelled: Task.isCancelled
        )
    }

    private struct HostResult: Sendable {
        var report: HostReport?
        var refusedProbes = 0
        var firstRefusal: String?
        var skipped = false
    }

    private func sweepHost(_ host: IPv4Address, probe: Probe) async -> HostResult {
        if Task.isCancelled { return HostResult(skipped: true) }

        var result = HostResult()
        var probed = Set<UInt16>()
        var open = Set<UInt16>()
        var alive = false

        for port in discoveryPorts {
            let outcome = await probe(host, port)
            probed.insert(port)
            if case .denied(let detail) = outcome {
                result.refusedProbes += 1
                result.firstRefusal = result.firstRefusal ?? "\(host):\(port) \(detail)"
                continue
            }
            if outcome == .open { open.insert(port) }
            if outcome.indicatesHostIsUp {
                alive = true
                break
            }
        }

        guard alive else { return result }

        for port in inventoryPorts where !probed.contains(port) {
            if Task.isCancelled { return HostResult(skipped: true) }
            let outcome = await probe(host, port)
            if case .denied(let detail) = outcome {
                result.refusedProbes += 1
                result.firstRefusal = result.firstRefusal ?? "\(host):\(port) \(detail)"
                continue
            }
            if outcome == .open { open.insert(port) }
        }

        result.report = HostReport(address: host, openPorts: open.sorted())
        return result
    }
}
