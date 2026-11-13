import Foundation

/// The raw result of sweeping a scope, before findings or Bonjour are attached.
public struct SweepResult: Sendable, Hashable {
    /// Hosts that were probed to completion, whether or not they answered.
    public let scannedHostCount: Int
    /// Hosts that answered, sorted by address.
    public let hosts: [HostReport]
    public let localNetworkDenied: Bool
    public let wasCancelled: Bool

    public init(scannedHostCount: Int, hosts: [HostReport], localNetworkDenied: Bool, wasCancelled: Bool) {
        self.scannedHostCount = scannedHostCount
        self.hosts = hosts
        self.localNetworkDenied = localNetworkDenied
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

    public func sweep(
        scope: ScanScope,
        probe: @escaping Probe,
        progress: @escaping @Sendable (ScanProgress) -> Void = { _ in }
    ) async -> SweepResult {
        let total = scope.hostCount
        var iterator = scope.hosts.makeIterator()
        var reports: [HostReport] = []
        var scanned = 0
        var openCount = 0
        var denied = false
        var cancelled = false

        await withTaskGroup(of: HostOutcome.self) { group in
            for _ in 0..<min(concurrency, total) {
                guard let host = iterator.next() else { break }
                group.addTask { await sweepHost(host, probe: probe) }
            }

            while let outcome = await group.next() {
                switch outcome {
                case .up(let report):
                    scanned += 1
                    reports.append(report)
                    openCount += report.openPorts.count
                case .down:
                    scanned += 1
                case .denied:
                    denied = true
                case .skipped:
                    break
                }

                progress(
                    ScanProgress(
                        hostsCompleted: scanned,
                        hostCount: total,
                        hostsUp: reports.count,
                        openPortCount: openCount
                    )
                )

                if denied || cancelled || Task.isCancelled {
                    group.cancelAll()
                    continue
                }
                if let host = iterator.next() {
                    group.addTask { await sweepHost(host, probe: probe) }
                }
            }
        }

        if Task.isCancelled { cancelled = true }

        return SweepResult(
            scannedHostCount: scanned,
            hosts: reports.sorted { $0.address < $1.address },
            localNetworkDenied: denied,
            wasCancelled: cancelled
        )
    }

    private enum HostOutcome: Sendable {
        case up(HostReport)
        case down
        case denied
        case skipped
    }

    private func sweepHost(_ host: IPv4Address, probe: Probe) async -> HostOutcome {
        if Task.isCancelled { return .skipped }

        var probed = Set<UInt16>()
        var open = Set<UInt16>()
        var alive = false

        for port in discoveryPorts {
            let outcome = await probe(host, port)
            if outcome.isPermissionDenied { return .denied }
            probed.insert(port)
            if outcome == .open { open.insert(port) }
            if outcome.indicatesHostIsUp {
                alive = true
                break
            }
        }

        guard alive else { return .down }

        for port in inventoryPorts where !probed.contains(port) {
            if Task.isCancelled { return .skipped }
            let outcome = await probe(host, port)
            if outcome.isPermissionDenied { return .denied }
            if outcome == .open { open.insert(port) }
        }

        return .up(HostReport(address: host, openPorts: open.sorted()))
    }
}
