import Foundation
import Observation
import ScopeScanCore

/// Owns one scan from validation through to the finished report.
///
/// The sweep and the findings judgement live in `ScopeScanCore`; this type only
/// wires them to the device's sockets and presents progress.
@Observable
@MainActor
final class ScanStore {
    enum Phase: Equatable {
        case idle
        case running
        case finished
    }

    var cidrText: String = ""
    var ownershipConfirmed = false
    private(set) var phase: Phase = .idle
    private(set) var progress: ScanProgress?
    private(set) var report: ScanReport?
    private(set) var suggestedScope: ScanScope?
    private(set) var hasActiveTunnel = false

    private var task: Task<Void, Never>?
    private let evaluator = ExposureEvaluator()

    var validatedScope: Result<ScanScope, Error>? {
        let text = cidrText.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return nil }
        return Result { try ScanScope(cidr: text) }
    }

    var canStart: Bool {
        guard phase != .running, ownershipConfirmed else { return false }
        if case .success? = validatedScope { return true }
        return false
    }

    /// Fills the scope from the Wi-Fi network on first appearance, without
    /// overwriting anything the user has typed.
    func prepare() {
        suggestedScope = NetworkInterfaces.suggestedScope()
        hasActiveTunnel = NetworkInterfaces.hasActiveTunnel()
        if cidrText.isEmpty, let suggestedScope {
            cidrText = suggestedScope.cidr
        }
    }

    func start() {
        guard canStart, case .success(let scope)? = validatedScope else { return }

        phase = .running
        progress = nil
        report = nil

        task = Task {
            let startedAt = Date()
            let engine = SweepEngine()

            async let bonjourFound = BonjourBrowser.discover()
            let sweep = await engine.sweep(
                scope: scope,
                probe: { host, port in
                    await TCPProbe.outcome(host: host.description, port: port)
                },
                progress: { [weak self] update in
                    Task { @MainActor in self?.progress = update }
                }
            )
            let bonjour = await bonjourFound

            let openPorts = sweep.hosts.flatMap { host in
                host.openPorts.map { OpenPort(host: host.address.description, port: $0) }
            }

            report = ScanReport(
                cidr: scope.cidr,
                startedAt: startedAt,
                duration: Date().timeIntervalSince(startedAt),
                scannedHostCount: sweep.scannedHostCount,
                hosts: sweep.hosts,
                openPorts: openPorts,
                findings: evaluator.evaluate(openPorts),
                bonjour: bonjour.services,
                refusedProbeCount: sweep.refusedProbeCount,
                firstRefusal: sweep.firstRefusal,
                wasCancelled: sweep.wasCancelled
            )
            phase = .finished
            task = nil
        }
    }

    func cancel() {
        task?.cancel()
    }
}
