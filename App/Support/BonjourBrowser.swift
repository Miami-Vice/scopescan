import Foundation
import Network
import ScopeScanCore

/// Lists Bonjour services advertised on the local network.
///
/// Browsing needs no multicast entitlement, only the Local Network permission
/// and the service types declared in `NSBonjourServices`. The browse is
/// time-boxed: services are announced continuously, so there is no natural end.
enum BonjourBrowser {
    /// Service types declared in Info.plist. Browsing an undeclared type is
    /// silently refused by the system, so the list is read from the bundle.
    static var declaredTypes: [String] {
        (Bundle.main.object(forInfoDictionaryKey: "NSBonjourServices") as? [String]) ?? []
    }

    static func discover(duration: TimeInterval = 4) async -> BonjourDiscovery {
        let collector = BonjourCollector()
        let browsers = declaredTypes
            .filter { $0 != "_services._dns-sd._udp" }
            .map { makeBrowser(type: $0, collector: collector) }

        browsers.forEach { $0.start(queue: collector.queue) }
        try? await Task.sleep(nanoseconds: UInt64(duration * 1_000_000_000))
        browsers.forEach { $0.cancel() }

        return collector.snapshot()
    }

    private static func makeBrowser(type: String, collector: BonjourCollector) -> NWBrowser {
        let parameters: NWParameters = type.hasSuffix("_udp") ? .udp : .tcp
        let browser = NWBrowser(for: .bonjour(type: type, domain: nil), using: parameters)

        browser.stateUpdateHandler = { state in
            switch state {
            case .waiting(let error), .failed(let error):
                if case .dns = error { collector.markDenied() }
                if case .posix(let code) = error, code == .EPERM || code == .EACCES {
                    collector.markDenied()
                }
            default:
                break
            }
        }

        browser.browseResultsChangedHandler = { results, _ in
            collector.add(results.compactMap { result -> BonjourService? in
                guard case let .service(name, type, domain, _) = result.endpoint else { return nil }
                return BonjourService(name: name, type: type, domain: domain)
            })
        }

        return browser
    }
}

/// Collects browse results from several browsers on one queue.
private final class BonjourCollector: @unchecked Sendable {
    let queue = DispatchQueue(label: "dev.scopescan.bonjour")
    private let lock = NSLock()
    private var services = Set<BonjourService>()
    private var denied = false

    func add(_ found: [BonjourService]) {
        lock.lock()
        defer { lock.unlock() }
        services.formUnion(found)
    }

    func markDenied() {
        lock.lock()
        defer { lock.unlock() }
        denied = true
    }

    func snapshot() -> BonjourDiscovery {
        lock.lock()
        defer { lock.unlock() }
        let sorted = services.sorted {
            ($0.type, $0.name) < ($1.type, $1.name)
        }
        return BonjourDiscovery(services: sorted, denied: denied && sorted.isEmpty)
    }
}
