import Foundation
import Network
import ScopeScanCore

/// Lists Bonjour services advertised on the local network, and resolves each
/// one to an IPv4 address so its announced name can label that host.
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
            var found: [BonjourService] = []
            for result in results {
                guard case let .service(name, type, domain, _) = result.endpoint else { continue }
                found.append(BonjourService(name: name, type: type, domain: domain))
                collector.resolveIfNeeded(endpoint: result.endpoint, name: name)
            }
            collector.add(found)
        }

        return browser
    }

    /// Opens a connection to the service only to read which address it
    /// resolved to. Nothing is sent, and the connection closes as soon as the
    /// address is known or the deadline passes.
    fileprivate static func resolve(endpoint: NWEndpoint, collector: BonjourCollector, name: String) {
        let connection = NWConnection(to: endpoint, using: .tcp)
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                if case let .hostPort(host, _)? = connection.currentPath?.remoteEndpoint,
                   case let .ipv4(address) = host {
                    collector.addResolved(name: name, address: "\(address)")
                }
                connection.cancel()
            case .failed, .cancelled:
                connection.cancel()
            default:
                break
            }
        }
        connection.start(queue: collector.queue)
        collector.queue.asyncAfter(deadline: .now() + 3) { connection.cancel() }
    }
}

/// Collects browse results from several browsers on one queue.
private final class BonjourCollector: @unchecked Sendable {
    let queue = DispatchQueue(label: "dev.scopescan.bonjour")
    private let lock = NSLock()
    private var services = Set<BonjourService>()
    private var denied = false
    private var names: [ScopeScanCore.IPv4Address: String] = [:]
    private var attempted = Set<String>()

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

    /// Each instance is resolved at most once. Resolution runs on the browse
    /// queue, so the connection callbacks and the browse callbacks never race.
    func resolveIfNeeded(endpoint: NWEndpoint, name: String) {
        lock.lock()
        let isNew = attempted.insert(name).inserted
        lock.unlock()
        guard isNew else { return }
        BonjourBrowser.resolve(endpoint: endpoint, collector: self, name: name)
    }

    func addResolved(name: String, address: String) {
        guard let parsed = ScopeScanCore.IPv4Address(address) else { return }
        lock.lock()
        defer { lock.unlock() }
        if names[parsed] == nil {
            names[parsed] = name
        }
    }

    func snapshot() -> BonjourDiscovery {
        lock.lock()
        defer { lock.unlock() }
        let sorted = services.sorted {
            ($0.type, $0.name) < ($1.type, $1.name)
        }
        return BonjourDiscovery(
            services: sorted,
            denied: denied && sorted.isEmpty,
            namesByAddress: names
        )
    }
}
