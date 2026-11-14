import Foundation
import Darwin
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

    static func discover(duration: TimeInterval = 6) async -> BonjourDiscovery {
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
                collector.resolveIfNeeded(name: name, type: type, domain: domain)
            }
            collector.add(found)
        }

        return browser
    }
}

/// Resolves one Bonjour instance to its IPv4 address with `NetService`, which
/// reports the address directly. A connection's remote endpoint does not reliably
/// give one for a Bonjour service, which is why labels were not appearing.
private final class ServiceResolver: NSObject, NetServiceDelegate {
    private let service: NetService
    private let completion: (String?) -> Void
    private var finished = false

    init(name: String, type: String, domain: String, completion: @escaping (String?) -> Void) {
        let dottedType = type.hasSuffix(".") ? type : type + "."
        self.service = NetService(domain: domain, type: dottedType, name: name)
        self.completion = completion
        super.init()
    }

    /// Must run on the main run loop, where NetService delivers its callbacks.
    func start() {
        service.delegate = self
        service.resolve(withTimeout: 3)
    }

    func netServiceDidResolveAddress(_ sender: NetService) {
        finish(Self.ipv4Address(from: sender.addresses ?? []))
    }

    func netService(_ sender: NetService, didNotResolve errorDict: [String: NSNumber]) {
        finish(nil)
    }

    private func finish(_ address: String?) {
        guard !finished else { return }
        finished = true
        service.stop()
        completion(address)
    }

    private static func ipv4Address(from addresses: [Data]) -> String? {
        for data in addresses {
            let text: String? = data.withUnsafeBytes { raw -> String? in
                guard let base = raw.baseAddress else { return nil }
                let generic = base.assumingMemoryBound(to: sockaddr.self)
                guard generic.pointee.sa_family == sa_family_t(AF_INET) else { return nil }
                var address = base.assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                guard inet_ntop(AF_INET, &address, &buffer, socklen_t(buffer.count)) != nil else { return nil }
                return String(cString: buffer)
            }
            if let text { return text }
        }
        return nil
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
    private var resolvers: [ServiceResolver] = []

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

    /// Each instance is resolved at most once.
    func resolveIfNeeded(name: String, type: String, domain: String) {
        lock.lock()
        let isNew = attempted.insert("\(name)|\(type)|\(domain)").inserted
        lock.unlock()
        guard isNew else { return }

        DispatchQueue.main.async { [self] in
            let resolver = ServiceResolver(name: name, type: type, domain: domain) { [weak self] address in
                guard let address else { return }
                self?.addResolved(name: name, address: address)
            }
            lock.lock()
            resolvers.append(resolver)
            lock.unlock()
            resolver.start()
        }
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
