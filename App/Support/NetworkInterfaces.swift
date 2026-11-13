import Foundation
import Darwin
import ScopeScanCore

struct NetworkInterfaceInfo: Identifiable, Hashable {
    let name: String
    let address: String
    let isUp: Bool

    var id: String { "\(name)|\(address)" }
}

/// Enumerates this device's own IPv4 interfaces.
///
/// The sandbox allows `getifaddrs`, so this is reliable. Reading the ARP table
/// or the routing table is *not* available, which is why host discovery has to
/// be probe-based rather than table-based.
enum NetworkInterfaces {
    static func allIPv4() -> [NetworkInterfaceInfo] {
        var result: [NetworkInterfaceInfo] = []
        var head: UnsafeMutablePointer<ifaddrs>?

        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let pointer = cursor {
            let entry = pointer.pointee
            cursor = entry.ifa_next

            guard let sockaddrPointer = entry.ifa_addr,
                  sockaddrPointer.pointee.sa_family == UInt8(AF_INET)
            else {
                continue
            }

            var hostBuffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let length = socklen_t(sockaddrPointer.pointee.sa_len)
            guard getnameinfo(
                sockaddrPointer,
                length,
                &hostBuffer,
                socklen_t(hostBuffer.count),
                nil,
                0,
                NI_NUMERICHOST
            ) == 0 else {
                continue
            }

            result.append(
                NetworkInterfaceInfo(
                    name: String(cString: entry.ifa_name),
                    address: String(cString: hostBuffer),
                    isUp: (entry.ifa_flags & UInt32(IFF_UP)) != 0
                )
            )
        }

        return result
    }

    /// The Wi-Fi interface is en0 on every iPhone that ships Wi-Fi.
    static func primaryIPv4() -> NetworkInterfaceInfo? {
        let interfaces = allIPv4()
        return interfaces.first { $0.name == "en0" && $0.isUp }
            ?? interfaces.first { $0.isUp && !$0.address.hasPrefix("127.") }
    }

    /// Whether a VPN tunnel is carrying traffic on this device.
    ///
    /// The system does not expose VPN status or the default route to a
    /// sandboxed app, so this infers it from interface names. `ipsec*` and
    /// `ppp*` only exist when a tunnel is configured. `utun*` exists on stock
    /// devices too (Wi-Fi Calling, Private Relay), so it only counts when it
    /// holds a routable address rather than the 169.254 self-assigned one.
    ///
    /// This is a warning signal for scope selection, not proof that LAN traffic
    /// is being redirected.
    static func hasActiveTunnel() -> Bool {
        let dedicatedTunnelPrefixes = ["ipsec", "ppp"]

        for interface in allIPv4() where interface.isUp {
            if dedicatedTunnelPrefixes.contains(where: { interface.name.hasPrefix($0) }) {
                return true
            }
            if interface.name.hasPrefix("utun"),
               let address = IPv4Address(interface.address),
               !address.isLinkLocal {
                return true
            }
        }

        return false
    }

    /// Best-effort gateway guess: most consumer routers sit at the first host
    /// address of the /24 they hand out.
    static func gatewayGuess(for address: String) -> String? {
        guard let parsed = IPv4Address(address) else { return nil }
        let raw = (parsed.rawValue & 0xFFFF_FF00) | 1
        return IPv4Address(rawValue: raw).description
    }
}
