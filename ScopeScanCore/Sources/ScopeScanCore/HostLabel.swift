import Foundation

/// A short, plain-language hint about what a host probably is.
///
/// Labels are guesses from open ports and the network layout, never identities.
/// They are shown as "Likely …" wherever a guess could be wrong.
public enum HostLabel {
    public static func describe(openPorts: [UInt16], isGateway: Bool, isThisDevice: Bool) -> String? {
        if isThisDevice { return "This device" }
        if isGateway { return "Likely router" }

        let ports = Set(openPorts)
        if ports.contains(9100) || ports.contains(631) { return "Likely printer" }
        if ports.contains(445) || ports.contains(139) { return "Likely Windows PC or NAS (file sharing)" }
        if ports.contains(548) { return "Likely Mac or NAS (AFP sharing)" }
        if ports.contains(3389) { return "Likely Windows PC (Remote Desktop)" }
        if ports.contains(5900) { return "Likely computer (screen sharing)" }
        if ports.contains(22) { return "Likely server (SSH)" }
        if !ports.isDisjoint(with: [80, 443, 5000, 8080, 8443]) { return "Likely web device" }
        return nil
    }
}
