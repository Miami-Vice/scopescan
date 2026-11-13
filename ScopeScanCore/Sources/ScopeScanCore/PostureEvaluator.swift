import Foundation

/// Turns a `PostureObservation` into findings.
///
/// This is where the security judgement lives, and it is deliberately pure: no
/// Apple framework, no I/O, no clocks. That keeps every rule unit-testable on
/// Windows and means a rule change can be reviewed as a diff of policy rather
/// than scattered through view code.
public struct PostureEvaluator: Sendable {
    public struct Policy: Sendable {
        /// The iOS major version a device should be running. Bump this when a new
        /// major ships; it is a constant rather than a network lookup so the app
        /// keeps working offline and never phones home.
        public var recommendedOS: OSVersion

        public init(recommendedOS: OSVersion = OSVersion(27, 0)) {
            self.recommendedOS = recommendedOS
        }
    }

    public var policy: Policy

    public init(policy: Policy = Policy()) {
        self.policy = policy
    }

    /// Returns findings ordered most severe first. Empty means no weaknesses
    /// were observed — not that the device is provably secure.
    public func evaluate(_ observation: PostureObservation) -> [Finding] {
        var findings: [Finding] = []

        // An absent passcode is the root cause behind file protection, keychain
        // accessibility and remote-wipe protections all being weaker.
        if observation.passcodeEnrolled == false {
            findings.append(
                Finding(
                    title: "No passcode set",
                    severity: .critical,
                    category: .devicePosture,
                    evidence: "LAPolicy.deviceOwnerAuthentication reported no enrolled passcode or biometrics.",
                    remediation: "Set a 6-digit or longer passcode in Settings › Face ID & Passcode. Without one, iOS cannot encrypt files at rest and the stronger data-protection classes are unavailable.",
                    references: [URL(string: "https://support.apple.com/en-us/HT204060")!],
                    host: observation.deviceModel
                )
            )
        }

        if !observation.jailbreakIndicators.isEmpty {
            findings.append(
                Finding(
                    title: "Jailbreak indicators present",
                    severity: .critical,
                    category: .devicePosture,
                    evidence: observation.jailbreakIndicators.joined(separator: "; "),
                    remediation: "Restore this device from a clean iOS install. A jailbroken device has its code-signing and sandbox guarantees removed, so no third-party app can trust anything it reports.",
                    host: observation.deviceModel
                )
            )
        }

        if let current = observation.osVersion, current < policy.recommendedOS {
            let majorsBehind = current.majorReleasesBehind(policy.recommendedOS)
            findings.append(
                Finding(
                    title: "iOS is behind the recommended version",
                    severity: majorsBehind >= 2 ? .high : .medium,
                    category: .devicePosture,
                    evidence: "Running iOS \(current); recommended \(policy.recommendedOS) or later.",
                    remediation: "Update in Settings › General › Software Update. Security fixes for WebKit and the kernel ship in point releases, so staying current matters more than the version number suggests.",
                    references: [URL(string: "https://support.apple.com/en-us/HT201222")!],
                    host: observation.deviceModel
                )
            )
        }

        if observation.fileProtectionAvailable == false {
            findings.append(
                Finding(
                    title: "File data protection unavailable",
                    severity: .high,
                    category: .devicePosture,
                    evidence: "UIApplication.isProtectedDataAvailable reported false.",
                    remediation: "Set a passcode and unlock the device at least once since boot. File protection keys are derived from the passcode and are unavailable until after first unlock.",
                    host: observation.deviceModel
                )
            )
        }

        if let wifi = observation.wifiSecurity, wifi.isWeak {
            let detail: String
            switch wifi {
            case .open:
                detail = "The current Wi-Fi network uses no encryption."
            case .wep:
                detail = "The current Wi-Fi network uses WEP, which can be broken in minutes."
            default:
                detail = "The current Wi-Fi network uses \(wifi.displayName)."
            }
            findings.append(
                Finding(
                    title: "Weak Wi-Fi encryption",
                    severity: .high,
                    category: .networkExposure,
                    evidence: "\(detail) Reported as \(wifi.displayName).",
                    remediation: "Move this network to WPA2 or WPA3 with a strong passphrase. On an open network any device in range can read all traffic that is not independently encrypted.",
                    host: observation.deviceModel
                )
            )
        }

        if observation.isDebuggerAttached == true {
            findings.append(
                Finding(
                    title: "Debugger attached to this process",
                    severity: .medium,
                    category: .devicePosture,
                    evidence: "kinfo_proc reports P_TRACED on the current process.",
                    remediation: "Detach the debugger and reinstall from a build you trust. An attached debugger can read and modify this process's memory.",
                    host: observation.deviceModel
                )
            )
        }

        if observation.biometryAvailable == false, observation.passcodeEnrolled == true {
            findings.append(
                Finding(
                    title: "Biometric unlock unavailable",
                    severity: .low,
                    category: .devicePosture,
                    evidence: "LAPolicy.deviceOwnerAuthenticationWithBiometrics cannot be evaluated, but a passcode is set.",
                    remediation: "Re-enroll Face ID in Settings › Face ID & Passcode. This is a convenience gap, not a protection gap — the passcode still protects the device.",
                    host: observation.deviceModel
                )
            )
        }

        if observation.isVPNActive == true {
            findings.append(
                Finding(
                    title: "VPN tunnel is active",
                    severity: .info,
                    category: .devicePosture,
                    evidence: "A tunnel interface (ipsec/utun) is configured on this device.",
                    remediation: "No action needed. Note that LAN scans may be routed through the tunnel, so hosts this app reports may not be the ones physically nearby.",
                    host: observation.deviceModel
                )
            )
        }

        return findings.sortedBySeverity()
    }
}
