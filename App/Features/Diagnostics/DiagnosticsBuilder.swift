import Foundation
import LocalAuthentication
import CoreLocation
import UIKit
import ScopeScanCore

/// Collects everything the app can observe about its own host without any
/// special entitlement.
///
/// This doubles as the project's only device-feedback channel: CI can compile
/// and unit-test this code, but only a real phone can tell us whether the OS
/// actually returns what we expect. The rendered text is meant to be copied off
/// the device and pasted back into a bug report.
@MainActor
enum DiagnosticsBuilder {
    static func sections(probeOutput: String) -> [DiagnosticsSection] {
        [
            buildSection(),
            deviceSection(),
            authenticationSection(),
            interfaceSection(),
            permissionSection(probeOutput: probeOutput)
        ]
    }

    static func renderedText(from sections: [DiagnosticsSection]) -> String {
        var lines: [String] = [
            "ScopeScan diagnostics",
            "Generated: \(ISO8601DateFormatter().string(from: Date()))",
            ""
        ]

        for section in sections {
            lines.append("[\(section.title)]")
            for row in section.rows {
                lines.append("  \(row.label): \(row.value)")
            }
            lines.append("")
        }

        return lines.joined(separator: "\n")
    }

    // MARK: - Sections

    private static func buildSection() -> DiagnosticsSection {
        let info = Bundle.main.infoDictionary ?? [:]
        let version = info["CFBundleShortVersionString"] as? String ?? "?"
        let build = info["CFBundleVersion"] as? String ?? "?"

        return DiagnosticsSection(title: "Build", rows: [
            DiagnosticsRow(label: "App version", value: "\(version) (\(build))"),
            DiagnosticsRow(label: "Bundle ID", value: Bundle.main.bundleIdentifier ?? "?"),
            DiagnosticsRow(label: "Core version", value: CoreInfo.version)
        ])
    }

    private static func deviceSection() -> DiagnosticsSection {
        let os = ProcessInfo.processInfo.operatingSystemVersion

        return DiagnosticsSection(title: "Device", rows: [
            DiagnosticsRow(label: "Model identifier", value: Hardware.identifier()),
            DiagnosticsRow(
                label: "iOS",
                value: "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
            ),
            DiagnosticsRow(
                label: "Protected data available",
                value: UIApplication.shared.isProtectedDataAvailable ? "yes" : "no"
            )
        ])
    }

    private static func authenticationSection() -> DiagnosticsSection {
        let context = LAContext()
        var error: NSError?
        let canAuthenticate = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)

        let biometry: String
        switch context.biometryType {
        case .faceID: biometry = "Face ID"
        case .touchID: biometry = "Touch ID"
        case .opticID: biometry = "Optic ID"
        default: biometry = "none"
        }

        return DiagnosticsSection(title: "Authentication", rows: [
            DiagnosticsRow(
                label: "Passcode or biometrics enrolled",
                value: canAuthenticate ? "yes" : "no"
            ),
            DiagnosticsRow(label: "Biometry", value: biometry),
            DiagnosticsRow(label: "Last evaluation error", value: error?.localizedDescription ?? "none")
        ])
    }

    private static func interfaceSection() -> DiagnosticsSection {
        let interfaces = NetworkInterfaces.allIPv4()
        let rows: [DiagnosticsRow]

        if interfaces.isEmpty {
            rows = [DiagnosticsRow(label: "Interfaces", value: "none found")]
        } else {
            rows = interfaces.map { interface in
                DiagnosticsRow(
                    label: interface.name,
                    value: "\(interface.address)\(interface.isUp ? "" : " (down)")"
                )
            }
        }

        return DiagnosticsSection(title: "IPv4 interfaces", rows: rows)
    }

    private static func permissionSection(probeOutput: String) -> DiagnosticsSection {
        let manager = CLLocationManager()
        let location: String
        switch manager.authorizationStatus {
        case .authorizedAlways: location = "authorized (always)"
        case .authorizedWhenInUse: location = "authorized (when in use)"
        case .denied: location = "denied"
        case .restricted: location = "restricted"
        case .notDetermined: location = "not determined"
        @unknown default: location = "unknown"
        }

        return DiagnosticsSection(title: "Permissions", rows: [
            DiagnosticsRow(label: "Location", value: location),
            DiagnosticsRow(label: "Local network", value: probeOutput)
        ])
    }
}
