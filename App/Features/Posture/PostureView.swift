import SwiftUI
import ScopeScanCore

/// The posture report: findings first, then the raw checks behind them.
///
/// The checks section exists specifically so that a missing warning is never
/// mistaken for a pass. Every observation has three states — pass, fail and
/// *not determined* — and the last one is rendered explicitly rather than
/// omitted.
struct PostureView: View {
    @Environment(PostureStore.self) private var posture

    var body: some View {
        NavigationStack {
            List {
                findingsSection
                checksSection
                provenanceSection
            }
            .navigationTitle("Posture")
            .navigationDestination(for: Finding.self) { finding in
                FindingDetailView(finding: finding)
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Re-check", systemImage: "arrow.clockwise") {
                        Task { await posture.refresh() }
                    }
                    .disabled(posture.isRefreshing)
                }
            }
            .refreshable { await posture.refresh() }
            .task { await posture.refreshIfNeeded() }
        }
    }

    // MARK: - Findings

    private var findingsSection: some View {
        Section {
            if posture.isRefreshing, posture.lastRefreshed == nil {
                HStack(spacing: 12) {
                    ProgressView()
                    Text("Checking this device…")
                        .foregroundStyle(.secondary)
                }
            } else if posture.lastRefreshed == nil {
                Text("Not checked yet.")
                    .foregroundStyle(.secondary)
            } else if posture.findings.isEmpty {
                Label {
                    Text("No weaknesses observed")
                } icon: {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                }
                Text("This is an absence of findings, not proof of security. Checks that could not run are listed below as *not determined*.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(posture.findings) { finding in
                    NavigationLink(value: finding) {
                        FindingRow(finding: finding)
                    }
                }
            }
        } header: {
            Text("Findings")
        } footer: {
            if let refreshed = posture.lastRefreshed, !posture.findings.isEmpty {
                Text("\(posture.findings.count) finding\(posture.findings.count == 1 ? "" : "s"), most severe first. Checked \(refreshed.formatted(date: .abbreviated, time: .shortened)).")
            }
        }
    }

    // MARK: - Checks

    private var checksSection: some View {
        Section {
            ForEach(checks) { check in
                CheckRow(check: check)
            }
        } header: {
            Text("Checks")
        } footer: {
            Text("A check reported as *not determined* did not run. It is never counted as a pass, so a clean report only covers the checks that actually produced an answer.")
        }
    }

    private var provenanceSection: some View {
        Section {
            row("Model", posture.observation.deviceModel ?? "not determined")
            row("iOS", posture.observation.osVersion?.description ?? "not determined")
            row("Recommended iOS", posture.recommendedOS.description)
        } header: {
            Text("Device")
        } footer: {
            Text("Posture is judged by ScopeScanCore v\(CoreInfo.version), which is unit-tested off-device. Only the collection of these values is hardware-dependent.")
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value)
                .multilineTextAlignment(.trailing)
        }
        .font(.callout)
    }

    // MARK: - Derivation

    /// The observation rendered as displayable checks.
    private var checks: [PostureCheck] {
        let observation = posture.observation
        var result: [PostureCheck] = []

        result.append(
            PostureCheck(
                title: "Passcode",
                state: passFail(observation.passcodeEnrolled),
                detail: observation.passcodeEnrolled.map {
                    $0
                        ? "A passcode or biometrics is enrolled."
                        : "No passcode or biometrics is enrolled, so files cannot be protected at rest."
                } ?? "LocalAuthentication could not report enrollment."
            )
        )

        result.append(
            PostureCheck(
                title: "Biometric unlock",
                state: passFail(observation.biometryAvailable),
                detail: observation.biometryAvailable.map {
                    $0
                        ? "Face ID or Touch ID is available."
                        : "Biometrics is not enrolled on this device."
                } ?? "Biometrics could not be evaluated, or is temporarily locked out."
            )
        )

        result.append(
            PostureCheck(
                title: "File data protection",
                state: passFail(observation.fileProtectionAvailable),
                detail: observation.fileProtectionAvailable.map {
                    $0
                        ? "Protected data is available."
                        : "Protected data is unavailable. Unlock the device once since boot."
                } ?? "Not reported."
            )
        )

        let jailbreakCount = observation.jailbreakIndicators.count
        result.append(
            PostureCheck(
                title: "Jailbreak indicators",
                state: jailbreakCount == 0 ? .pass : .fail,
                detail: jailbreakCount == 0
                    ? "No known jailbreak paths, URL schemes or injected libraries were found."
                    : observation.jailbreakIndicators.joined(separator: "; ")
            )
        )

        result.append(
            PostureCheck(
                title: "Debugger",
                state: passFail(observation.isDebuggerAttached),
                detail: observation.isDebuggerAttached.map {
                    $0 ? "This process is being traced." : "This process is not traced."
                } ?? "Not reported."
            )
        )

        result.append(
            PostureCheck(
                title: "VPN tunnel",
                state: tunnelState(observation.isVPNActive),
                detail: observation.isVPNActive.map {
                    $0
                        ? "A tunnel interface is up. LAN scans may be routed through it."
                        : "No tunnel interface is carrying traffic."
                } ?? "Not reported."
            )
        )

        result.append(
            PostureCheck(
                title: "Wi-Fi security",
                state: .unknown,
                detail: "Requires the restricted Wi-Fi Info entitlement, which a free Apple ID cannot sign."
            )
        )

        if let current = observation.osVersion {
            result.append(
                PostureCheck(
                    title: "iOS version",
                    state: current < posture.recommendedOS ? .fail : .pass,
                    detail: "Running \(current); recommended \(posture.recommendedOS) or later."
                )
            )
        } else {
            result.append(
                PostureCheck(
                    title: "iOS version",
                    state: .unknown,
                    detail: "The operating system version could not be read."
                )
            )
        }

        return result
    }

    private func passFail(_ value: Bool?) -> PostureCheck.State {
        guard let value else { return .unknown }
        return value ? .pass : .fail
    }

    private func tunnelState(_ value: Bool?) -> PostureCheck.State {
        guard let value else { return .unknown }
        return value ? .notice : .pass
    }
}

// MARK: - Rows

private struct PostureCheck: Identifiable {
    enum State {
        case pass
        case fail
        case unknown
        /// Observed but not inherently a weakness, e.g. an active VPN.
        case notice
    }

    let title: String
    let state: State
    let detail: String

    var id: String { title }

    var symbol: String {
        switch state {
        case .pass: return "checkmark.circle.fill"
        case .fail: return "exclamationmark.circle.fill"
        case .unknown: return "questionmark.circle.fill"
        case .notice: return "info.circle.fill"
        }
    }

    var tint: Color {
        switch state {
        case .pass: return .green
        case .fail: return .red
        case .unknown: return .secondary
        case .notice: return .blue
        }
    }
}

private struct CheckRow: View {
    let check: PostureCheck

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Image(systemName: check.symbol)
                .foregroundStyle(check.tint)
                .accessibilityLabel(accessibilityLabel)

            VStack(alignment: .leading, spacing: 2) {
                Text(check.title)
                Text(check.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var accessibilityLabel: String {
        switch check.state {
        case .pass: return "Passed"
        case .fail: return "Failed"
        case .unknown: return "Not determined"
        case .notice: return "Informational"
        }
    }
}

struct FindingRow: View {
    let finding: Finding

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            SeverityBadge(severity: finding.severity)
            Text(finding.title)
                .font(.body)
            Text(finding.category.displayName)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }
}

struct SeverityBadge: View {
    let severity: Severity

    var body: some View {
        Text(severity.displayName.uppercased())
            .font(.caption2.weight(.bold))
            .tracking(0.5)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(tint.opacity(0.15), in: Capsule())
            .foregroundStyle(tint)
    }

    private var tint: Color {
        switch severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        case .info: return .secondary
        }
    }
}

// MARK: - Detail

struct FindingDetailView: View {
    let finding: Finding

    var body: some View {
        List {
            Section {
                HStack {
                    SeverityBadge(severity: finding.severity)
                    Spacer()
                    Text(finding.category.displayName)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Text(finding.title)
                    .font(.title3.weight(.semibold))
            }

            if let host = finding.host {
                Section("Host") {
                    Text(host)
                        .font(.callout.monospaced())
                }
            }

            Section("What was observed") {
                Text(finding.evidence)
                    .font(.callout)
            }

            Section("How to fix it") {
                Text(finding.remediation)
                    .font(.callout)
            }

            if !finding.references.isEmpty {
                Section("References") {
                    ForEach(finding.references, id: \.absoluteString) { link in
                        Link(link.absoluteString, destination: link)
                            .font(.callout)
                    }
                }
            }

            Section {
                Text("Observed \(finding.discoveredAt.formatted(date: .abbreviated, time: .shortened)).")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Finding")
        .navigationBarTitleDisplayMode(.inline)
    }
}

#Preview {
    PostureView()
        .environment(PostureStore())
}
