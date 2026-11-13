import SwiftUI
import ScopeScanCore

struct ScanHomeView: View {
    @Environment(PostureStore.self) private var posture
    @State private var scan = ScanStore()

    var body: some View {
        NavigationStack {
            List {
                postureSection
                scopeSection
                if scan.phase != .idle {
                    progressSection
                }
                if let report = scan.report {
                    resultsSections(report)
                }
            }
            .navigationTitle("ScopeScan")
            .navigationDestination(for: Finding.self) { finding in
                FindingDetailView(finding: finding)
            }
            .navigationDestination(for: HostReport.self) { host in
                HostDetailView(host: host)
            }
            .task {
                await posture.refreshIfNeeded()
                scan.prepare()
            }
        }
    }

    // MARK: - Posture summary

    private var postureSection: some View {
        Section {
            if posture.lastRefreshed == nil {
                if posture.isRefreshing {
                    HStack(spacing: 12) {
                        ProgressView()
                        Text("Checking this device…")
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Text("Not checked yet.")
                        .foregroundStyle(.secondary)
                    Button("Check posture") {
                        Task { await posture.refresh() }
                    }
                }
            } else if let severity = posture.highestSeverity {
                HStack(spacing: 12) {
                    SeverityBadge(severity: severity)
                    Text("\(posture.findings.count) finding\(posture.findings.count == 1 ? "" : "s")")
                }

                ForEach(posture.findings.prefix(3)) { finding in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(finding.title)
                        Text(finding.category.displayName)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } else {
                Label {
                    Text("No weaknesses observed")
                } icon: {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                }
            }
        } header: {
            Text("Device posture")
        } footer: {
            if posture.findings.count > 3 {
                Text("\(posture.findings.count - 3) more on the Posture tab.")
            } else if posture.lastRefreshed != nil {
                Text("Open the Posture tab for evidence and remediation. Checks that could not run are never counted as passes.")
            } else {
                Text("Passcode, biometrics, jailbreak indicators, debugger and tunnel state.")
            }
        }
    }

    // MARK: - Scope

    private var scopeSection: some View {
        Section {
            if let suggested = scan.suggestedScope {
                LabeledContent("Wi-Fi network", value: suggested.cidr)
            } else {
                Text("No private Wi-Fi address found. Enter a network you own.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            TextField("192.168.1.0/24", text: $scan.cidrText)
                .font(.callout.monospaced())
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.numbersAndPunctuation)

            if case .failure(let error)? = scan.validatedScope {
                Label(error.localizedDescription, systemImage: "exclamationmark.triangle")
                    .font(.footnote)
                    .foregroundStyle(.red)
            }

            if scan.hasActiveTunnel {
                Label {
                    Text("A VPN tunnel is active. Traffic may be routed away from this network, so results may not reflect it.")
                        .font(.footnote)
                } icon: {
                    Image(systemName: "lock.trianglebadge.exclamationmark")
                }
                .foregroundStyle(.orange)
            }

            Toggle("I own this network or am authorized to scan it", isOn: $scan.ownershipConfirmed)

            if scan.phase == .running {
                Button("Cancel scan", role: .destructive) { scan.cancel() }
            } else {
                Button("Start scan") { scan.start() }
                    .disabled(!scan.canStart)
            }
        } header: {
            Text("Network scan")
        } footer: {
            Text("Probes TCP ports on the network you choose, up to 1,024 hosts (/22). Only hosts you own or are authorized to test should be scanned.")
        }
    }

    // MARK: - Progress

    private var progressSection: some View {
        Section {
            if let progress = scan.progress, scan.phase == .running {
                ProgressView(value: progress.fraction) {
                    Text("\(progress.hostsCompleted) of \(progress.hostCount) hosts")
                }
                Text("\(progress.hostsUp) up · \(progress.openPortCount) open ports so far")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else if scan.phase == .running {
                HStack(spacing: 12) {
                    ProgressView()
                    Text("Starting…")
                        .foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("Progress")
        }
    }

    // MARK: - Results

    @ViewBuilder
    private func resultsSections(_ report: ScanReport) -> some View {
        Section {
            if report.localNetworkDenied {
                Label {
                    Text("Local Network access was denied. Allow it in Settings → Privacy & Security → Local Network, then scan again.")
                        .font(.footnote)
                } icon: {
                    Image(systemName: "hand.raised.fill")
                }
                .foregroundStyle(.red)
            }

            LabeledContent("Network", value: report.cidr)
            LabeledContent("Hosts probed", value: "\(report.scannedHostCount)")
            LabeledContent("Hosts up", value: "\(report.hostsUp)")
            LabeledContent("Duration", value: Duration.seconds(report.duration).formatted(.units(allowed: [.minutes, .seconds], width: .narrow)))

            if report.wasCancelled {
                Label("Scan was cancelled. Results are partial.", systemImage: "stop.circle")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("Summary")
        }

        Section {
            if report.findings.isEmpty {
                Text(report.hostsUp == 0
                     ? "No hosts answered. Silent hosts are not reported, so this is not proof the network is empty."
                     : "No exposed services in the catalog. Only catalogued ports are checked.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(report.findings) { finding in
                    NavigationLink(value: finding) {
                        FindingRow(finding: finding)
                    }
                }
            }
        } header: {
            Text("Findings")
        }

        Section {
            if report.hosts.isEmpty {
                Text("No hosts answered.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(report.hosts) { host in
                    NavigationLink(value: host) {
                        HostRow(host: host)
                    }
                }
            }
        } header: {
            Text("Hosts")
        }

        Section {
            if report.bonjour.isEmpty {
                Text("No Bonjour services announced.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(report.bonjour) { service in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(service.name)
                        Text(service.displayType)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        } header: {
            Text("Bonjour services")
        } footer: {
            Text("Advertised services are inventory, not findings. Devices that stay silent to multicast are not listed.")
        }
    }
}

private struct HostRow: View {
    let host: HostReport

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(host.address.description)
                .font(.callout.monospaced())
            Text(summary)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var summary: String {
        guard !host.openPorts.isEmpty else { return "Up, no catalogued ports open" }
        return host.openPorts.map { ServiceCatalog.name(for: $0) }.joined(separator: ", ")
    }
}

private struct HostDetailView: View {
    let host: HostReport

    var body: some View {
        List {
            Section("Address") {
                Text(host.address.description)
                    .font(.callout.monospaced())
            }
            Section("Open ports") {
                if host.openPorts.isEmpty {
                    Text("None of the catalogued ports accepted a connection.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(host.openPorts, id: \.self) { port in
                        LabeledContent("\(port)", value: ServiceCatalog.name(for: port))
                    }
                }
            }
        }
        .navigationTitle("Host")
        .navigationBarTitleDisplayMode(.inline)
    }
}

#Preview {
    ScanHomeView()
        .environment(PostureStore())
}
