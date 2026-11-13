import SwiftUI
import ScopeScanCore

struct ScanHomeView: View {
    @Environment(PostureStore.self) private var posture

    var body: some View {
        NavigationStack {
            List {
                postureSection
                scannerSection
            }
            .navigationTitle("ScopeScan")
            .task { await posture.refreshIfNeeded() }
        }
    }

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

    private var scannerSection: some View {
        Section {
            Label("Scanner arrives in M2", systemImage: "dot.radiowaves.left.and.right")
            Text("Scope validation, host discovery and TLS grading are next.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        } header: {
            Text("Network scan")
        } footer: {
            Text("Core module v\(CoreInfo.version) is linked and tested. Diagnostics reports what this device can observe.")
        }
    }
}

#Preview {
    ScanHomeView()
        .environment(PostureStore())
}
