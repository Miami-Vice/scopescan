import SwiftUI
import UIKit

struct DiagnosticsView: View {
    @State private var sections: [DiagnosticsSection] = []
    @State private var report: String = ""
    @State private var probeOutput: String = "not probed"
    @State private var isProbing = false

    var body: some View {
        NavigationStack {
            List {
                localNetworkSection

                ForEach(sections) { section in
                    Section(section.title) {
                        ForEach(section.rows) { row in
                            rowView(row)
                        }
                    }
                }

                exportSection
            }
            .navigationTitle("Diagnostics")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Refresh", systemImage: "arrow.clockwise") {
                        Task { await reload() }
                    }
                }
            }
            .refreshable { await reload() }
            .task { await reload() }
        }
    }

    private var localNetworkSection: some View {
        Section {
            Button {
                Task { await runProbe() }
            } label: {
                Label(
                    isProbing ? "Probing…" : "Probe local network",
                    systemImage: "antenna.radiowaves.left.and.right"
                )
            }
            .disabled(isProbing)

            rowView(DiagnosticsRow(label: "Result", value: probeOutput))
        } header: {
            Text("Local network access")
        } footer: {
            Text("Sends one TCP connect attempt to the gateway on port 80. iOS shows its Local Network prompt the first time. A \"waiting:\" result usually means permission was denied.")
        }
    }

    private var exportSection: some View {
        Section {
            ShareLink(item: report) {
                Label("Share report", systemImage: "square.and.arrow.up")
            }

            Button {
                UIPasteboard.general.string = report
            } label: {
                Label("Copy report", systemImage: "doc.on.doc")
            }
        } header: {
            Text("Export")
        } footer: {
            Text("Paste this back into the build agent to confirm the APIs behave as expected on real hardware.")
        }
    }

    private func rowView(_ row: DiagnosticsRow) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(row.label)
                .foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(row.value)
                .multilineTextAlignment(.trailing)
        }
        .font(.callout)
    }

    private func reload() async {
        sections = DiagnosticsBuilder.sections(probeOutput: probeOutput)
        report = DiagnosticsBuilder.renderedText(from: sections)
    }

    private func runProbe() async {
        isProbing = true
        defer { isProbing = false }

        guard let interface = NetworkInterfaces.primaryIPv4(),
              let gateway = NetworkInterfaces.gatewayGuess(for: interface.address)
        else {
            probeOutput = "no IPv4 interface"
            await reload()
            return
        }

        probeOutput = await TCPProbe.connect(host: gateway, port: 80, timeout: 2.5)
        await reload()
    }
}

#Preview {
    DiagnosticsView()
}
