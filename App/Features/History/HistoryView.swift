import SwiftUI
import ScopeScanCore

/// Saved scans, newest first. Everything shown here is decrypted on demand
/// from the on-device vault.
struct HistoryView: View {
    @State private var reports: [ReportVault.StoredReport] = []
    @State private var errorMessage: String?

    private var vault: ReportVault? { try? ReportVault() }

    var body: some View {
        NavigationStack {
            List {
                if reports.isEmpty {
                    Text("No scans saved yet. Finished scans are stored here, encrypted on this device.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(reports) { stored in
                        NavigationLink(value: stored.id) {
                            HistoryRow(export: stored.export)
                        }
                    }
                }

                if let errorMessage {
                    Text(errorMessage)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            }
            .navigationTitle("History")
            .navigationDestination(for: UUID.self) { id in
                if let stored = reports.first(where: { $0.id == id }) {
                    ReportDetailView(id: id, export: stored.export) {
                        delete(id)
                    }
                }
            }
            .toolbar {
                if !reports.isEmpty {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Clear all", role: .destructive) {
                            clearAll()
                        }
                    }
                }
            }
            .refreshable { reload() }
            .task { reload() }
        }
    }

    private func reload() {
        reports = vault?.loadAll() ?? []
    }

    private func delete(_ id: UUID) {
        do {
            try vault?.delete(id)
            errorMessage = nil
        } catch {
            errorMessage = "Could not delete that scan: \(error.localizedDescription)"
        }
        reload()
    }

    private func clearAll() {
        do {
            try vault?.deleteAll()
            errorMessage = nil
        } catch {
            errorMessage = "Could not clear history: \(error.localizedDescription)"
        }
        reload()
    }
}

private struct HistoryRow: View {
    let export: ReportExport

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(export.network)
                .font(.callout.monospaced())
            Text(export.startedAt.formatted(date: .abbreviated, time: .shortened))
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("\(export.hostsUp) up · \(export.findings.count) finding\(export.findings.count == 1 ? "" : "s")")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }
}

/// One saved scan. Exporting always goes through `redacted(_:)`, so the chosen
/// address mode is applied to the file that is shared.
private struct ReportDetailView: View {
    let id: UUID
    let export: ReportExport
    let onDelete: () -> Void

    @State private var mode: AddressRedaction = .maskLastOctet
    @State private var exportURL: URL?
    @State private var exportError: String?
    @State private var confirmDelete = false

    var body: some View {
        List {
            Section {
                LabeledContent("Network", value: export.network)
                LabeledContent("Started", value: export.startedAt.formatted(date: .abbreviated, time: .shortened))
                LabeledContent("Hosts up", value: "\(export.hostsUp) of \(export.scannedHostCount)")
                if export.refusedProbeCount > 0 {
                    LabeledContent("Refused probes", value: "\(export.refusedProbeCount)")
                }
                if export.wasCancelled {
                    Text("This scan was cancelled, so its results are partial.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("Summary")
            }

            Section {
                ForEach(export.hosts, id: \.address) { host in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(host.address)
                            .font(.callout.monospaced())
                        if let label = host.label {
                            Text(label)
                                .font(.caption)
                        }
                    }
                }
            } header: {
                Text("Hosts")
            }

            Section {
                if export.findings.isEmpty {
                    Text("No findings in this scan.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(Array(export.findings.enumerated()), id: \.offset) { _, finding in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(finding.title)
                            Text("\(finding.severity.displayName) · \(finding.category)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Text("Findings")
            }

            Section {
                Picker("Addresses", selection: $mode) {
                    ForEach(AddressRedaction.allCases, id: \.self) { option in
                        Text(option.displayName).tag(option)
                    }
                }
                .onChange(of: mode) { discardExport() }

                Button("Prepare export") {
                    prepareExport()
                }

                if let exportURL {
                    ShareLink(item: exportURL) {
                        Label("Share JSON", systemImage: "square.and.arrow.up")
                    }
                }

                if let exportError {
                    Text(exportError)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            } header: {
                Text("Export")
            } footer: {
                Text("The shared file is written in the address mode you choose. Device names from Bonjour are removed unless addresses are shown in full.")
            }

            Section {
                Button("Delete this scan", role: .destructive) {
                    confirmDelete = true
                }
            }
        }
        .navigationTitle("Scan")
        .navigationBarTitleDisplayMode(.inline)
        .onDisappear(perform: discardExport)
        .confirmationDialog("Delete this scan?", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("Delete", role: .destructive) { onDelete() }
        }
    }

    private func prepareExport() {
        discardExport()
        do {
            let data = try ReportExporter.json(export.redacted(mode))
            let name = "scopescan-\(export.startedAt.formatted(.iso8601.year().month().day().dateSeparator(.dash)))-\(mode.rawValue).json"
            let url = FileManager.default.temporaryDirectory.appendingPathComponent(name)
            try data.write(to: url, options: [.atomic, .completeFileProtection])
            exportURL = url
            exportError = nil
        } catch {
            exportURL = nil
            exportError = "Could not prepare the export: \(error.localizedDescription)"
        }
    }

    /// A redacted export is still a scan, so it is not left behind in the
    /// temporary directory once the screen is gone or the mode changes.
    private func discardExport() {
        if let exportURL {
            try? FileManager.default.removeItem(at: exportURL)
        }
        exportURL = nil
    }
}
