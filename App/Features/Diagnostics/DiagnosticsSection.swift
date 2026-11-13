import Foundation

struct DiagnosticsRow: Identifiable {
    let id = UUID()
    let label: String
    let value: String
}

struct DiagnosticsSection: Identifiable {
    let id = UUID()
    let title: String
    let rows: [DiagnosticsRow]
}
