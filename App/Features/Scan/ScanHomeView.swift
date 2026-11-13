import SwiftUI
import ScopeScanCore

struct ScanHomeView: View {
    var body: some View {
        NavigationStack {
            ContentUnavailableView {
                Label("Scanner arrives in M2", systemImage: "dot.radiowaves.left.and.right")
            } description: {
                Text("Scope validation, interface discovery and TLS grading are next. Core module v\(CoreInfo.version) is linked and tested.")
            } actions: {
                Text("Start with the Diagnostics tab to confirm this build is running on your device.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .navigationTitle("ScopeScan")
        }
    }
}

#Preview {
    ScanHomeView()
}
