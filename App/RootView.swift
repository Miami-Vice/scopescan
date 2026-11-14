import SwiftUI

struct RootView: View {
    var body: some View {
        TabView {
            ScanHomeView()
                .tabItem { Label("Scan", systemImage: "dot.radiowaves.left.and.right") }

            PostureView()
                .tabItem { Label("Posture", systemImage: "checkmark.shield") }

            HistoryView()
                .tabItem { Label("History", systemImage: "clock.arrow.circlepath") }

            DiagnosticsView()
                .tabItem { Label("Diagnostics", systemImage: "stethoscope") }
        }
    }
}

#Preview {
    RootView()
        .environment(PostureStore())
}
