import SwiftUI

@main
struct ScopeScanApp: App {
    @State private var posture = PostureStore()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(posture)
                .overlay {
                    // The app switcher snapshots the screen as the app leaves the
                    // foreground. Covering it keeps scan results out of that image.
                    if scenePhase != .active {
                        PrivacyCover()
                    }
                }
        }
    }
}

private struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Rectangle()
                .fill(.background)
                .ignoresSafeArea()
            Label("ScopeScan", systemImage: "lock.shield")
                .font(.headline)
                .foregroundStyle(.secondary)
        }
    }
}
