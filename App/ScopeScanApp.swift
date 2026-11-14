import SwiftUI

@main
struct ScopeScanApp: App {
    @State private var posture = PostureStore()
    @State private var lock = AppLock()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ZStack {
                RootView()
                    .environment(posture)

                if lock.isLocked {
                    LockScreenView(lock: lock)
                        .transition(.opacity)
                }
            }
            .animation(.easeInOut(duration: 0.15), value: lock.isLocked)
            .task {
                // The UIKit cover has to be installed before the first time the
                // app is backgrounded, so it is set up with the root view.
                PrivacyScreen.shared.start()
                await lock.unlock()
            }
            .onChange(of: scenePhase) { _, phase in
                switch phase {
                case .active:
                    Task { await lock.unlock() }
                case .background:
                    lock.lock()
                default:
                    break
                }
            }
        }
    }
}
