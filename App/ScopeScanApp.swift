import SwiftUI

@main
struct ScopeScanApp: App {
    @State private var posture = PostureStore()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(posture)
        }
    }
}
