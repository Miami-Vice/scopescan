import SwiftUI

/// Shown until the device owner authenticates. It is opaque, so saved scans are
/// not visible behind it.
struct LockScreenView: View {
    @ObservedObject var lock: AppLock

    var body: some View {
        ZStack {
            Rectangle()
                .fill(.background)
                .ignoresSafeArea()

            VStack(spacing: 16) {
                Image(systemName: "lock.shield")
                    .font(.system(size: 56))
                    .foregroundStyle(.secondary)

                Text("ScopeScan is locked")
                    .font(.title2.weight(.semibold))

                Text("Saved scans stay encrypted until you unlock.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                if let message = lock.message {
                    Text(message)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }

                if lock.hasNoPasscode {
                    Button("Continue without lock") {
                        lock.continueWithoutLock()
                    }
                    .buttonStyle(.bordered)
                } else {
                    Button {
                        Task { await lock.unlock() }
                    } label: {
                        if lock.isAuthenticating {
                            ProgressView()
                        } else {
                            Text("Unlock")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(lock.isAuthenticating)
                }
            }
            .padding(32)
        }
    }
}
