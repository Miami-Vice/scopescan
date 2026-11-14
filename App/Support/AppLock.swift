import Combine
import LocalAuthentication

/// App-level lock backed by the system's own authentication. The device passcode
/// is the fallback, so the app never stores or checks a secret of its own.
@MainActor
final class AppLock: ObservableObject {
    @Published private(set) var isLocked = true
    @Published private(set) var isAuthenticating = false
    @Published private(set) var message: String?
    /// Set when the device has no passcode, which leaves nothing to
    /// authenticate against. The lock screen offers an explicit way past it.
    @Published private(set) var hasNoPasscode = false

    private let reason = "Unlock ScopeScan to view saved scans."

    /// Called on launch and whenever the app becomes active again.
    func unlock() async {
        guard isLocked, !isAuthenticating, !hasNoPasscode else { return }

        isAuthenticating = true
        defer { isAuthenticating = false }

        let context = LAContext()
        context.localizedCancelTitle = "Lock"

        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError) else {
            if policyError?.code == LAError.passcodeNotSet.rawValue {
                hasNoPasscode = true
                message = "This device has no passcode. Set one in Settings to let ScopeScan lock."
            } else {
                message = "Unlock is unavailable: \(policyError?.localizedDescription ?? "unknown reason")."
            }
            return
        }

        do {
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            )
            if success {
                message = nil
                isLocked = false
            }
        } catch {
            // Cancelling is a normal choice, not a failure worth explaining.
            let code = (error as NSError).code
            if code != LAError.userCancel.rawValue,
               code != LAError.appCancel.rawValue,
               code != LAError.systemCancel.rawValue {
                message = "Could not unlock: \(error.localizedDescription)"
            }
        }
    }

    /// Only meaningful when the device has no passcode; without this the app
    /// would be unusable on such a device.
    func continueWithoutLock() {
        message = nil
        hasNoPasscode = false
        isLocked = false
    }

    func lock() {
        isLocked = true
        message = nil
        hasNoPasscode = false
    }
}
