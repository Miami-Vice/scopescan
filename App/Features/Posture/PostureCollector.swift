import Foundation
import LocalAuthentication
import UIKit
import ScopeScanCore

/// Gathers the raw facts the posture rules judge.
///
/// This is the only file in the posture feature that touches Apple frameworks,
/// which is deliberate: everything downstream is a pure value type.
@MainActor
enum PostureCollector {
    static func collect() -> PostureObservation {
        PostureObservation(
            deviceModel: Hardware.identifier(),
            osVersion: currentOSVersion(),
            passcodeEnrolled: passcodeState(),
            biometryAvailable: biometryAvailability(),
            fileProtectionAvailable: UIApplication.shared.isProtectedDataAvailable,
            isVPNActive: NetworkInterfaces.hasActiveTunnel(),
            isDebuggerAttached: DebuggerDetector.isAttached(),
            // Wi-Fi SSID and security require com.apple.developer.networking.wifi-info,
            // a restricted entitlement a free personal team cannot obtain. Left
            // undetermined rather than guessed, so the rule stays silent.
            wifiSecurity: nil,
            jailbreakIndicators: JailbreakDetector.indicators()
        )
    }

    private static func currentOSVersion() -> OSVersion {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return OSVersion(version.majorVersion, version.minorVersion, version.patchVersion)
    }

    /// Returns nil when the answer is genuinely unknown.
    ///
    /// `canEvaluatePolicy(.deviceOwnerAuthentication)` reports whether a passcode
    /// *or* biometrics is enrolled, and returns `.passcodeNotSet` specifically
    /// when neither is. Other errors mean we learned nothing and must not report
    /// a missing passcode that isn't missing.
    private static func passcodeState() -> Bool? {
        let context = LAContext()
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            return true
        }
        if let laError = error as? LAError, laError.code == .passcodeNotSet {
            return false
        }
        return nil
    }

    private static func biometryAvailability() -> Bool? {
        let context = LAContext()
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            return true
        }
        guard let laError = error as? LAError else { return nil }
        switch laError.code {
        case .biometryNotEnrolled, .biometryNotAvailable:
            return false
        case .biometryLockout:
            // Temporarily locked out after failed attempts; not a posture problem.
            return nil
        default:
            return false
        }
    }
}
