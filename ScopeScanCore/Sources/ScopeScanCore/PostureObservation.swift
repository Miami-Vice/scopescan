import Foundation

/// Raw facts observed about this device.
///
/// Everything here is gathered by the app target, which is the only place that
/// can touch LocalAuthentication, Network and sysctl. Keeping the observation as
/// a plain value type means every rule below can be unit-tested on any platform.
///
/// Optional fields mean "could not determine", which is deliberately different
/// from `false`: a check that cannot run must not silently become a pass.
public struct PostureObservation: Hashable, Sendable {
    public var deviceModel: String?
    public var osVersion: OSVersion?
    public var passcodeEnrolled: Bool?
    public var biometryAvailable: Bool?
    public var fileProtectionAvailable: Bool?
    public var isVPNActive: Bool?
    public var isDebuggerAttached: Bool?
    public var wifiSecurity: WifiSecurity?
    /// Human-readable evidence, e.g. "cydia:// resolved", "writable /private".
    public var jailbreakIndicators: [String]

    public init(
        deviceModel: String? = nil,
        osVersion: OSVersion? = nil,
        passcodeEnrolled: Bool? = nil,
        biometryAvailable: Bool? = nil,
        fileProtectionAvailable: Bool? = nil,
        isVPNActive: Bool? = nil,
        isDebuggerAttached: Bool? = nil,
        wifiSecurity: WifiSecurity? = nil,
        jailbreakIndicators: [String] = []
    ) {
        self.deviceModel = deviceModel
        self.osVersion = osVersion
        self.passcodeEnrolled = passcodeEnrolled
        self.biometryAvailable = biometryAvailable
        self.fileProtectionAvailable = fileProtectionAvailable
        self.isVPNActive = isVPNActive
        self.isDebuggerAttached = isDebuggerAttached
        self.wifiSecurity = wifiSecurity
        self.jailbreakIndicators = jailbreakIndicators
    }
}
