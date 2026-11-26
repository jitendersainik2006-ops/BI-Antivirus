import Foundation

public struct iOSSecurityRecommendation: Identifiable {
    public let id: String
    public let title: String
    public let detail: String
    public let severity: String
    public let actionTitle: String
}

public final class PrivacySettingsManager: ObservableObject {

    public static let shared = PrivacySettingsManager()

    private let defaults = UserDefaults.standard

    private let keyTelemetry = "com.biantivirus.ios.telemetry"
    private let keyCloudLookup = "com.biantivirus.ios.cloudlookup"
    private let keyAutoQuarantine = "com.biantivirus.ios.autoquarantine"

    // Default to strict local privacy
    @Published public var isTelemetryEnabled: Bool {
        didSet { defaults.set(isTelemetryEnabled, forKey: keyTelemetry) }
    }

    @Published public var isCloudLookupEnabled: Bool {
        didSet { defaults.set(isCloudLookupEnabled, forKey: keyCloudLookup) }
    }

    @Published public var isAutoQuarantineEnabled: Bool {
        didSet { defaults.set(isAutoQuarantineEnabled, forKey: keyAutoQuarantine) }
    }

    public init() {
        self.isTelemetryEnabled = defaults.bool(forKey: keyTelemetry)
        self.isCloudLookupEnabled = defaults.bool(forKey: keyCloudLookup)
        self.isAutoQuarantineEnabled = defaults.bool(forKey: keyAutoQuarantine)
    }

    public func generateRecommendations(posture: iOSSecurityPosture) -> [iOSSecurityRecommendation] {
        var recs: [iOSSecurityRecommendation] = []

        if !posture.isPasscodeConfigured {
            recs.append(
                iOSSecurityRecommendation(
                    id = "REC-IOS-PASSCODE",
                    title = "Set Device Passcode",
                    detail = "No device passcode is configured. Data protection classes cannot encrypt files at rest.",
                    severity = "CRITICAL",
                    actionTitle = "Settings > Face ID & Passcode"
                )
            )
        }

        if !posture.isBiometricsEnabled {
            recs.append(
                iOSSecurityRecommendation(
                    id = "REC-IOS-BIOMETRICS",
                    title = "Enable Face ID / Touch ID",
                    detail = "Biometric authentication enhances defense against physical shoulder-surfing attacks.",
                    severity = "MEDIUM",
                    actionTitle = "Configure Biometrics"
                )
            )
        }

        if !posture.isLatestOSVersion {
            recs.append(
                iOSSecurityRecommendation(
                    id = "REC-IOS-UPDATE",
                    title = "Update iOS Firmware",
                    detail = "Running iOS \(posture.osVersion). Apple patches critical WebKit and kernel zero-days in newer minor updates.",
                    severity = "HIGH",
                    actionTitle = "Software Update"
                )
            )
        }

        return recs
    }
}
