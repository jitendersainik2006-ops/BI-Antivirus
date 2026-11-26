import Foundation

public enum InspectionVerdict: String, Codable, CaseIterable {
    case clean = "CLEAN"
    case threatDetected = "THREAT_DETECTED"
    case suspicious = "SUSPICIOUS"
    case unsupported = "UNSUPPORTED"
    case scanError = "SCAN_ERROR"

    public var isThreat: Bool {
        self == .threatDetected || self == .suspicious
    }

    public var isActionable: Bool {
        self == .threatDetected || self == .suspicious || self == .scanError
    }
}

public enum ThreatSeverity: String, Codable {
    case none = "NONE"
    case low = "LOW"
    case medium = "MEDIUM"
    case high = "HIGH"
    case critical = "CRITICAL"
}
