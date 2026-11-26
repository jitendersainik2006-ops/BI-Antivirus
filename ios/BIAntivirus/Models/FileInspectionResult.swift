import Foundation

public struct FileInspectionResult: Identifiable, Codable {
    public let id: String
    public let timestamp: Date
    public let fileName: String
    public let filePath: String
    public let fileSize: Int64
    public let sha256: String
    public let md5: String
    public let entropy: Double
    public let verdict: InspectionVerdict
    public let threatName: String?
    public let threatFamily: String?
    public let severity: ThreatSeverity
    public let matchedRules: [String]
    public var isQuarantined: BooleanLiteralType
    public let errorMessage: String?

    public init(
        id: String = "INSP-" + UUID().uuidString.prefix(8).uppercased(),
        timestamp: Date = Date(),
        fileName: String,
        filePath: String,
        fileSize: Int64,
        sha256: String,
        md5: String = "",
        entropy: Double = 0.0,
        verdict: InspectionVerdict,
        threatName: String? = nil,
        threatFamily: String? = nil,
        severity: ThreatSeverity = .none,
        matchedRules: [String] = [],
        isQuarantined: Bool = false,
        errorMessage: String? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.fileName = fileName
        self.filePath = filePath
        self.fileSize = fileSize
        self.sha256 = sha256
        self.md5 = md5
        self.entropy = entropy
        self.verdict = verdict
        self.threatName = threatName
        self.threatFamily = threatFamily
        self.severity = severity
        self.matchedRules = matchedRules
        self.isQuarantined = isQuarantined
        self.errorMessage = errorMessage
    }
}
