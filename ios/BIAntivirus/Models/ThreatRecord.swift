import Foundation

public struct ThreatRecord: Identifiable, Codable, Equatable {
    public let id: String
    public let name: String
    public let family: String
    public let severity: ThreatSeverity
    public let sha256: String
    public let md5: String
    public let description: String

    public init(
        id: String,
        name: String,
        family: String,
        severity: ThreatSeverity,
        sha256: String,
        md5: String,
        description: String
    ) {
        self.id = id
        self.name = name
        self.family = family
        self.severity = severity
        self.sha256 = sha256.lowercased()
        self.md5 = md5.lowercased()
        self.description = description
    }
}
