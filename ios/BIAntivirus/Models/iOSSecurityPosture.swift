import Foundation

public enum PostureStatus: String, Codable {
    case pass = "PASS"
    case warn = "WARN"
    case fail = "FAIL"
    case notApplicable = "NOT_APPLICABLE"
}

public struct PostureCheck: Identifiable, Codable {
    public let id: String
    public let name: String
    public let category: String
    public let status: PostureStatus
    public let details: String
    public let recommendation: String

    public init(
        id: String,
        name: String,
        category: String,
        status: PostureStatus,
        details: String,
        recommendation: String
    ) {
        self.id = id
        self.name = name
        self.category = category
        self.status = status
        self.details = details
        self.recommendation = recommendation
    }
}

public struct iOSSecurityPosture: Identifiable, Codable {
    public let id: String
    public let timestamp: Date
    public let deviceModel: String
    public let osVersion: String
    public let overallScore: Int
    public let statusText: String
    public let checks: [PostureCheck]

    public init(
        id: String = "REP-" + UUID().uuidString.prefix(8).uppercased(),
        timestamp: Date = Date(),
        deviceModel: String,
        osVersion: String,
        overallScore: Int,
        statusText: String,
        checks: [PostureCheck]
    ) {
        self.id = id
        self.timestamp = timestamp
        self.deviceModel = deviceModel
        self.osVersion = osVersion
        self.overallScore = overallScore
        self.statusText = statusText
        self.checks = checks
    }
}
