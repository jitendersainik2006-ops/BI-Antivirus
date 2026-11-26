import Foundation

public struct VaultedThreat: Identifiable, Codable {
    public let id: String
    public let originalFileName: String
    public let originalPath: String
    public let quarantinedDate: Date
    public let sha256: String
    public let threatName: String
    public let vaultFilePath: String
    public let fileSize: Int64

    public init(
        id: String = "Q-" + UUID().uuidString.prefix(8).uppercased(),
        originalFileName: String,
        originalPath: String,
        quarantinedDate: Date = Date(),
        sha256: String,
        threatName: String,
        vaultFilePath: String,
        fileSize: Int64
    ) {
        self.id = id
        self.originalFileName = originalFileName
        self.originalPath = originalPath
        self.quarantinedDate = quarantinedDate
        self.sha256 = sha256
        self.threatName = threatName
        self.vaultFilePath = vaultFilePath
        self.fileSize = fileSize
    }
}
