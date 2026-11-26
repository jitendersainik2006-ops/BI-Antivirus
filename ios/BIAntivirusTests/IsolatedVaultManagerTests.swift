import XCTest
import CryptoKit
@testable import BIAntivirus

final class IsolatedVaultManagerTests: XCTestCase {

    var tempVaultDir: URL!
    var tempRestoreDir: URL!
    var vaultManager: IsolatedVaultManager!

    override func setUp() {
        super.setUp()
        let tempBase = FileManager.default.temporaryDirectory
        tempVaultDir = tempBase.appendingPathComponent("vault_test_\(UUID().uuidString)", isDirectory: true)
        tempRestoreDir = tempBase.appendingPathComponent("restore_test_\(UUID().uuidString)", isDirectory: true)

        try? FileManager.default.createDirectory(at: tempVaultDir, withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(at: tempRestoreDir, withIntermediateDirectories: true)

        vaultManager = IsolatedVaultManager(customVaultDirectory: tempVaultDir)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempVaultDir)
        try? FileManager.default.removeItem(at: tempRestoreDir)
        super.tearDown()
    }

    func testQuarantineAndLedgerPersistence() throws {
        let sampleData = "Malicious mobile configuration profile payload".data(using: .utf8)!
        let sha256 = SHA256.hash(data: sampleData).map { String(format: "%02x", $0) }.joined()

        let record = try vaultManager.quarantine(
            fileName: "bad_profile.mobileconfig",
            originalPath: "/Users/mobile/bad_profile.mobileconfig",
            data: sampleData,
            threatName: "iOS.Phishing.ConfigProfile",
            sha256: sha256
        )

        XCTAssertEqual(record.status, .quarantined)
        XCTAssertEqual(record.originalFileName, "bad_profile.mobileconfig")
        XCTAssertTrue(FileManager.default.fileExists(atPath: record.vaultFilePath))

        // Reload manager to verify persistence
        let reloaded = IsolatedVaultManager(customVaultDirectory: tempVaultDir)
        let history = reloaded.getLedgerHistory()
        XCTAssertEqual(history.count, 1)
        XCTAssertEqual(history.first?.id, record.id)
    }

    func testUniqueNonceProducesDifferentCiphertextForIdenticalPayload() throws {
        let payload = "Identical payload bytes for encryption randomization testing".data(using: .utf8)!
        let sha256 = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()

        let rec1 = try vaultManager.quarantine(
            fileName: "file1.bin",
            originalPath: "/path/file1.bin",
            data: payload,
            threatName: "Threat1",
            sha256: sha256
        )

        let rec2 = try vaultManager.quarantine(
            fileName: "file2.bin",
            originalPath: "/path/file2.bin",
            data: payload,
            threatName: "Threat1",
            sha256: sha256
        )

        let bytes1 = try Data(contentsOf: URL(fileURLWithPath: rec1.vaultFilePath))
        let bytes2 = try Data(contentsOf: URL(fileURLWithPath: rec2.vaultFilePath))

        // With Apple CryptoKit AES.GCM and unique 12-byte random nonces, sealed boxes must be distinct
        XCTAssertNotEqual(bytes1, bytes2)
    }

    func testRestoreWithIntegrityVerification() throws {
        let payload = "Sensitive enterprise presentation content".data(using: .utf8)!
        let sha256 = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()

        let record = try vaultManager.quarantine(
            fileName: "deck.key",
            originalPath: "/Users/mobile/deck.key",
            data: payload,
            threatName: "Heuristic.Anomaly",
            sha256: sha256
        )

        let result = vaultManager.restoreItem(id: record.id, destinationDirectory: tempRestoreDir, allowOverwrite: false)
        guard case let .success(restoredURL, verifiedSha) = result else {
            XCTFail("Expected successful restore")
            return
        }

        XCTAssertEqual(verifiedSha, sha256)
        XCTAssertEqual(restoredURL.lastPathComponent, "deck.key")
        let restoredData = try Data(contentsOf: restoredURL)
        XCTAssertEqual(restoredData, payload)
    }

    func testRestoreRefusesOverwriteWithoutFlag() throws {
        let payload = "File data".data(using: .utf8)!
        let sha256 = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()

        let record = try vaultManager.quarantine(
            fileName: "existing.txt",
            originalPath: "/path/existing.txt",
            data: payload,
            threatName: "TestThreat",
            sha256: sha256
        )

        // Pre-create destination file
        let existingURL = tempRestoreDir.appendingPathComponent("existing.txt")
        try "Original untouched text".write(to: existingURL, atomically: true, encoding: .utf8)

        let result = vaultManager.restoreItem(id: record.id, destinationDirectory: tempRestoreDir, allowOverwrite: false)
        guard case .destinationExists = result else {
            XCTFail("Expected destinationExists rejection")
            return
        }

        // Test with allowOverwrite = true
        let overwriteResult = vaultManager.restoreItem(id: record.id, destinationDirectory: tempRestoreDir, allowOverwrite: true)
        guard case .success = overwriteResult else {
            XCTFail("Expected success when allowOverwrite is true")
            return
        }
    }

    func testTamperedVaultFileTriggersTamperDetected() throws {
        let payload = "Authentic original payload".data(using: .utf8)!
        let sha256 = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()

        let record = try vaultManager.quarantine(
            fileName: "data.bin",
            originalPath: "/path/data.bin",
            data: payload,
            threatName: "TestThreat",
            sha256: sha256
        )

        // Tamper with vault file on disk
        let vaultURL = URL(fileURLWithPath: record.vaultFilePath)
        var tampered = try Data(contentsOf: vaultURL)
        tampered[0] ^= 0xFF
        try tampered.write(to: vaultURL)

        let result = vaultManager.restoreItem(id: record.id, destinationDirectory: tempRestoreDir, allowOverwrite: false)
        guard case .tamperDetected = result else {
            XCTFail("Expected tamperDetected error")
            return
        }
    }
}
