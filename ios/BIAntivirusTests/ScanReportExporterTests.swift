import XCTest
@testable import BIAntivirus

final class ScanReportExporterTests: XCTestCase {

    func testExportToJSONGeneratesValidStructure() {
        let results = [
            FileInspectionResult(
                fileName = "clean.pdf",
                filePath = "/Documents/clean.pdf",
                fileSize = 1024,
                sha256 = "1111111111111111111111111111111111111111111111111111111111111111",
                md5 = "22222222222222222222222222222222",
                entropy = 4.5,
                verdict = .clean,
                severity = .none
            ),
            FileInspectionResult(
                fileName = "payload.bin",
                filePath = "/Downloads/payload.bin",
                fileSize = 4096,
                sha256 = "3333333333333333333333333333333333333333333333333333333333333333",
                md5 = "44444444444444444444444444444444",
                entropy = 7.9,
                verdict = .suspicious,
                threatName = "HighEntropyPacked",
                threatFamily = "Suspicious",
                severity = .high,
                matchedRules: ["HEUR:HIGH_SHANNON_ENTROPY"]
            ),
            FileInspectionResult(
                fileName = "unsupported.xyz",
                filePath = "/Downloads/unsupported.xyz",
                fileSize = 256,
                sha256 = "5555555555555555555555555555555555555555555555555555555555555555",
                verdict = .unsupported,
                errorMessage = "Unsupported extension"
            ),
            FileInspectionResult(
                fileName = "corrupted.bin",
                filePath = "/Downloads/corrupted.bin",
                fileSize = 50,
                sha256 = "6666666666666666666666666666666666666666666666666666666666666666",
                verdict = .scanError,
                errorMessage = "Truncated file"
            )
        ]

        let jsonString = ScanReportExporter.exportToJSON(results: results, scanDurationMs: 250, deviceModel: "iPhone 15 Pro")
        guard let data = jsonString.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            XCTFail("Failed to parse exported JSON")
            return
        }

        XCTAssertEqual(json["reportVersion"] as? String, "1.0.0")
        XCTAssertEqual(json["deviceInfo"] as? String, "iPhone 15 Pro")
        XCTAssertEqual(json["totalFilesScanned"] as? Int, 4)
        XCTAssertEqual(json["threatsDetectedCount"] as? Int, 0)
        XCTAssertEqual(json["suspiciousCount"] as? Int, 1)
        XCTAssertEqual(json["cleanCount"] as? Int, 1)
        XCTAssertEqual(json["unsupportedCount"] as? Int, 1)
        XCTAssertEqual(json["scanErrorCount"] as? Int, 1)
    }

    func testExportToMarkdownContainsExpectedHeadings() {
        let results = [
            FileInspectionResult(
                fileName = "test.txt",
                filePath = "/test.txt",
                fileSize = 100,
                sha256 = "abcdef123456abcdef123456abcdef123456abcdef123456abcdef123456abcd",
                verdict = .clean
            )
        ]

        let md = ScanReportExporter.exportToMarkdown(results: results, scanDurationMs: 50)
        XCTAssertTrue(md.contains("# BI Antivirus Enterprise — iOS Security Inspection Report"))
        XCTAssertTrue(md.contains("Clean Items:** 1"))
        XCTAssertTrue(md.contains("`test.txt`"))
    }
}
