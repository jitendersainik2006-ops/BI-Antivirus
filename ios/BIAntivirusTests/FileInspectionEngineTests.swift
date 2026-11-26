//
//  FileInspectionEngineTests.swift
//  BIAntivirusTests
//
//  Unit tests for FileInspectionEngine integration and verdict assignment.
//

import XCTest
@testable import BIAntivirus

final class FileInspectionEngineTests: XCTestCase {

    var engine: FileInspectionEngine!
    var catalog: ThreatCatalog!

    override func setUp() {
        super.setUp()
        catalog = ThreatCatalog()
        engine = FileInspectionEngine(catalog: catalog)
    }

    func testInspectCleanMemoryData() {
        let cleanText = "This is a clean corporate report file content."
        let data = cleanText.data(using: .utf8)!

        let result = engine.inspect(data: data, fileName: "quarterly_review.txt")

        XCTAssertEqual(result.verdict, .clean)
        XCTAssertNil(result.threatName)
        XCTAssertEqual(result.severity, .none)
        XCTAssertFalse(result.sha256.isEmpty)
    }

    func testInspectEicarSignatureDirectHit() {
        let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        let data = eicar.data(using: .isoLatin1)!

        let result = engine.inspect(data: data, fileName: "eicar.com")

        XCTAssertEqual(result.verdict, .threatDetected)
        XCTAssertEqual(result.severity, .critical)
        XCTAssertNotEqual(result.verdict, .clean)
    }

    func testInspectDoubleExtensionSuspiciousVerdict() {
        let dummyApkData = Data([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x08, 0x00])

        let result = engine.inspect(data: dummyApkData, fileName: "document.pdf.apk")

        XCTAssertEqual(result.verdict, .suspicious)
        XCTAssertTrue(result.matchedRules.contains { $0.contains("HEUR:SUSPICIOUS_DOUBLE_EXTENSION") })
        XCTAssertNotEqual(result.verdict, .clean)
    }

    func testCorruptedFileNeverReportsClean() {
        let corruptPayload = "Corrupted and truncated binary stream header.\n[TRUNCATED_STREAM_AT_OFFSET_0x4F]"
        let data = corruptPayload.data(using: .utf8)!

        let result = engine.inspect(data: data, fileName: "corrupted.bin")

        XCTAssertEqual(result.verdict, .scanError)
        XCTAssertNotEqual(result.verdict, .clean)
        XCTAssertNotNil(result.errorMessage)
    }

    func testUnsupportedFormatNeverReportsClean() {
        let data = "Unsupported proprietary binary format container".data(using: .utf8)!

        let result = engine.inspect(data: data, fileName: "test.xyz")

        XCTAssertEqual(result.verdict, .unsupported)
        XCTAssertNotEqual(result.verdict, .clean)
        XCTAssertNotNil(result.errorMessage)
    }
}
