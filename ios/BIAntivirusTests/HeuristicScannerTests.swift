//
//  HeuristicScannerTests.swift
//  BIAntivirusTests
//
//  Unit tests for HeuristicScanner double extension, entropy, and pattern evaluation.
//

import XCTest
@testable import BIAntivirus

final class HeuristicScannerTests: XCTestCase {

    func testCleanFileEvaluatesClean() {
        let result = HeuristicScanner.evaluate(
            fileName: "financial_report.pdf",
            fileSize: 45000,
            entropy: 4.5,
            sampleData: "Safe document content".data(using: .utf8)
        )

        XCTAssertFalse(result.isSuspicious)
        XCTAssertTrue(result.matchedRules.isEmpty)
        XCTAssertEqual(result.severity, .none)
    }

    func testDoubleExtensionTrigger() {
        let result = HeuristicScanner.evaluate(
            fileName: "invoice.pdf.apk",
            fileSize: 15000,
            entropy: 4.8,
            sampleData: nil
        )

        XCTAssertTrue(result.isSuspicious)
        XCTAssertTrue(result.matchedRules.contains { $0.contains("HEUR:SUSPICIOUS_DOUBLE_EXTENSION") })
        XCTAssertEqual(result.severity, .medium)
    }

    func testHighEntropyPackedBinaryTrigger() {
        let result = HeuristicScanner.evaluate(
            fileName: "unknown_payload.bin",
            fileSize: 10240,
            entropy: 7.85,
            sampleData: nil
        )

        XCTAssertTrue(result.isSuspicious)
        XCTAssertTrue(result.matchedRules.contains { $0.contains("HEUR:HIGH_SHANNON_ENTROPY") })
    }

    func testEicarPatternDetection() {
        let eicarString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        let data = eicarString.data(using: .isoLatin1)

        let result = HeuristicScanner.evaluate(
            fileName: "test_eicar.com",
            fileSize: Int64(data?.count ?? 68),
            entropy: 5.2,
            sampleData: data
        )

        XCTAssertTrue(result.isSuspicious)
        XCTAssertTrue(result.matchedRules.contains("HEUR:EICAR_PATTERN_DETECTED"))
        XCTAssertEqual(result.severity, .critical)
        XCTAssertEqual(result.threatFamily, "TestVirus")
    }

    func testUntypedMobileConfigProfileDetection() {
        let payload = "<?xml><dict><key>PayloadType</key><string>Configuration</string></dict>"
        let data = payload.data(using: .utf8)

        let result = HeuristicScanner.evaluate(
            fileName: "vpn_profile.mobileconfig",
            fileSize: Int64(data?.count ?? 100),
            entropy: 4.2,
            sampleData: data
        )

        XCTAssertTrue(result.isSuspicious)
        XCTAssertTrue(result.matchedRules.contains("HEUR:UNTYPED_MOBILE_CONFIG_PROFILE"))
    }
}
