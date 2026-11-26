//
//  HashCalculatorTests.swift
//  BIAntivirusTests
//
//  Unit tests for HashCalculator cryptographic hashing (SHA-256 and MD5).
//

import XCTest
@testable import BIAntivirus

final class HashCalculatorTests: XCTestCase {

    func testEmptyDataHashes() {
        let emptyData = Data()
        let result = HashCalculator.computeHashes(for: emptyData)

        // SHA-256 of empty string is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        XCTAssertEqual(result.sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        // MD5 of empty string is d41d8cd98f00b204e9800998ecf8427e
        XCTAssertEqual(result.md5, "d41d8cd98f00b204e9800998ecf8427e")
        XCTAssertEqual(result.bytesProcessed, 0)
    }

    func testKnownStringHashes() {
        let testString = "BI-Antivirus-Enterprise-Cross-Platform-Test-Vector"
        guard let data = testString.data(using: .utf8) else {
            XCTFail("Failed to encode test string")
            return
        }

        let result = HashCalculator.computeHashes(for: data)
        XCTAssertEqual(result.sha256.count, 64)
        XCTAssertEqual(result.md5.count, 32)
        XCTAssertEqual(result.bytesProcessed, Int64(data.count))
    }

    func testTemporaryFileStreamHashing() throws {
        let tempDir = FileManager.default.temporaryDirectory
        let tempFile = tempDir.appendingPathComponent("test_hash_\(UUID().uuidString).txt")
        let content = "Enterprise security hashing stream test vector for iOS."
        try content.write(to: tempFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tempFile) }

        let result = try HashCalculator.computeHashes(for: tempFile)
        XCTAssertEqual(result.sha256.count, 64)
        XCTAssertEqual(result.md5.count, 32)
        XCTAssertEqual(result.bytesProcessed, Int64(content.utf8.count))
    }
}
