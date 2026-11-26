//
//  EntropyAnalyzerTests.swift
//  BIAntivirusTests
//
//  Unit tests for Shannon Entropy calculation.
//

import XCTest
@testable import BIAntivirus

final class EntropyAnalyzerTests: XCTestCase {

    func testEmptyDataEntropyIsZero() {
        let empty = Data()
        let entropy = EntropyAnalyzer.calculateEntropy(for: empty)
        XCTAssertEqual(entropy, 0.0)
    }

    func testUniformZeroByteStreamEntropyIsZero() {
        let zeros = Data(repeating: 0x00, count: 1024)
        let entropy = EntropyAnalyzer.calculateEntropy(for: zeros)
        XCTAssertEqual(entropy, 0.0)
    }

    func testHighEntropyRandomData() {
        var randomBytes = [UInt8](repeating: 0, count: 2048)
        let status = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
        XCTAssertEqual(status, errSecSuccess)

        let data = Data(randomBytes)
        let entropy = EntropyAnalyzer.calculateEntropy(for: data)
        // High entropy random buffer should be close to 8.0 (typically >= 7.5)
        XCTAssertGreaterThan(entropy, 7.2)
    }

    func testPlainTextLowEntropy() {
        let plainText = "The quick brown fox jumps over the lazy dog. Normal ASCII prose has lower entropy."
        guard let data = plainText.data(using: .utf8) else {
            XCTFail("Failed to encode test string")
            return
        }

        let entropy = EntropyAnalyzer.calculateEntropy(for: data)
        // Normal English text entropy is usually between 3.5 and 5.0
        XCTAssertLessThan(entropy, 6.0)
        XCTAssertGreaterThan(entropy, 2.0)
    }
}
