import XCTest
@testable import BIAntivirus

final class WebReputationAuditorTests: XCTestCase {

    var auditor: WebReputationAuditor!

    override func setUp() {
        super.setUp()
        auditor = WebReputationAuditor.shared
    }

    func testCleanLegitimateDomain() {
        let result = auditor.auditUrl("https://www.apple.com")
        XCTAssertEqual(result.verdict, .safe)
        XCTAssertEqual(result.riskScore, 0)
        XCTAssertTrue(result.reasons.isEmpty)
    }

    func testIpAddressUrl() {
        let result = auditor.auditUrl("http://192.168.1.100/download.exe")
        XCTAssertEqual(result.verdict, .suspicious)
        XCTAssertGreaterThanOrEqual(result.riskScore, 35)
        XCTAssertTrue(result.reasons.contains { $0.contains("Raw IP address") })
    }

    func testPhishingKeywordDomain() {
        let result = auditor.auditUrl("https://login-verify-service.top/auth")
        XCTAssertEqual(result.verdict, .phishing)
        XCTAssertGreaterThanOrEqual(result.riskScore, 60)
        XCTAssertTrue(result.reasons.contains { $0.contains("phishing") })
        XCTAssertTrue(result.reasons.contains { $0.contains("top-level domain") })
    }

    func testPunycodeHomoglyph() {
        let result = auditor.auditUrl("https://xn--pple-43d.com")
        XCTAssertEqual(result.verdict, .suspicious)
        XCTAssertTrue(result.reasons.contains { $0.contains("Punycode") })
    }
}
