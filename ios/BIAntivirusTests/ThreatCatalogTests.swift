//
//  ThreatCatalogTests.swift
//  BIAntivirusTests
//
//  Unit tests for ThreatCatalog signature registration, lookup, and bundle loading.
//

import XCTest
@testable import BIAntivirus

final class ThreatCatalogTests: XCTestCase {

    func testBaselineSignaturesLoaded() {
        let catalog = ThreatCatalog()
        XCTAssertGreaterThan(catalog.signatureCount, 0)
        
        // EICAR standard test signature check
        let eicar = catalog.lookup(sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        XCTAssertNotNil(eicar)
        XCTAssertEqual(eicar?.family, "TestVirus")
        XCTAssertEqual(eicar?.severity, .critical)
    }

    func testDynamicRegistrationAndLookup() {
        let catalog = ThreatCatalog()
        let customRecord = ThreatRecord(
            id: "SIG-TEST-CUSTOM-99",
            name: "iOS.Test.Dropper",
            family: "TestFamily",
            severity: .high,
            sha256: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            md5: "00112233445566778899aabbccddeeff",
            description: "Custom test threat registration."
        )

        catalog.register(record: customRecord)

        let lookupUpper = catalog.lookup(sha256: "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899")
        XCTAssertNotNil(lookupUpper)
        XCTAssertEqual(lookupUpper?.id, "SIG-TEST-CUSTOM-99")

        let lookupMd5 = catalog.lookup(md5: "00112233445566778899AABBCCDDEEFF")
        XCTAssertNotNil(lookupMd5)
        XCTAssertEqual(lookupMd5?.name, "iOS.Test.Dropper")
    }

    func testLookupNonExistentReturnsNil() {
        let catalog = ThreatCatalog()
        let result = catalog.lookup(sha256: "0000000000000000000000000000000000000000000000000000000000000000")
        XCTAssertNil(result)
    }
}
