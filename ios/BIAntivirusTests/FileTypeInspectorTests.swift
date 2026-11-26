import XCTest
@testable import BIAntivirus

final class FileTypeInspectorTests: XCTestCase {

    func testValidPdfInspection() {
        let pdfMagic = Data([0x25, 0x50, 0x44, 0x46, 0x2D])
        let result = FileTypeInspector.inspect(fileName: "contract.pdf", headerData: pdfMagic)

        XCTAssertEqual(result.detectedMimeType, "application/pdf")
        XCTAssertEqual(result.declaredExtension, "pdf")
        XCTAssertTrue(result.isConsistent)
        XCTAssertFalse(result.isSpoofed)
    }

    func testSpoofedMachOBinaryDisguisedAsJpeg() {
        // Mach-O 64-bit binary disguised as .jpg image
        let machOMagic = Data([0xCF, 0xFA, 0xED, 0xFE])
        let result = FileTypeInspector.inspect(fileName: "vacation.jpg", headerData: machOMagic)

        XCTAssertEqual(result.detectedMimeType, "application/x-mach-binary")
        XCTAssertEqual(result.declaredExtension, "jpg")
        XCTAssertFalse(result.isConsistent)
        XCTAssertTrue(result.isSpoofed)
        XCTAssertTrue(result.details.contains("Spoofed Extension Attack"))
    }

    func testSpoofedIpaDisguisedAsPng() {
        // ZIP/IPA header disguised as .png
        let zipMagic = Data([0x50, 0x4B, 0x03, 0x04])
        let result = FileTypeInspector.inspect(fileName: "logo.png", headerData: zipMagic)

        XCTAssertEqual(result.detectedMimeType, "application/zip")
        XCTAssertEqual(result.declaredExtension, "png")
        XCTAssertFalse(result.isConsistent)
        XCTAssertTrue(result.isSpoofed)
    }
}
