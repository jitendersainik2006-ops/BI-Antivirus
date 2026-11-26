import Foundation

public struct FileTypeInspection {
    public let detectedMimeType: String
    public let declaredExtension: String
    public let isConsistent: Bool
    public let isSpoofed: Bool
    public let details: String
}

public enum FileTypeInspector {

    private static let magicZip: [UInt8] = [0x50, 0x4B, 0x03, 0x04] // IPA, ZIP, APK
    private static let magicMachO64: [UInt8] = [0xCF, 0xFA, 0xED, 0xFE] // Mach-O 64-bit binary
    private static let magicMachO32: [UInt8] = [0xCE, 0xFA, 0xED, 0xFE] // Mach-O 32-bit binary
    private static let magicPdf: [UInt8] = [0x25, 0x50, 0x44, 0x46] // %PDF
    private static let magicPng: [UInt8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
    private static let magicJpeg: [UInt8] = [0xFF, 0xD8, 0xFF]

    private static func match(data: Data, magic: [UInt8]) -> Bool {
        guard data.count >= magic.count else { return false }
        for (i, byte) in magic.enumerated() {
            if data[i] != byte { return false }
        }
        return true
    }

    public static func inspect(fileName: String, headerData: Data) -> FileTypeInspection {
        let ext = (fileName as NSString).pathExtension.lowercased()

        let detected: String
        if match(data: headerData, magic: magicMachO64) || match(data: headerData, magic: magicMachO32) {
            detected = "application/x-mach-binary"
        } else if match(data: headerData, magic: magicZip) {
            detected = "application/zip" // Includes .ipa, .zip, .jar
        } else if match(data: headerData, magic: magicPdf) {
            detected = "application/pdf"
        } else if match(data: headerData, magic: magicPng) {
            detected = "image/png"
        } else if match(data: headerData, magic: magicJpeg) {
            detected = "image/jpeg"
        } else {
            detected = "application/octet-stream"
        }

        // Detect spoofed extensions
        let isSpoofed: Bool
        if (detected == "application/zip" || detected == "application/x-mach-binary") &&
            ["jpg", "jpeg", "png", "pdf", "txt", "doc", "docx"].contains(ext) {
            isSpoofed = true
        } else if (detected == "image/png" || detected == "image/jpeg") &&
            ["ipa", "mobileconfig", "dylib"].contains(ext) {
            isSpoofed = true
        } else {
            isSpoofed = false
        }

        let isConsistent = !isSpoofed
        let details: String
        if isSpoofed {
            details = "CRITICAL: Header indicates \(detected) but file extension declares .\(ext) (Spoofed Extension Attack)."
        } else if detected == "application/octet-stream" {
            details = "Generic binary or plaintext data stream."
        } else {
            details = "File header signature correctly corresponds to declared extension .\(ext)."
        }

        return FileTypeInspection(
            detectedMimeType: detected,
            declaredExtension: ext,
            isConsistent: isConsistent,
            isSpoofed: isSpoofed,
            details = details
        )
    }
}
