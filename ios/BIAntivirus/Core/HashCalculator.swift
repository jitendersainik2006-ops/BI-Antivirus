import Foundation
import CryptoKit
import CommonCrypto

public struct HashOutput {
    public let sha256: String
    public let md5: String
    public let bytesProcessed: Int64
}

public enum HashCalculator {

    private static let bufferSize = 64 * 1024 // 64 KB memory-safe chunk

    public static func computeHashes(for url: URL) throws -> HashOutput {
        let fileHandle = try FileHandle(forReadingFrom: url)
        defer {
            try? fileHandle.close()
        }

        var sha256 = SHA256()
        var md5Context = CC_MD5_CTX()
        CC_MD5_Init(&md5Context)

        var totalBytes: Int64 = 0

        while autoreleasepool(invoking: {
            let data = fileHandle.readData(ofLength: bufferSize)
            if data.isEmpty {
                return false
            }

            sha256.update(data: data)
            data.withUnsafeBytes { buffer in
                if let baseAddress = buffer.baseAddress {
                    CC_MD5_Update(&md5Context, baseAddress, CC_LONG(buffer.count))
                }
            }
            totalBytes += Int64(data.count)
            return true
        }) {}

        let sha256Digest = sha256.finalize()
        let sha256Hex = sha256Digest.map { String(format: "%02x", $0) }.joined()

        var md5Digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        CC_MD5_Final(&md5Digest, &md5Context)
        let md5Hex = md5Digest.map { String(format: "%02x", $0) }.joined()

        return HashOutput(
            sha256: sha256Hex,
            md5: md5Hex,
            bytesProcessed: totalBytes
        )
    }

    public static func computeHashes(for data: Data) -> HashOutput {
        let sha256Digest = SHA256.hash(data: data)
        let sha256Hex = sha256Digest.map { String(format: "%02x", $0) }.joined()

        var md5Digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes { buffer in
            if let baseAddress = buffer.baseAddress {
                CC_MD5(baseAddress, CC_LONG(buffer.count), &md5Digest)
            }
        }
        let md5Hex = md5Digest.map { String(format: "%02x", $0) }.joined()

        return HashOutput(
            sha256: sha256Hex,
            md5: md5Hex,
            bytesProcessed: Int64(data.count)
        )
    }
}
