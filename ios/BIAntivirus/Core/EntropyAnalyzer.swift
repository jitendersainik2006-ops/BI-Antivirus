import Foundation

public enum EntropyAnalyzer {

    private static let log2Const = log(2.0)

    public static func calculateEntropy(for data: Data) -> Double {
        guard !data.isEmpty else { return 0.0 }

        var frequencies = [Int](repeating: 0, count: 256)
        data.forEach { byte in
            frequencies[Int(byte)] += 1
        }

        let total = Double(data.count)
        var entropy: Double = 0.0

        for count in frequencies where count > 0 {
            let p = Double(count) / total
            entropy -= p * (log(p) / log2Const)
        }

        return Double(round(1000 * entropy) / 1000)
    }

    public static func calculateEntropy(for url: URL, maxBytes: Int = 1024 * 1024) -> Double {
        guard let fileHandle = try? FileHandle(forReadingFrom: url) else { return 0.0 }
        defer { try? fileHandle.close() }

        let data = fileHandle.readData(ofLength: maxBytes)
        return calculateEntropy(for: data)
    }
}
