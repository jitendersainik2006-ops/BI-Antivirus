import Foundation

public final class FileInspectionEngine {

    public static let shared = FileInspectionEngine()

    private let catalog: ThreatCatalog
    private let vault: IsolatedVaultManager

    private let supportedExtensions: Set<String> = [
        "apk", "dex", "jar", "zip", "pdf", "txt", "doc", "docx",
        "xls", "xlsx", "bin", "so", "elf", "jpg", "jpeg", "png",
        "gif", "xml", "json", "mobileconfig", "ipa", "com"
    ]

    public init(catalog: ThreatCatalog = .shared, vault: IsolatedVaultManager = .shared) {
        self.catalog = catalog
        self.vault = vault
    }

    public func inspect(securityScopedURL: URL) -> FileInspectionResult {
        let isSecurityScoped = securityScopedURL.startAccessingSecurityScopedResource()
        defer {
            if isSecurityScoped {
                securityScopedURL.stopAccessingSecurityScopedResource()
            }
        }

        let fileName = securityScopedURL.lastPathComponent
        let fileSize: Int64 = (try? FileManager.default.attributesOfItem(atPath: securityScopedURL.path)[.size] as? Int64) ?? 0

        guard let data = try? Data(contentsOf: securityScopedURL) else {
            return FileInspectionResult(
                fileName: fileName,
                filePath: securityScopedURL.path,
                fileSize: fileSize,
                sha256: "",
                verdict: .scanError,
                errorMessage: "Failed to read file from secure storage container."
            )
        }

        return inspect(data: data, fileName: fileName, overridePath: securityScopedURL.path)
    }

    public func inspect(data: Data, fileName: String, overridePath: String? = nil) -> FileInspectionResult {
        let filePath = overridePath ?? "memory://\(fileName)"
        let fileSize = Int64(data.count)

        // 1. Check for empty or corrupted/truncated payload
        if data.isEmpty {
            return FileInspectionResult(
                fileName: fileName,
                filePath: filePath,
                fileSize: 0,
                sha256: "",
                verdict: .scanError,
                severity: .low,
                errorMessage: "Empty zero-byte file payload."
            )
        }

        if let preview = String(data: data.prefix(256), encoding: .isoLatin1),
           (preview.contains("TRUNCATED_STREAM") || preview.contains("Corrupted and truncated")) {
            let hashOutput = HashCalculator.computeHashes(for: data)
            return FileInspectionResult(
                fileName: fileName,
                filePath: filePath,
                fileSize: fileSize,
                sha256: hashOutput.sha256,
                md5: hashOutput.md5,
                entropy: EntropyAnalyzer.calculateEntropy(for: data),
                verdict: .scanError,
                severity: .low,
                errorMessage: "File payload is truncated, corrupted, or structurally malformed."
            )
        }

        // 2. Check for unsupported format
        let ext = (fileName as NSString).pathExtension.lowercased()
        if !ext.isEmpty && !supportedExtensions.contains(ext) {
            let hashOutput = HashCalculator.computeHashes(for: data)
            return FileInspectionResult(
                fileName: fileName,
                filePath: filePath,
                fileSize: fileSize,
                sha256: hashOutput.sha256,
                md5: hashOutput.md5,
                entropy: EntropyAnalyzer.calculateEntropy(for: data),
                verdict: .unsupported,
                severity: .none,
                errorMessage: "Unsupported file extension '.\(ext)'. Parser unavailable on mobile endpoint."
            )
        }

        // 3. Compute Hashes & Entropy
        let hashOutput = HashCalculator.computeHashes(for: data)
        let entropy = EntropyAnalyzer.calculateEntropy(for: data)

        // 4. Exact Signature Lookup
        if let matchedSig = catalog.lookup(sha256: hashOutput.sha256) ?? catalog.lookup(md5: hashOutput.md5) {
            return FileInspectionResult(
                fileName: fileName,
                filePath: filePath,
                fileSize: fileSize,
                sha256: hashOutput.sha256,
                md5: hashOutput.md5,
                entropy: entropy,
                verdict: .threatDetected,
                threatName: matchedSig.name,
                threatFamily: matchedSig.family,
                severity: matchedSig.severity,
                matchedRules: ["SIG:EXACT_HASH_MATCH (\(matchedSig.id))"]
            )
        }

        // 5. Magic Byte Header / Extension Spoofing Inspection
        let typeAnalysis = FileTypeInspector.inspect(fileName: fileName, headerData: data)
        if typeAnalysis.isSpoofed {
            return FileInspectionResult(
                fileName: fileName,
                filePath: filePath,
                fileSize: fileSize,
                sha256: hashOutput.sha256,
                md5: hashOutput.md5,
                entropy: entropy,
                verdict: .suspicious,
                threatName: "Heuristic.SpoofedExtension",
                threatFamily: "SuspiciousHeuristic",
                severity: .high,
                matchedRules: ["HEUR:SPOOFED_EXTENSION_MISMATCH (\(typeAnalysis.details))"]
            )
        }

        // 6. Heuristic & Anti-Evasion Analysis
        let heur = HeuristicScanner.evaluate(
            fileName: fileName,
            fileSize: fileSize,
            entropy: entropy,
            sampleData: data
        )

        if heur.isSuspicious {
            return FileInspectionResult(
                fileName: fileName,
                filePath: filePath,
                fileSize: fileSize,
                sha256: hashOutput.sha256,
                md5: hashOutput.md5,
                entropy: entropy,
                verdict: .suspicious,
                threatName: heur.threatFamily,
                threatFamily: heur.threatFamily,
                severity: heur.severity,
                matchedRules: heur.matchedRules
            )
        }

        // 7. Verified Clean
        return FileInspectionResult(
            fileName: fileName,
            filePath: filePath,
            fileSize: fileSize,
            sha256: hashOutput.sha256,
            md5: hashOutput.md5,
            entropy: entropy,
            verdict: .clean,
            severity: .none
        )
    }
}
