import Foundation

public struct HeuristicInspectionResult {
    public let isSuspicious: BooleanLiteralType
    public let matchedRules: [String]
    public let threatFamily: String?
    public let severity: ThreatSeverity
}

public enum HeuristicScanner {

    public static let entropyThreshold = 7.2

    private static let suspiciousDoubleExtensions = [
        ".pdf.apk", ".jpg.apk", ".doc.apk", ".pdf.ipa",
        ".png.ipa", ".doc.mobileconfig", ".pdf.mobileconfig"
    ]

    private static let eicarPattern = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    public static func evaluate(
        fileName: String,
        fileSize: Int64,
        entropy: Double,
        sampleData: Data? = nil
    ) -> HeuristicInspectionResult {
        var rules: [String] = []
        let lowerName = fileName.lowercased()

        // 1. Double extension check
        for doubleExt in suspiciousDoubleExtensions {
            if lowerName.hasSuffix(doubleExt) {
                rules.append("HEUR:SUSPICIOUS_DOUBLE_EXTENSION (\(doubleExt))")
                break
            }
        }

        // 2. High Shannon entropy check
        if entropy >= entropyThreshold && fileSize > 1024 {
            rules.append("HEUR:HIGH_SHANNON_ENTROPY (\(entropy) >= \(entropyThreshold))")
        }

        // 3. EICAR or suspicious mobile string pattern
        if let sample = sampleData, let text = String(data: sample, encoding: .isoLatin1) {
            if text.contains(eicarPattern) {
                rules.append("HEUR:EICAR_PATTERN_DETECTED")
            }
            if text.contains("PayloadType") && text.contains("Configuration") && lowerName.hasSuffix(".mobileconfig") {
                rules.append("HEUR:UNTYPED_MOBILE_CONFIG_PROFILE")
            }
        }

        if rules.isEmpty {
            return HeuristicInspectionResult(
                isSuspicious: false,
                matchedRules: [],
                threatFamily: nil,
                severity: .none
            )
        }

        let isEicar = rules.contains { $0.contains("EICAR") }
        let sev: ThreatSeverity = isEicar ? .critical : (rules.count >= 2 ? .high : .medium)
        let family = isEicar ? "TestVirus" : "iOS.Heuristic.Dropper"

        return HeuristicInspectionResult(
            isSuspicious: true,
            matchedRules: rules,
            threatFamily: family,
            severity: sev
        )
    }
}
