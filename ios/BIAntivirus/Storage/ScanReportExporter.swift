import Foundation

public enum ScanReportExporter {

    private static let isoFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withDashSeparatorInDate, .withColonSeparatorInTime]
        return formatter
    }()

    public static func exportToJSON(
        results: [FileInspectionResult],
        scanDurationMs: Int64,
        deviceModel: String = "Apple iOS Device"
    ) -> String {
        var items: [[String: Any]] = []

        for r in results {
            var dict: [String: Any] = [
                "fileName": r.fileName,
                "filePath": r.filePath,
                "fileSize": r.fileSize,
                "sha256": r.sha256,
                "md5": r.md5,
                "entropy": r.entropy,
                "verdict": r.verdict.rawValue,
                "severity": r.severity.rawValue,
                "matchedRules": r.matchedRules
            ]
            if let tn = r.threatName { dict["threatName"] = tn }
            if let tf = r.threatFamily { dict["threatFamily"] = tf }
            if let em = r.errorMessage { dict["errorMessage"] = em }
            items.append(dict)
        }

        let root: [String: Any] = [
            "reportVersion": "1.0.0",
            "generatedAt": isoFormatter.string(from: Date()),
            "deviceInfo": deviceModel,
            "scanDurationMs": scanDurationMs,
            "totalFilesScanned": results.count,
            "threatsDetectedCount": results.count { $0.verdict == .threatDetected },
            "suspiciousCount": results.count { $0.verdict == .suspicious },
            "cleanCount": results.count { $0.verdict == .clean },
            "unsupportedCount": results.count { $0.verdict == .unsupported },
            "scanErrorCount": results.count { $0.verdict == .scanError },
            "results": items
        ]

        guard let data = try? JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys]),
              let jsonString = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return jsonString
    }

    public static func exportToMarkdown(
        results: [FileInspectionResult],
        scanDurationMs: Int64,
        deviceModel: String = "Apple iOS Device"
    ) -> String {
        var md = "# BI Antivirus Enterprise — iOS Security Inspection Report\n\n"
        md += "**Generated At:** \(isoFormatter.string(from: Date()))\n"
        md += "**Device:** \(deviceModel)\n"
        md += "**Duration:** \(scanDurationMs) ms\n"
        md += "**Inspected Count:** \(results.count)\n\n"

        let threats = results.count { $0.verdict == .threatDetected }
        let suspicious = results.count { $0.verdict == .suspicious }
        let clean = results.count { $0.verdict == .clean }
        let unsupported = results.count { $0.verdict == .unsupported }
        let errors = results.count { $0.verdict == .scanError }

        md += "### Summary\n"
        md += "- **Threats Detected:** \(threats)\n"
        md += "- **Suspicious Items:** \(suspicious)\n"
        md += "- **Clean Items:** \(clean)\n"
        md += "- **Unsupported Formats:** \(unsupported)\n"
        md += "- **Scan / File Errors:** \(errors)\n\n"

        md += "### Findings\n\n"
        md += "| File Name | Verdict | Severity | Details | SHA-256 |\n"
        md += "| :--- | :---: | :---: | :--- | :--- |\n"

        for item in results {
            let detail = item.threatName ?? item.matchedRules.first ?? item.errorMessage ?? "None"
            let hashPrefix = item.sha256.count >= 12 ? String(item.sha256.prefix(12)) + "..." : item.sha256
            md += "| `\(item.fileName)` | \(item.verdict.rawValue) | \(item.severity.rawValue) | \(detail) | `\(hashPrefix)` |\n"
        }

        return md
    }
}
