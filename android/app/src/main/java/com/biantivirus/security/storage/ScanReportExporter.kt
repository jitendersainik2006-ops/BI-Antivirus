package com.biantivirus.security.storage

import android.content.Context
import com.biantivirus.security.model.ScanResult
import com.biantivirus.security.model.ScanVerdict
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object ScanReportExporter {

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)

    fun exportToJson(
        scanResults: List<ScanResult>,
        scanDurationMs: Long,
        deviceInfo: String = "Android Endpoint"
    ): String {
        val root = JSONObject()
        root.put("reportVersion", "1.0.0")
        root.put("generatedAt", dateFormat.format(Date()))
        root.put("deviceInfo", deviceInfo)
        root.put("scanDurationMs", scanDurationMs)
        root.put("totalFilesScanned", scanResults.size)
        root.put("threatsDetectedCount", scanResults.count { it.verdict == ScanVerdict.THREAT_DETECTED })
        root.put("suspiciousCount", scanResults.count { it.verdict == ScanVerdict.SUSPICIOUS })
        root.put("cleanCount", scanResults.count { it.verdict == ScanVerdict.CLEAN })
        root.put("unsupportedCount", scanResults.count { it.verdict == ScanVerdict.UNSUPPORTED })
        root.put("scanErrorCount", scanResults.count { it.verdict == ScanVerdict.SCAN_ERROR })

        val items = JSONArray()
        for (res in scanResults) {
            val item = JSONObject()
            item.put("fileName", res.fileName)
            item.put("filePath", res.filePath)
            item.put("fileSize", res.fileSize)
            item.put("sha256", res.sha256)
            item.put("md5", res.md5)
            item.put("entropy", res.entropy)
            item.put("verdict", res.verdict.name)
            item.put("threatName", res.threatName ?: JSONObject.NULL)
            item.put("threatFamily", res.threatFamily ?: JSONObject.NULL)
            item.put("severity", res.severity.name)
            item.put("matchedRules", JSONArray(res.matchedRules))
            item.put("errorMessage", res.errorMessage ?: JSONObject.NULL)
            items.put(item)
        }
        root.put("results", items)
        return root.toString(2)
    }

    fun exportToMarkdown(
        scanResults: List<ScanResult>,
        scanDurationMs: Long,
        deviceInfo: String = "Android Endpoint"
    ): String {
        val sb = StringBuilder()
        sb.append("# BI Antivirus Enterprise — Mobile Security Audit Report\n\n")
        sb.append("**Generated At:** ").append(dateFormat.format(Date())).append("\n")
        sb.append("**Device Info:** ").append(deviceInfo).append("\n")
        sb.append("**Scan Duration:** ").append(scanDurationMs).append(" ms\n")
        sb.append("**Total Items Evaluated:** ").append(scanResults.size).append("\n\n")

        val threats = scanResults.count { it.verdict == ScanVerdict.THREAT_DETECTED }
        val suspicious = scanResults.count { it.verdict == ScanVerdict.SUSPICIOUS }
        val clean = scanResults.count { it.verdict == ScanVerdict.CLEAN }
        val unsupported = scanResults.count { it.verdict == ScanVerdict.UNSUPPORTED }
        val errors = scanResults.count { it.verdict == ScanVerdict.SCAN_ERROR }

        sb.append("### Summary\n")
        sb.append("- **Threats Detected:** ").append(threats).append("\n")
        sb.append("- **Suspicious Items:** ").append(suspicious).append("\n")
        sb.append("- **Clean Items:** ").append(clean).append("\n")
        sb.append("- **Unsupported Formats:** ").append(unsupported).append("\n")
        sb.append("- **Scan / File Errors:** ").append(errors).append("\n\n")

        sb.append("### Detailed Findings\n\n")
        sb.append("| File Name | Verdict | Severity | Threat / Rule | SHA-256 |\n")
        sb.append("| :--- | :---: | :---: | :--- | :--- |\n")

        for (item in scanResults) {
            val rule = item.threatName ?: item.matchedRules.firstOrNull() ?: item.errorMessage ?: "None"
            val hashPrefix = if (item.sha256.length >= 12) item.sha256.take(12) + "..." else item.sha256
            sb.append("| `").append(item.fileName).append("` | ")
                .append(item.verdict.name).append(" | ")
                .append(item.severity.name).append(" | ")
                .append(rule).append(" | `")
                .append(hashPrefix).append("` |\n")
        }

        return sb.toString()
    }

    fun saveReportToStorage(context: Context, content: String, isJson: Boolean = true): File {
        val reportsDir = File(context.filesDir, "reports")
        if (!reportsDir.exists()) {
            reportsDir.mkdirs()
        }
        val ext = if (isJson) "json" else "md"
        val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val file = File(reportsDir, "scan_report_$timestamp.$ext")
        file.writeText(content, Charsets.UTF_8)
        return file
    }
}
