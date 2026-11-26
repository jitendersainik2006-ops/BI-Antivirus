package com.biantivirus.security

import com.biantivirus.security.model.ScanResult
import com.biantivirus.security.model.ScanVerdict
import com.biantivirus.security.model.ThreatSeverity
import com.biantivirus.security.storage.ScanReportExporter
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanReportExporterTest {

    @Test
    fun testJsonReportExportStructure() {
        val results = listOf(
            ScanResult(
                fileName = "clean.pdf",
                filePath = "/sdcard/Documents/clean.pdf",
                fileSize = 1024,
                sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                md5 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                entropy = 4.2,
                verdict = ScanVerdict.CLEAN,
                severity = ThreatSeverity.NONE
            ),
            ScanResult(
                fileName = "trojan.apk",
                filePath = "/sdcard/Downloads/trojan.apk",
                fileSize = 2048,
                sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                md5 = "dddddddddddddddddddddddddddddddd",
                entropy = 7.8,
                verdict = ScanVerdict.THREAT_DETECTED,
                threatName = "Android.Trojan.Banker",
                threatFamily = "Trojan",
                severity = ThreatSeverity.CRITICAL,
                matchedRules = listOf("SIG:EXACT_HASH_MATCH")
            ),
            ScanResult(
                fileName = "unknown.xyz",
                filePath = "/sdcard/Downloads/unknown.xyz",
                fileSize = 512,
                sha256 = "1111111111111111111111111111111111111111111111111111111111111111",
                md5 = "22222222222222222222222222222222",
                entropy = 4.1,
                verdict = ScanVerdict.UNSUPPORTED,
                severity = ThreatSeverity.NONE,
                errorMessage = "Unsupported format"
            ),
            ScanResult(
                fileName = "corrupt.bin",
                filePath = "/sdcard/Downloads/corrupt.bin",
                fileSize = 100,
                sha256 = "3333333333333333333333333333333333333333333333333333333333333333",
                md5 = "44444444444444444444444444444444",
                entropy = 3.9,
                verdict = ScanVerdict.SCAN_ERROR,
                severity = ThreatSeverity.LOW,
                errorMessage = "Truncated file stream"
            )
        )

        val jsonStr = ScanReportExporter.exportToJson(results, 350L, "Pixel 7 Pro")
        val json = JSONObject(jsonStr)

        assertEquals("1.0.0", json.getString("reportVersion"))
        assertEquals("Pixel 7 Pro", json.getString("deviceInfo"))
        assertEquals(350L, json.getLong("scanDurationMs"))
        assertEquals(4, json.getInt("totalFilesScanned"))
        assertEquals(1, json.getInt("threatsDetectedCount"))
        assertEquals(1, json.getInt("cleanCount"))
        assertEquals(1, json.getInt("unsupportedCount"))
        assertEquals(1, json.getInt("scanErrorCount"))
        assertEquals(4, json.getJSONArray("results").length())
    }

    @Test
    fun testMarkdownReportExportStructure() {
        val results = listOf(
            ScanResult(
                fileName = "sample.pdf.apk",
                filePath = "/sdcard/Download/sample.pdf.apk",
                fileSize = 5000,
                sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                md5 = "ffffffffffffffffffffffffffffffff",
                entropy = 6.8,
                verdict = ScanVerdict.SUSPICIOUS,
                severity = ThreatSeverity.MEDIUM,
                matchedRules = listOf("HEUR:SUSPICIOUS_DOUBLE_EXTENSION")
            )
        )

        val markdown = ScanReportExporter.exportToMarkdown(results, 120L)
        assertTrue(markdown.contains("# BI Antivirus Enterprise — Mobile Security Audit Report"))
        assertTrue(markdown.contains("Suspicious Items:** 1"))
        assertTrue(markdown.contains("`sample.pdf.apk`"))
        assertTrue(markdown.contains("SUSPICIOUS"))
    }
}
