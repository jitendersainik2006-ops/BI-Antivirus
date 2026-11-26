package com.biantivirus.security

import com.biantivirus.security.core.ScannerEngine
import com.biantivirus.security.core.SignatureDatabase
import com.biantivirus.security.model.ScanVerdict
import com.biantivirus.security.model.ThreatSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import java.io.ByteArrayInputStream

class ScannerEngineTest {

    private val signatureDb = SignatureDatabase()
    private val scanner = ScannerEngine(signatureDb = signatureDb)

    @Test
    fun testScanCleanFileReturnsClean() {
        val cleanContent = "Hello World! This is a completely harmless text document."
        val stream = ByteArrayInputStream(cleanContent.toByteArray())

        val result = scanner.scanStream(
            fileName = "welcome.txt",
            filePath = "/storage/emulated/0/Documents/welcome.txt",
            fileSize = cleanContent.length.toLong(),
            inputStream = stream
        )

        assertEquals(ScanVerdict.CLEAN, result.verdict)
        assertEquals(ThreatSeverity.NONE, result.severity)
        assertEquals("welcome.txt", result.fileName)
        assertNotNull(result.sha256)
    }

    @Test
    fun testScanEicarFileReturnsThreatDetected() {
        val eicarString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*"
        val stream = ByteArrayInputStream(eicarString.toByteArray(Charsets.US_ASCII))

        val result = scanner.scanStream(
            fileName = "eicar.com",
            filePath = "/storage/emulated/0/Download/eicar.com",
            fileSize = eicarString.length.toLong(),
            inputStream = stream
        )

        assertEquals(ScanVerdict.THREAT_DETECTED, result.verdict)
        assertEquals("EICAR-Standard-AV-Test-File", result.threatName)
        assertEquals(ThreatSeverity.CRITICAL, result.severity)
    }

    @Test
    fun testScanDoubleExtensionReturnsSuspicious() {
        val content = "Simulated application payload"
        val stream = ByteArrayInputStream(content.toByteArray())

        val result = scanner.scanStream(
            fileName = "bank_statement.pdf.apk",
            filePath = "/storage/emulated/0/Download/bank_statement.pdf.apk",
            fileSize = content.length.toLong(),
            inputStream = stream
        )

        assertEquals(ScanVerdict.SUSPICIOUS, result.verdict)
        assertEquals(ThreatSeverity.MEDIUM, result.severity)
        assertNotEquals(ScanVerdict.CLEAN, result.verdict)
    }

    @Test
    fun testCorruptedFileNeverReportsClean() {
        val corruptPayload = "Corrupted and truncated binary header test input without valid magic.\n[TRUNCATED_STREAM_AT_OFFSET_0x4F]"
        val stream = ByteArrayInputStream(corruptPayload.toByteArray())

        val result = scanner.scanStream(
            fileName = "corrupted_truncated_sample.bin",
            filePath = "/storage/emulated/0/Download/corrupted_truncated_sample.bin",
            fileSize = corruptPayload.length.toLong(),
            inputStream = stream
        )

        assertEquals(ScanVerdict.SCAN_ERROR, result.verdict)
        assertNotEquals(ScanVerdict.CLEAN, result.verdict)
        assertNotNull(result.errorMessage)
    }

    @Test
    fun testUnsupportedFormatNeverReportsClean() {
        val content = "Data in custom unparseable proprietary container format"
        val stream = ByteArrayInputStream(content.toByteArray())

        val result = scanner.scanStream(
            fileName = "archive.xyz",
            filePath = "/storage/emulated/0/Download/archive.xyz",
            fileSize = content.length.toLong(),
            inputStream = stream
        )

        assertEquals(ScanVerdict.UNSUPPORTED, result.verdict)
        assertNotEquals(ScanVerdict.CLEAN, result.verdict)
        assertNotNull(result.errorMessage)
    }
}
