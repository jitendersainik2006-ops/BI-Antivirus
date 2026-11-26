package com.biantivirus.security

import com.biantivirus.security.core.FileTypeChecker
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FileTypeCheckerTest {

    @Test
    fun testValidPdfDocument() {
        val pdfHeader = byteArrayOf(0x25.toByte(), 0x50.toByte(), 0x44.toByte(), 0x46.toByte(), 0x2D.toByte())
        val analysis = FileTypeChecker.analyze("financial_report.pdf", pdfHeader)

        assertEquals("application/pdf", analysis.detectedMimeType)
        assertEquals("pdf", analysis.declaredExtension)
        assertTrue(analysis.isConsistent)
        assertFalse(analysis.isSpoofed)
    }

    @Test
    fun testValidApkZipPackage() {
        val zipHeader = byteArrayOf(0x50.toByte(), 0x4B.toByte(), 0x03.toByte(), 0x04.toByte(), 0x14.toByte())
        val analysis = FileTypeChecker.analyze("update.apk", zipHeader)

        assertEquals("application/zip", analysis.detectedMimeType)
        assertEquals("apk", analysis.declaredExtension)
        assertTrue(analysis.isConsistent)
        assertFalse(analysis.isSpoofed)
    }

    @Test
    fun testSpoofedApkDisguisedAsJpeg() {
        // ZIP/APK header disguised with .jpg extension
        val apkHeader = byteArrayOf(0x50.toByte(), 0x4B.toByte(), 0x03.toByte(), 0x04.toByte(), 0x14.toByte())
        val analysis = FileTypeChecker.analyze("profile_photo.jpg", apkHeader)

        assertEquals("application/zip", analysis.detectedMimeType)
        assertEquals("jpg", analysis.declaredExtension)
        assertFalse(analysis.isConsistent)
        assertTrue(analysis.isSpoofed)
        assertTrue(analysis.details.contains("Spoofed Extension Attack"))
    }

    @Test
    fun testSpoofedElfDisguisedAsPdf() {
        val elfHeader = byteArrayOf(0x7F.toByte(), 0x45.toByte(), 0x4C.toByte(), 0x46.toByte(), 0x02.toByte())
        val analysis = FileTypeChecker.analyze("invoice.pdf", elfHeader)

        assertEquals("application/x-elf", analysis.detectedMimeType)
        assertEquals("pdf", analysis.declaredExtension)
        assertFalse(analysis.isConsistent)
        assertTrue(analysis.isSpoofed)
    }

    @Test
    fun testDexByteHeaderDetection() {
        val dexHeader = byteArrayOf(0x64.toByte(), 0x65.toByte(), 0x78.toByte(), 0x0A.toByte(), 0x30.toByte())
        val analysis = FileTypeChecker.analyze("classes.dex", dexHeader)

        assertEquals("application/vnd.android.dex", analysis.detectedMimeType)
        assertTrue(analysis.isConsistent)
        assertFalse(analysis.isSpoofed)
    }
}
