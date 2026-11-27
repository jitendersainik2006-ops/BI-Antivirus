package com.biantivirus.security

import com.biantivirus.security.core.ArchiveInspector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ArchiveInspectorTest {

    private val inspector = ArchiveInspector()

    private fun createZipStream(entries: Map<String, ByteArray>): ByteArrayInputStream {
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            for ((name, data) in entries) {
                val entry = ZipEntry(name)
                zos.putNextEntry(entry)
                zos.write(data)
                zos.closeEntry()
            }
        }
        return ByteArrayInputStream(baos.toByteArray())
    }

    @Test
    fun testCleanArchiveInspection() {
        val files = mapOf(
            "documents/readme.txt" to "Welcome to BI Antivirus".toByteArray(),
            "data/config.json" to "{\"secure\": true}".toByteArray()
        )
        val stream = createZipStream(files)

        val result = inspector.inspectZipStream("clean_backup.zip", stream)
        assertTrue(result.isSafe)
        assertFalse(result.isZipSlipAttempt)
        assertFalse(result.isZipBombAttempt)
        assertFalse(result.containsExecutables)
        assertEquals(2, result.totalEntries)
    }

    @Test
    fun testZipSlipDirectoryTraversalBlocked() {
        val files = mapOf(
            "../../etc/passwd" to "root:x:0:0:root:/root:/bin/bash".toByteArray()
        )
        val stream = createZipStream(files)

        val result = inspector.inspectZipStream("exploit_payload.zip", stream)
        assertFalse(result.isSafe)
        assertTrue(result.isZipSlipAttempt)
        assertTrue(result.suspiciousEntries.any { it.contains("PATH_TRAVERSAL") })
        assertTrue(result.details.contains("Zip Slip", ignoreCase = true))
    }

    @Test
    fun testZipSlipCanonicalPathEscapingBlocked() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "bi_test_zip_slip_" + System.currentTimeMillis())
        tempDir.mkdirs()

        try {
            val files = mapOf(
                "../escaping_file.dex" to "dex_bytes".toByteArray()
            )
            val stream = createZipStream(files)

            val result = inspector.inspectZipStream("escape.zip", stream, targetDir = tempDir)
            assertFalse(result.isSafe)
            assertTrue(result.isZipSlipAttempt)
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun testExecutablePayloadDetectionInsideZip() {
        val files = mapOf(
            "classes.dex" to "dex035_mock_bytecode".toByteArray(),
            "payload.sh" to "#!/bin/sh\nrm -rf /".toByteArray()
        )
        val stream = createZipStream(files)

        val result = inspector.inspectZipStream("script_container.zip", stream)
        assertFalse(result.isSafe)
        assertTrue(result.containsExecutables)
        assertTrue(result.suspiciousEntries.any { it.contains("classes.dex") })
        assertTrue(result.suspiciousEntries.any { it.contains("payload.sh") })
    }
}
