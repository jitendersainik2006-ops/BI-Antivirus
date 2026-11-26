package com.biantivirus.security

import com.biantivirus.security.core.QuarantineManager
import com.biantivirus.security.core.QuarantineStatus
import com.biantivirus.security.core.RestoreResult
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files

class QuarantineManagerTest {

    private lateinit var tempVaultDir: File
    private lateinit var tempRestoreDir: File
    private lateinit var manager: QuarantineManager

    @Before
    fun setUp() {
        tempVaultDir = Files.createTempDirectory("bi_test_vault").toFile()
        tempRestoreDir = Files.createTempDirectory("bi_test_restore").toFile()
        manager = QuarantineManager(tempVaultDir)
    }

    @After
    fun tearDown() {
        tempVaultDir.deleteRecursively()
        tempRestoreDir.deleteRecursively()
    }

    @Test
    fun testQuarantineCreationAndLedgerPersistence() {
        val payload = "Malware payload sample byte array".toByteArray(Charsets.UTF_8)
        val sha256 = "d2a02e64627d3eb6ff82cf51b0337f90c427091fe7c7cfddaeef3ef3393952ba"

        val record = manager.quarantineBytes(
            fileName = "trojan.apk",
            originalPath = "/sdcard/Download/trojan.apk",
            bytes = payload,
            threatName = "Android.Trojan.Test",
            sha256 = sha256
        )

        assertEquals("trojan.apk", record.originalFileName)
        assertEquals(QuarantineStatus.QUARANTINED, record.status)
        assertTrue(File(record.vaultFilePath).exists())

        // Recreate manager to verify ledger persistence
        val reloadedManager = QuarantineManager(tempVaultDir)
        val history = reloadedManager.getQuarantineHistory()
        assertEquals(1, history.size)
        assertEquals(record.id, history[0].id)
    }

    @Test
    fun testUniqueNonceProducesDifferentCiphertextForIdenticalPayload() {
        val payload = "Identical payload bytes for encryption randomization testing".toByteArray(Charsets.UTF_8)
        val sha256 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

        val rec1 = manager.quarantineBytes("file1.bin", "/path/file1.bin", payload, "Threat1", sha256)
        val rec2 = manager.quarantineBytes("file2.bin", "/path/file2.bin", payload, "Threat1", sha256)

        val bytes1 = File(rec1.vaultFilePath).readBytes()
        val bytes2 = File(rec2.vaultFilePath).readBytes()

        // With AES-GCM and unique 12-byte random nonces, ciphertexts must be distinct
        assertNotEquals(bytes1, bytes2)
    }

    @Test
    fun testSuccessfulRestoreWithIntegrityVerification() {
        val payload = "Important business file quarantined accidentally".toByteArray(Charsets.UTF_8)
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(payload)
        val sha256 = digest.joinToString("") { "%02x".format(it) }

        val record = manager.quarantineBytes(
            fileName = "quarterly_budget.xlsx",
            originalPath = "/sdcard/Documents/quarterly_budget.xlsx",
            bytes = payload,
            threatName = "Heuristic.Anomaly",
            sha256 = sha256
        )

        val result = manager.restoreQuarantinedFile(record.id, tempRestoreDir, allowOverwrite = false)
        assertTrue(result is RestoreResult.Success)
        val success = result as RestoreResult.Success
        assertEquals("quarterly_budget.xlsx", success.restoredFile.name)
        assertEquals(String(payload), success.restoredFile.readText(Charsets.UTF_8))
        assertEquals(QuarantineStatus.RESTORED, manager.getQuarantineHistory().find { it.id == record.id }?.status)
    }

    @Test
    fun testRestoreRefusesToOverwriteExistingFile() {
        val payload = "Sample data".toByteArray(Charsets.UTF_8)
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(payload)
        val sha256 = digest.joinToString("") { "%02x".format(it) }

        val record = manager.quarantineBytes("existing.txt", "/path/existing.txt", payload, "Test", sha256)

        // Pre-create the destination file
        val existingFile = File(tempRestoreDir, "existing.txt")
        existingFile.writeText("Pre-existing content")

        val result = manager.restoreQuarantinedFile(record.id, tempRestoreDir, allowOverwrite = false)
        assertTrue(result is RestoreResult.DestinationExists)

        // Now test with allowOverwrite = true
        val overwriteResult = manager.restoreQuarantinedFile(record.id, tempRestoreDir, allowOverwrite = true)
        assertTrue(overwriteResult is RestoreResult.Success)
    }

    @Test
    fun testTamperDetectionRejectsCorruptedVaultFile() {
        val payload = "Confidential data payload".toByteArray(Charsets.UTF_8)
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(payload)
        val sha256 = digest.joinToString("") { "%02x".format(it) }

        val record = manager.quarantineBytes("data.bin", "/path/data.bin", payload, "Test", sha256)

        // Deliberately tamper with ciphertext/tag in the vault file
        val vaultFile = File(record.vaultFilePath)
        val tamperedBytes = vaultFile.readBytes()
        tamperedBytes[tamperedBytes.size - 1] = (tamperedBytes[tamperedBytes.size - 1] + 1).toByte()
        FileOutputStream(vaultFile).use { it.write(tamperedBytes) }

        val result = manager.restoreQuarantinedFile(record.id, tempRestoreDir, allowOverwrite = false)
        assertTrue(result is RestoreResult.TamperDetected)
    }

    @Test
    fun testMissingLedgerRecordReturnsNotFound() {
        val result = manager.restoreQuarantinedFile("Q-NONEXIST", tempRestoreDir)
        assertTrue(result is RestoreResult.RecordNotFound)
    }
}
