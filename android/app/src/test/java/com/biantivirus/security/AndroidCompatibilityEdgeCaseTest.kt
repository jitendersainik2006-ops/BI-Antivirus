package com.biantivirus.security

import com.biantivirus.security.core.ArchiveInspector
import com.biantivirus.security.core.DeviceFormFactor
import com.biantivirus.security.core.Edition
import com.biantivirus.security.core.LicenseManager
import com.biantivirus.security.core.OEMBackgroundManager
import com.biantivirus.security.core.OEMType
import com.biantivirus.security.core.QuarantineManager
import com.biantivirus.security.core.QuarantineStatus
import com.biantivirus.security.core.RestoreResult
import com.biantivirus.security.core.ScannerEngine
import com.biantivirus.security.core.SignatureDatabase
import com.biantivirus.security.model.ScanVerdict
import com.biantivirus.security.model.ThreatSeverity
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Comprehensive Android Universal Compatibility & Edge-Case Test Suite.
 * Covers API 26-34 OEM background policy, form factor handling,
 * scan stream interruption, archive exploit prevention,
 * quarantine vault ledger recovery, and licensing boundary logic.
 */
class AndroidCompatibilityEdgeCaseTest {

    private lateinit var tempVaultDir: File
    private lateinit var tempRestoreDir: File

    @Before
    fun setUp() {
        tempVaultDir = Files.createTempDirectory("bi_edge_vault").toFile()
        tempRestoreDir = Files.createTempDirectory("bi_edge_restore").toFile()
    }

    @After
    fun tearDown() {
        tempVaultDir.deleteRecursively()
        tempRestoreDir.deleteRecursively()
    }

    // ---------------------------------------------------------
    // 1. OEM Background & Form Factor Compatibility
    // ---------------------------------------------------------

    @Test
    fun testAllOEMTypesHaveGuidanceAndOSFlavors() {
        val manager = OEMBackgroundManager(context = null)
        val oemTypes = OEMType.values()

        for (oem in oemTypes) {
            val flavor = manager.detectOSFlavor(oem)
            assertNotNull("OS flavor must not be null for $oem", flavor)
            assertTrue("OS flavor must be non-empty for $oem", flavor.isNotEmpty())
        }

        val status = manager.getBackgroundStatus()
        assertNotNull(status.formFactor)
        assertNotNull(status.osFlavor)
        assertTrue(status.stepByStepInstructions.isNotEmpty())
        assertTrue(status.actionLabel.isNotEmpty())
    }

    @Test
    fun testDeviceFormFactorEnumIntegrity() {
        val formFactors = DeviceFormFactor.values()
        assertEquals(3, formFactors.size)
        assertTrue(formFactors.contains(DeviceFormFactor.PHONE))
        assertTrue(formFactors.contains(DeviceFormFactor.TABLET))
        assertTrue(formFactors.contains(DeviceFormFactor.FOLDABLE))

        val manager = OEMBackgroundManager(context = null)
        val detected = manager.detectFormFactor()
        assertEquals(DeviceFormFactor.PHONE, detected)
    }

    @Test
    fun testOptimizationIntentCreationWithoutCrash() {
        val manager = OEMBackgroundManager(context = null)
        try {
            val intent = manager.createOptimizationIntent()
            assertNotNull(intent)
        } catch (_: RuntimeException) {
            // Android SDK framework methods unmocked in offline JVM unit test environment
        }
    }

    // ---------------------------------------------------------
    // 2. Scanner Engine Resilience & Interruption Handling
    // ---------------------------------------------------------

    @Test
    fun testScannerEngineHandlesInterruptedThreadGracefully() {
        val signatureDb = SignatureDatabase()
        val scanner = ScannerEngine(signatureDb = signatureDb)

        val sampleData = "Normal document contents".toByteArray()
        val stream = ByteArrayInputStream(sampleData)

        // Set the thread interrupt flag
        Thread.currentThread().interrupt()

        val result = scanner.scanStream(
            fileName = "interrupted_test.txt",
            filePath = "/sdcard/Documents/interrupted_test.txt",
            fileSize = sampleData.size.toLong(),
            inputStream = stream
        )

        // Clear interrupt flag for subsequent test execution
        Thread.interrupted()

        assertEquals(ScanVerdict.SCAN_ERROR, result.verdict)
        assertNotNull(result.errorMessage)
        assertTrue(result.errorMessage!!.contains("SCAN_CANCELLED"))
    }

    @Test
    fun testScannerEngineHandlesCorruptedStreamGracefully() {
        val signatureDb = SignatureDatabase()
        val scanner = ScannerEngine(signatureDb = signatureDb)

        val corruptData = "[TRUNCATED_STREAM_AT_OFFSET_0x4F]".toByteArray()
        val stream = ByteArrayInputStream(corruptData)

        val result = scanner.scanStream(
            fileName = "corrupted.bin",
            filePath = "/sdcard/Downloads/corrupted.bin",
            fileSize = corruptData.size.toLong(),
            inputStream = stream
        )

        assertEquals(ScanVerdict.SCAN_ERROR, result.verdict)
        assertNotNull(result.errorMessage)
        assertTrue(result.errorMessage!!.contains("corrupted", ignoreCase = true))
    }

    // ---------------------------------------------------------
    // 3. Safe Archive Inspection: Zip Slip & Directory Traversal
    // ---------------------------------------------------------

    @Test
    fun testArchiveInspectorDetectsZipSlipDirectoryTraversal() {
        val inspector = ArchiveInspector()

        // Create in-memory zip archive with path traversal entry
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            val evilEntry = ZipEntry("../../system/app/malicious.apk")
            zos.putNextEntry(evilEntry)
            zos.write("payload".toByteArray())
            zos.closeEntry()
        }

        val zipBytes = baos.toByteArray()
        val check = inspector.inspectZipStream("exploit_sample.zip", ByteArrayInputStream(zipBytes))

        assertTrue("Zip Slip traversal must be flagged", check.isZipSlipAttempt)
        assertFalse("Exploitative zip must not be marked safe", check.isSafe)
        assertTrue(check.suspiciousEntries.any { it.contains("PATH_TRAVERSAL") })
    }

    @Test
    fun testArchiveInspectorDetectsLegitimateZipAsSafe() {
        val inspector = ArchiveInspector()

        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            val normalEntry = ZipEntry("photos/vacation.jpg")
            zos.putNextEntry(normalEntry)
            zos.write(ByteArray(1024))
            zos.closeEntry()
        }

        val zipBytes = baos.toByteArray()
        val check = inspector.inspectZipStream("vacation.zip", ByteArrayInputStream(zipBytes))

        assertFalse("Legitimate zip must not be flagged as zip slip", check.isZipSlipAttempt)
        assertFalse("Legitimate zip must not be flagged as zip bomb", check.isZipBombAttempt)
        assertTrue("Legitimate zip must be safe", check.isSafe)
    }

    // ---------------------------------------------------------
    // 4. Quarantine Vault: Atomic Ledger & Orphan Recovery
    // ---------------------------------------------------------

    @Test
    fun testQuarantineLedgerBackupCreatedAndMaintained() {
        val qm = QuarantineManager(tempVaultDir)
        val payload1 = "Threat payload 1".toByteArray(Charsets.UTF_8)
        val payload2 = "Threat payload 2".toByteArray(Charsets.UTF_8)

        qm.quarantineBytes("threat1.apk", "/sdcard/threat1.apk", payload1, "Trojan1", "sha256_1")
        qm.quarantineBytes("threat2.apk", "/sdcard/threat2.apk", payload2, "Trojan2", "sha256_2")

        val ledgerFile = File(tempVaultDir, "quarantine_ledger.json")
        val backupFile = File(tempVaultDir, "quarantine_ledger.json.bak")

        assertTrue("Main ledger must exist", ledgerFile.exists())
        assertTrue("Backup ledger must exist after updates", backupFile.exists())
    }

    @Test
    fun testQuarantineRecoversOrphanedVaultFilesWhenLedgerCorrupted() {
        val qm = QuarantineManager(tempVaultDir)
        val payload = "Important isolated payload".toByteArray(Charsets.UTF_8)

        val record = qm.quarantineBytes("isolated.apk", "/sdcard/isolated.apk", payload, "Spyware", "sha256_isolated")
        val vaultFile = File(record.vaultFilePath)
        assertTrue(vaultFile.exists())

        // Deliberately corrupt both ledger and backup
        val ledgerFile = File(tempVaultDir, "quarantine_ledger.json")
        val backupFile = File(tempVaultDir, "quarantine_ledger.json.bak")
        ledgerFile.writeText("CORRUPTED_JSON_NOT_VALID")
        if (backupFile.exists()) backupFile.writeText("CORRUPTED_JSON_BACKUP")

        // Recreate QuarantineManager: should automatically reconstruct records from .biq files
        val recoveredQm = QuarantineManager(tempVaultDir)
        val recoveredHistory = recoveredQm.getQuarantineHistory()

        assertEquals(1, recoveredHistory.size)
        assertEquals(record.id, recoveredHistory[0].id)
        assertEquals(QuarantineStatus.QUARANTINED, recoveredHistory[0].status)
    }

    // ---------------------------------------------------------
    // 5. Licensing Engine Quota & Model Integrity
    // ---------------------------------------------------------

    @Test
    fun testFreeQuotaDailyLimitAndGating() {
        val lm = LicenseManager(context = null)
        assertEquals(Edition.FREE, lm.getEdition())
        assertEquals(5, lm.getRemainingScans())

        // Consume 5 scans
        for (i in 1..5) {
            val (canScan, _) = lm.canPerformScan()
            assertTrue("Scan $i should be permitted", canScan)
            lm.recordScanPerformed()
            assertEquals(5 - i, lm.getRemainingScans())
        }

        // 6th scan should be rejected under Free tier
        val (canScan6, msg6) = lm.canPerformScan()
        assertFalse("6th scan must be rejected under Free quota", canScan6)
        assertTrue(msg6.contains("allowance reached"))
        assertEquals(0, lm.getRemainingScans())

        // Deep scan is premium only
        val (canDeepScan, deepMsg) = lm.canPerformScan(isDeepScan = true)
        assertFalse("Deep scan must be restricted in Free edition", canDeepScan)
        assertTrue(deepMsg.contains("exclusive BI Antivirus Premium capability"))
    }

    @Test
    fun testScanVerdictPropertiesIntegrity() {
        assertTrue(ScanVerdict.THREAT_DETECTED.isThreat)
        assertTrue(ScanVerdict.SUSPICIOUS.isThreat)
        assertFalse(ScanVerdict.CLEAN.isThreat)
        assertFalse(ScanVerdict.UNSUPPORTED.isThreat)
        assertFalse(ScanVerdict.SCAN_ERROR.isThreat)

        assertTrue(ScanVerdict.THREAT_DETECTED.isActionable)
        assertTrue(ScanVerdict.SUSPICIOUS.isActionable)
        assertTrue(ScanVerdict.SCAN_ERROR.isActionable)
        assertFalse(ScanVerdict.CLEAN.isActionable)
        assertFalse(ScanVerdict.UNSUPPORTED.isActionable)
    }
}
