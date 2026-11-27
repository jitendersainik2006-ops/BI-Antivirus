package com.biantivirus.security

import com.biantivirus.security.core.Edition
import com.biantivirus.security.core.LicenseManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LicenseManagerTest {

    private val manager = LicenseManager(context = null)

    @Test
    fun testDefaultEditionIsFree() {
        assertEquals(Edition.FREE, manager.getEdition())
        assertFalse(manager.isPremium())
        assertEquals(5, manager.getRemainingScans())
    }

    @Test
    fun testKeyValidationWithCorrectChecksum() {
        // Derive valid key using computeKeyChecksum
        val basePayload = "BI-PREM-7170-B1AC-K1NT"
        val chk = LicenseManager.computeKeyChecksum(basePayload)
        val validKey = "$basePayload-$chk"

        val (valid, tier, msg) = LicenseManager.validateKey(validKey)
        assertTrue(valid)
        assertEquals(Edition.PREMIUM, tier)
        assertTrue(msg.contains("Valid", ignoreCase = true))
    }

    @Test
    fun testKeyValidationRejectsTamperedChecksum() {
        val basePayload = "BI-PREM-7170-B1AC-K1NT"
        val chk = LicenseManager.computeKeyChecksum(basePayload)
        val tamperedChk = if (chk != "0000") "0000" else "FFFF"
        val badKey = "$basePayload-$tamperedChk"

        val (valid, _, msg) = LicenseManager.validateKey(badKey)
        assertFalse(valid)
        assertTrue(msg.contains("checksum", ignoreCase = true))
    }

    @Test
    fun testKeyValidationRejectsMalformedKeys() {
        val (v1, _, _) = LicenseManager.validateKey("")
        assertFalse(v1)

        val (v2, _, _) = LicenseManager.validateKey("INVALID-KEY")
        assertFalse(v2)

        val (v3, _, _) = LicenseManager.validateKey("BI-PREM-SHORT-KEY")
        assertFalse(v3)
    }

    @Test
    fun testActivateAndDeactivatePremium() {
        val basePayload = "BI-PREM-7170-TEST-UNIT"
        val chk = LicenseManager.computeKeyChecksum(basePayload)
        val validKey = "$basePayload-$chk"

        val (ok, msg) = manager.activate(validKey)
        assertTrue(ok)
        assertEquals(Edition.PREMIUM, manager.getEdition())
        assertTrue(manager.isPremium())
        assertEquals(-1, manager.getRemainingScans()) // Unlimited

        val (deepAllowed, _) = manager.canPerformScan(isDeepScan = true)
        assertTrue(deepAllowed)

        val (deactOk, _) = manager.deactivate()
        assertTrue(deactOk)
        assertEquals(Edition.FREE, manager.getEdition())
        assertFalse(manager.isPremium())
    }

    @Test
    fun testDeepScanLockedOnFreeEdition() {
        assertEquals(Edition.FREE, manager.getEdition())
        val (allowed, reason) = manager.canPerformScan(isDeepScan = true)
        assertFalse(allowed)
        assertTrue(reason.contains("Premium", ignoreCase = true))
    }

    @Test
    fun testDailyScanAllowanceQuota() {
        assertEquals(Edition.FREE, manager.getEdition())
        assertEquals(5, manager.getRemainingScans())

        for (i in 0 until 5) {
            val (allowed, _) = manager.canPerformScan(isDeepScan = false)
            assertTrue(allowed)
            manager.recordScanPerformed(isDeepScan = false)
        }

        // 6th scan should be blocked
        val (allowed6, reason6) = manager.canPerformScan(isDeepScan = false)
        assertFalse(allowed6)
        assertTrue(reason6.contains("allowance reached", ignoreCase = true))
        assertEquals(0, manager.getRemainingScans())
    }

    @Test
    fun testStatusSummaryCompleteness() {
        val summary = manager.getStatusSummary()
        assertNotNull(summary.edition)
        assertNotNull(summary.resetTimeRemainingText)
        assertTrue(summary.maxFreeScansPerDay >= 5)
    }
}
