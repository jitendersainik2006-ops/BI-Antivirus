package com.biantivirus.security

import com.biantivirus.security.core.Edition
import com.biantivirus.security.core.LicenseManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Android Unit Tests for BI Antivirus Licensing Architecture
 * Verifies asymmetric RSA-2048 token verification, tampered token rejection,
 * expired token rejection, daily Free quotas, and feature gating.
 */
class LicenseManagerTest {

    private val manager = LicenseManager(context = null)

    companion object {
        // Cryptographically signed asymmetric token from official Black Intel Issuer
        const val VALID_RSA_TOKEN =
            "BI-LIC-V2.eyJleHBpcmVzX2F0IjoxODI3MzExMDY5LCJmZWF0dXJlcyI6WyJkZWVwX3NjYW4iLCJ1bmxpbWl0ZWRfc2" +
            "NhbnMiLCJhZHZhbmNlZF9oZXVyaXN0aWNzIiwicmFuc29td2FyZV9zaGllbGQiXSwiaXNzdWVkX2F0IjoxNzk1Nzc1MD" +
            "Y5LCJpc3N1ZWRfdG8iOiJFbnRlcnByaXNlIEVuZHBvaW50IiwibGljZW5zZV9pZCI6IkJJLVBSRU0tNzE3MC00MkUzLT" +
            "IyRDUiLCJwcm9kdWN0IjoiQkktQU5USVZJUlVTIiwidGllciI6IlBSRU1JVU0ifQ.LHGh5YGgXP0qfTG2roz-vvb3120" +
            "oFj2E0HpTiuFuXzE_hvjOcsE718GGl--5ogtnl4HFHlP8z-aAHnxalhWfBmkHbuLLHtXCziWup4GLZSA2qBj483PhXpFC" +
            "EXESHtrnD5MGo4RMC8dSYOBp5rs34tpgySVZrcNYs1K4MMVU8zwE3qawY2dAaT1jiRlrnLM2qGkUbPCipiupf1DfqPDh" +
            "veVzwkTjy_Ew6RsHRtJS5ObP8VvKbU0nxisaXI2-W_6jDczG89U9usIZE5aAkISaeq2n5vRx7BkwQ5G13cNqaZJvC8gY" +
            "zsNN7B1H8SYIxxN9SCdaAR-KrQMt3f4CJqmdgw"

        const val EXPIRED_RSA_TOKEN =
            "BI-LIC-V2.e2V4cGlyZXNfYXQ6MTYwMDAwMDAwMCxmZWF0dXJlczpbZGVlcF9zY2FuXSxpc3N1ZWRfYXQ6MTUwMDAwMD" +
            "AwMCxsaWNlbnNlX2lkOkJJLVBSRU0tNzE3MC1FWFBJUkVELTk5LHByb2R1Y3Q6QkktQU5USVZJUlVTLHRpZXI6UFJFTUl" +
            "VTX0.l2Qg5rGYeNsmONn0HRfYpJovl341Kg5JnPbBoctQDbJudBPfW3dlLFJKhL6cUU1kzeNp_jdeFDww_UxnsO7xivdG" +
            "844BIUbb-rCBjfVyD7WavP_oQh9V71T7pOYSR6xrR38oChV51WkTCmYas56G7EHFMtKnRj9iQ1e9EuD8QLi3W7mrlEKZ" +
            "80l8-7fixDgBGEauPFLOuUn47MV9wFtzmBwrI-us4Bgx094a9wGU1Lnv12Oh9le-HJ4iw3TP3mTFGe5YRJ_OcG9ZhLWsh" +
            "0ijhobKDgfxHwDy5z4uS0Hm1lfV2sps1poGUsmC2ws88a8TpbVgKMl42p5pUbyAGXx-qg"
    }

    @Test
    fun testDefaultEditionIsFree() {
        assertEquals(Edition.FREE, manager.getEdition())
        assertFalse(manager.isPremium())
        assertEquals(5, manager.getRemainingScans())
    }

    @Test
    fun testValidAsymmetricRsaTokenActivation() {
        val (valid, tier, msg) = LicenseManager.validateKey(VALID_RSA_TOKEN)
        assertTrue(valid)
        assertEquals(Edition.PREMIUM, tier)
        assertTrue(msg.contains("Valid", ignoreCase = true))

        val (ok, actMsg) = manager.activate(VALID_RSA_TOKEN)
        assertTrue(ok)
        assertEquals(Edition.PREMIUM, manager.getEdition())
        assertTrue(manager.isPremium())
        assertEquals(-1, manager.getRemainingScans()) // Unlimited
    }

    @Test
    fun testTamperedAsymmetricTokenRejected() {
        val parts = VALID_RSA_TOKEN.split(".")
        // Tamper signature
        val tamperedSig = parts[2].substring(0, parts[2].length - 4) + "ZZZZ"
        val badToken = "${parts[0]}.${parts[1]}.$tamperedSig"

        val (valid, _, msg) = LicenseManager.validateKey(badToken)
        assertFalse(valid)
        assertTrue(msg.contains("validation failed", ignoreCase = true))
    }

    @Test
    fun testExpiredAsymmetricTokenRejected() {
        val (valid, _, msg) = LicenseManager.validateKey(EXPIRED_RSA_TOKEN)
        assertFalse(valid)
        assertTrue(msg.contains("expired", ignoreCase = true))
    }

    @Test
    fun testKeyValidationRejectsMalformedKeys() {
        val (v1, _, _) = LicenseManager.validateKey("")
        assertFalse(v1)

        val (v2, _, _) = LicenseManager.validateKey("INVALID-KEY")
        assertFalse(v2)

        val (v3, _, _) = LicenseManager.validateKey("BI-LIC-V2.NOT_VALID_BASE64.SIG")
        assertFalse(v3)
    }

    @Test
    fun testActivateAndDeactivatePremium() {
        val (ok, _) = manager.activate(VALID_RSA_TOKEN)
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

        // 6th scan must be rejected
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
