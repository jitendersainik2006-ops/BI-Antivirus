package com.biantivirus.security

import com.biantivirus.security.core.WebReputationAuditor
import com.biantivirus.security.core.WebVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class WebReputationAuditorTest {

    private lateinit var auditor: WebReputationAuditor

    @Before
    fun setUp() {
        auditor = WebReputationAuditor()
    }

    @Test
    fun testCleanLegitimateDomain() {
        val result = auditor.auditUrl("https://www.google.com")
        assertEquals(WebVerdict.SAFE, result.verdict)
        assertEquals(0, result.riskScore)
        assertTrue(result.reasons.isEmpty())
    }

    @Test
    fun testIpAddressUrl() {
        val result = auditor.auditUrl("http://192.168.1.100/index.html")
        assertEquals(WebVerdict.SUSPICIOUS, result.verdict)
        assertTrue(result.riskScore >= 35)
        assertTrue(result.reasons.any { it.contains("Raw IP address") })
    }

    @Test
    fun testPhishingKeywordDomain() {
        val result = auditor.auditUrl("https://login-verify-service.top/auth")
        assertEquals(WebVerdict.PHISHING, result.verdict)
        assertTrue(result.riskScore >= 60)
        assertTrue(result.reasons.any { it.contains("phishing") })
        assertTrue(result.reasons.any { it.contains("top-level domain") })
    }

    @Test
    fun testPunycodeHomoglyph() {
        val result = auditor.auditUrl("https://xn--pple-43d.com")
        assertEquals(WebVerdict.SUSPICIOUS, result.verdict)
        assertTrue(result.reasons.any { it.contains("Punycode") })
    }
}
