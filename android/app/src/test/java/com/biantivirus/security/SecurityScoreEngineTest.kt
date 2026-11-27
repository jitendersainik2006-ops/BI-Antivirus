package com.biantivirus.security

import com.biantivirus.security.core.AppPrivacyProfile
import com.biantivirus.security.core.PrivacyAuditReport
import com.biantivirus.security.core.PrivacyRiskLevel
import com.biantivirus.security.core.SecurityScoreEngine
import com.biantivirus.security.model.CheckStatus
import com.biantivirus.security.model.DevicePosture
import com.biantivirus.security.model.PostureCheckItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityScoreEngineTest {

    private val engine = SecurityScoreEngine()

    private fun createOptimalPosture(): DevicePosture {
        return DevicePosture(
            reportId = "REP-TEST",
            deviceModel = "Universal Device",
            osVersion = "Android 14 (API 34)",
            overallScore = 100,
            statusText = "SECURE",
            checks = listOf(
                PostureCheckItem("CHK-LOCK-01", "Screen Lock", "Access", CheckStatus.PASS, "PIN set", "OK"),
                PostureCheckItem("CHK-ENC-02", "Encryption", "Storage", CheckStatus.PASS, "Encrypted", "OK"),
                PostureCheckItem("CHK-DEV-03", "ADB", "Attack Surface", CheckStatus.PASS, "Disabled", "OK"),
                PostureCheckItem("CHK-OS-04", "OS Version", "System", CheckStatus.PASS, "API 34", "OK")
            )
        )
    }

    private fun createCleanPrivacyReport(): PrivacyAuditReport {
        return PrivacyAuditReport(
            totalAppsAudited = 10,
            highRiskAppsCount = 0,
            privacyScore = 100,
            profiles = listOf(
                AppPrivacyProfile("com.clean.app", "Clean", "1.0", false, emptyList(), 0, PrivacyRiskLevel.LOW, "Clean")
            ),
            categorizedApps = emptyMap()
        )
    }

    @Test
    fun testOptimalDeviceAchieves100Score() {
        val report = engine.calculateScore(
            threatCount = 0,
            suspiciousCount = 0,
            posture = createOptimalPosture(),
            privacyReport = createCleanPrivacyReport(),
            signatureCount = 50
        )

        assertEquals(100, report.overallScore)
        assertEquals("SECURE", report.statusText)
        assertEquals(40, report.threatPoints)
        assertEquals(30, report.posturePoints)
        assertEquals(20, report.privacyPoints)
        assertEquals(10, report.signaturePoints)
        assertTrue(report.actionableRecommendations.isEmpty())
    }

    @Test
    fun testActiveThreatDeductsAllThreatPoints() {
        val report = engine.calculateScore(
            threatCount = 2,
            suspiciousCount = 0,
            posture = createOptimalPosture(),
            privacyReport = createCleanPrivacyReport(),
            signatureCount = 50
        )

        assertEquals(0, report.threatPoints)
        assertEquals(60, report.overallScore)
        assertEquals("ATTENTION", report.statusText)
        assertTrue(report.actionableRecommendations.any { it.contains("active malware threat") })
    }

    @Test
    fun testInsecurePostureDeductsPointsAccurately() {
        val insecurePosture = DevicePosture(
            reportId = "REP-INSECURE",
            deviceModel = "Test Device",
            osVersion = "Android 10",
            overallScore = 40,
            statusText = "AT_RISK",
            checks = listOf(
                PostureCheckItem("CHK-LOCK-01", "Screen Lock", "Access", CheckStatus.FAIL, "No lock", "Set lock"),
                PostureCheckItem("CHK-ENC-02", "Encryption", "Storage", CheckStatus.PASS, "Encrypted", "OK"),
                PostureCheckItem("CHK-DEV-03", "ADB", "Attack Surface", CheckStatus.WARN, "ADB Enabled", "Disable ADB"),
                PostureCheckItem("CHK-OS-04", "OS Version", "System", CheckStatus.WARN, "Old Android", "Update OS")
            )
        )

        val report = engine.calculateScore(
            threatCount = 0,
            suspiciousCount = 0,
            posture = insecurePosture,
            privacyReport = createCleanPrivacyReport(),
            signatureCount = 50
        )

        // posturePoints should be 10 (encryption only) out of 30
        assertEquals(10, report.posturePoints)
        // overall score: 40 (threat) + 10 (posture) + 20 (privacy) + 10 (signatures) = 80
        assertEquals(80, report.overallScore)
        assertEquals("ATTENTION", report.statusText)
        assertTrue(report.actionableRecommendations.any { it.contains("Screen Lock") })
        assertTrue(report.actionableRecommendations.any { it.contains("USB Debugging") })
    }
}
