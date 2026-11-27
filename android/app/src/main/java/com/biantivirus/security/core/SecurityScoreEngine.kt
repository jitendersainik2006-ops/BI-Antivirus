package com.biantivirus.security.core

import com.biantivirus.security.model.CheckStatus
import com.biantivirus.security.model.DevicePosture
import com.biantivirus.security.model.ScanVerdict

data class ScoreFactor(
    val id: String,
    val title: String,
    val category: String,
    val earnedPoints: Int,
    val maxPoints: Int,
    val isOptimal: Boolean,
    val explanation: String,
    val actionableFix: String?
)

data class SecurityScoreReport(
    val overallScore: Int, // 0 - 100
    val statusText: String, // "SECURE", "ATTENTION", "AT_RISK"
    val threatPoints: Int, // Max 40
    val posturePoints: Int, // Max 30
    val privacyPoints: Int, // Max 20
    val signaturePoints: Int, // Max 10
    val factors: List<ScoreFactor>,
    val actionableRecommendations: List<String>
)

class SecurityScoreEngine {

    fun calculateScore(
        threatCount: Int = 0,
        suspiciousCount: Int = 0,
        posture: DevicePosture? = null,
        privacyReport: PrivacyAuditReport? = null,
        signatureCount: Int = 0
    ): SecurityScoreReport {
        val factors = mutableListOf<ScoreFactor>()
        val recommendations = mutableListOf<String>()

        // 1. Threat Protection (Max 40 points)
        val threatPoints: Int = when {
            threatCount > 0 -> {
                recommendations.add("CRITICAL: Eliminate $threatCount active malware threat(s) immediately (+40 pts).")
                0
            }
            suspiciousCount > 0 -> {
                val earned = (40 - (suspiciousCount * 15)).coerceAtLeast(10)
                recommendations.add("Review and quarantine $suspiciousCount suspicious application(s) (+${40 - earned} pts).")
                earned
            }
            else -> 40
        }

        factors.add(
            ScoreFactor(
                id = "FACTOR-THREAT",
                title = "Malware & Threat Defense",
                category = "Endpoint Protection",
                earnedPoints = threatPoints,
                maxPoints = 40,
                isOptimal = threatPoints == 40,
                explanation = if (threatPoints == 40) "Zero malware infections or suspicious binaries detected."
                else "Active threats or unquarantined suspicious items detected.",
                actionableFix = if (threatPoints < 40) "Quarantine or uninstall flagged threats from the Scanner screen." else null
            )
        )

        // 2. Device Posture (Max 30 points)
        var posturePoints = 0

        // 2a. Screen Lock (10 pts)
        val lockCheck = posture?.checks?.find { it.checkId == "CHK-LOCK-01" }
        val hasLock = lockCheck?.status == CheckStatus.PASS
        if (hasLock) {
            posturePoints += 10
            factors.add(ScoreFactor("FACTOR-LOCK", "Screen Lock Security", "Device Access", 10, 10, true, "PIN, Pattern, or Password configured.", null))
        } else {
            recommendations.add("Configure a device Screen Lock (PIN or Password) in Android Settings (+10 pts).")
            factors.add(ScoreFactor("FACTOR-LOCK", "Screen Lock Security", "Device Access", 0, 10, false, "Device is unprotected by screen lock.", "Set up a screen lock in Android Settings > Security."))
        }

        // 2b. Storage Encryption (10 pts)
        val encCheck = posture?.checks?.find { it.checkId == "CHK-ENC-02" }
        val isEncrypted = encCheck?.status == CheckStatus.PASS
        if (isEncrypted) {
            posturePoints += 10
            factors.add(ScoreFactor("FACTOR-ENC", "Hardware Encryption", "Data Protection", 10, 10, true, "File-based hardware encryption active.", null))
        } else {
            factors.add(ScoreFactor("FACTOR-ENC", "Hardware Encryption", "Data Protection", 0, 10, false, "Storage encryption not detected as active.", "Enable device encryption."))
        }

        // 2c. USB Debugging ADB (5 pts)
        val adbCheck = posture?.checks?.find { it.checkId == "CHK-DEV-03" }
        val adbSafe = adbCheck?.status == CheckStatus.PASS
        if (adbSafe) {
            posturePoints += 5
            factors.add(ScoreFactor("FACTOR-ADB", "USB Debugging Bridge", "Host Attack Surface", 5, 5, true, "USB debugging disabled.", null))
        } else {
            recommendations.add("Turn off USB Debugging in Developer Options when not testing (+5 pts).")
            factors.add(ScoreFactor("FACTOR-ADB", "USB Debugging Bridge", "Host Attack Surface", 0, 5, false, "USB debugging is active, increasing attack surface.", "Disable USB Debugging in Settings > Developer Options."))
        }

        // 2d. OS Version Baseline (5 pts)
        val osCheck = posture?.checks?.find { it.checkId == "CHK-OS-04" }
        val osSafe = osCheck?.status == CheckStatus.PASS
        if (osSafe) {
            posturePoints += 5
            factors.add(ScoreFactor("FACTOR-OS", "OS Security Baseline", "System Integrity", 5, 5, true, "Running modern Android baseline (API 33+).", null))
        } else {
            factors.add(ScoreFactor("FACTOR-OS", "OS Security Baseline", "System Integrity", 0, 5, false, "Running legacy Android baseline.", "Check for system software updates in Settings > System."))
        }

        // 3. Privacy & Permission Exposure (Max 20 points)
        val criticalPrivacyApps = privacyReport?.profiles?.count { it.riskLevel == PrivacyRiskLevel.CRITICAL } ?: 0
        val highPrivacyApps = privacyReport?.profiles?.count { it.riskLevel == PrivacyRiskLevel.HIGH } ?: 0

        val privacyPoints: Int = when {
            criticalPrivacyApps == 0 && highPrivacyApps == 0 -> 20
            criticalPrivacyApps == 0 && highPrivacyApps <= 2 -> 15
            criticalPrivacyApps <= 1 -> 10
            criticalPrivacyApps <= 3 -> 5
            else -> 2
        }

        if (privacyPoints < 20) {
            recommendations.add("Audit permissions of $criticalPrivacyApps critical and $highPrivacyApps high-privilege apps (+${20 - privacyPoints} pts).")
        }

        factors.add(
            ScoreFactor(
                id = "FACTOR-PRIVACY",
                title = "App Privacy & Permissions",
                category = "Privacy Exposure",
                earnedPoints = privacyPoints,
                maxPoints = 20,
                isOptimal = privacyPoints == 20,
                explanation = if (privacyPoints == 20) "No third-party apps hold hazardous permission combinations."
                else "$criticalPrivacyApps app(s) hold critical permissions (Accessibility, Overlay, SMS).",
                actionableFix = if (privacyPoints < 20) "Open the Privacy Audit screen to review and revoke unneeded app permissions." else null
            )
        )

        // 4. Threat Intelligence Signatures (Max 10 points)
        val signaturePoints = if (signatureCount > 0) 10 else 0
        factors.add(
            ScoreFactor(
                id = "FACTOR-SIG",
                title = "Threat Intelligence Offline DB",
                category = "Engine Currency",
                earnedPoints = signaturePoints,
                maxPoints = 10,
                isOptimal = signaturePoints == 10,
                explanation = if (signaturePoints == 10) "Black Intel threat signature database loaded ($signatureCount verified rules)."
                else "Threat signature database uninitialized.",
                actionableFix = if (signaturePoints == 0) "Restart app or update threat definitions." else null
            )
        )

        val total = (threatPoints + posturePoints + privacyPoints + signaturePoints).coerceIn(0, 100)
        val statusText = when {
            total >= 85 -> "SECURE"
            total >= 60 -> "ATTENTION"
            else -> "AT_RISK"
        }

        return SecurityScoreReport(
            overallScore = total,
            statusText = statusText,
            threatPoints = threatPoints,
            posturePoints = posturePoints,
            privacyPoints = privacyPoints,
            signaturePoints = signaturePoints,
            factors = factors,
            actionableRecommendations = recommendations
        )
    }
}
