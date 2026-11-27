package com.biantivirus.security.core

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import java.util.UUID

enum class PrivacyRiskLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

data class SensitivePermission(
    val permissionId: String,
    val displayName: String,
    val category: String,
    val riskWeight: Int,
    val description: String
)

data class AppPrivacyProfile(
    val packageName: String,
    val appName: String,
    val versionName: String,
    val isSystemApp: Boolean,
    val sensitivePermissions: List<SensitivePermission>,
    val riskScore: Int,
    val riskLevel: PrivacyRiskLevel,
    val recommendation: String
)

data class PrivacyAuditReport(
    val reportId: String = "PRIV-" + UUID.randomUUID().toString().substring(0, 8).uppercase(),
    val timestamp: Long = System.currentTimeMillis(),
    val totalAppsAudited: Int,
    val highRiskAppsCount: Int,
    val privacyScore: Int, // 0 to 100, where 100 is optimal/safe
    val profiles: List<AppPrivacyProfile>,
    val categorizedApps: Map<String, List<AppPrivacyProfile>>
)

class PrivacyAuditor(private val context: Context? = null) {

    companion object {
        val SENSITIVE_PERMISSIONS_CATALOG = mapOf(
            "android.permission.BIND_ACCESSIBILITY_SERVICE" to SensitivePermission(
                permissionId = "android.permission.BIND_ACCESSIBILITY_SERVICE",
                displayName = "Accessibility Service",
                category = "Full System Control",
                riskWeight = 30,
                description = "Allows reading all on-screen content, keystrokes, and simulating user clicks."
            ),
            "android.permission.BIND_DEVICE_ADMIN" to SensitivePermission(
                permissionId = "android.permission.BIND_DEVICE_ADMIN",
                displayName = "Device Administrator",
                category = "Full System Control",
                riskWeight = 25,
                description = "Grants endpoint administrator rights, including lock and wipe capabilities."
            ),
            "android.permission.SYSTEM_ALERT_WINDOW" to SensitivePermission(
                permissionId = "android.permission.SYSTEM_ALERT_WINDOW",
                displayName = "Display Over Other Apps",
                category = "Screen Overlay",
                riskWeight = 20,
                description = "Enables drawing over active applications, a technique often used in phishing or tapjacking."
            ),
            "android.permission.REQUEST_INSTALL_PACKAGES" to SensitivePermission(
                permissionId = "android.permission.REQUEST_INSTALL_PACKAGES",
                displayName = "Install Unknown Apps",
                category = "App Management",
                riskWeight = 20,
                description = "Permits downloading and installing secondary executable packages."
            ),
            "android.permission.RECEIVE_SMS" to SensitivePermission(
                permissionId = "android.permission.RECEIVE_SMS",
                displayName = "Receive SMS Messages",
                category = "SMS & Telephony",
                riskWeight = 18,
                description = "Allows intercepting incoming SMS messages, including 2FA verification codes."
            ),
            "android.permission.READ_SMS" to SensitivePermission(
                permissionId = "android.permission.READ_SMS",
                displayName = "Read SMS Storage",
                category = "SMS & Telephony",
                riskWeight = 18,
                description = "Permits reading confidential SMS messages and transaction history."
            ),
            "android.permission.SEND_SMS" to SensitivePermission(
                permissionId = "android.permission.SEND_SMS",
                displayName = "Send SMS Messages",
                category = "SMS & Telephony",
                riskWeight = 15,
                description = "Can send SMS messages in the background, potentially incurring charges."
            ),
            "android.permission.RECORD_AUDIO" to SensitivePermission(
                permissionId = "android.permission.RECORD_AUDIO",
                displayName = "Record Audio / Microphone",
                category = "Audio Surveillance",
                riskWeight = 15,
                description = "Captures raw microphone audio without persistent UI cues."
            ),
            "android.permission.CAMERA" to SensitivePermission(
                permissionId = "android.permission.CAMERA",
                displayName = "Camera Access",
                category = "Visual Surveillance",
                riskWeight = 15,
                description = "Captures photos and video streams from front and rear cameras."
            ),
            "android.permission.ACCESS_FINE_LOCATION" to SensitivePermission(
                permissionId = "android.permission.ACCESS_FINE_LOCATION",
                displayName = "Precise GPS Location",
                category = "Physical Tracking",
                riskWeight = 14,
                description = "Accesses precise GPS coordinates and physical movement logs."
            ),
            "android.permission.ACCESS_BACKGROUND_LOCATION" to SensitivePermission(
                permissionId = "android.permission.ACCESS_BACKGROUND_LOCATION",
                displayName = "Background Location",
                category = "Physical Tracking",
                riskWeight = 16,
                description = "Continuously tracks physical device location even when app is closed."
            ),
            "android.permission.READ_CONTACTS" to SensitivePermission(
                permissionId = "android.permission.READ_CONTACTS",
                displayName = "Read Address Book",
                category = "Personal Contacts",
                riskWeight = 12,
                description = "Reads private contacts, telephone numbers, and email directories."
            ),
            "android.permission.READ_CALL_LOG" to SensitivePermission(
                permissionId = "android.permission.READ_CALL_LOG",
                displayName = "Read Call Records",
                category = "Telephony",
                riskWeight = 14,
                description = "Accesses complete incoming and outgoing voice call history."
            )
        )
    }

    fun auditPrivacy(includeSystemApps: Boolean = false): PrivacyAuditReport {
        val ctx = context ?: return PrivacyAuditReport(
            totalAppsAudited = 0,
            highRiskAppsCount = 0,
            privacyScore = 100,
            profiles = emptyList(),
            categorizedApps = emptyMap()
        )

        val pm = ctx.packageManager
        val packages = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (_: Exception) {
            emptyList<PackageInfo>()
        }

        val targetPackages = packages.filter { pkg ->
            val isSystem = (pkg.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM) ?: 0) != 0
            includeSystemApps || !isSystem
        }

        val profiles = mutableListOf<AppPrivacyProfile>()
        val categoryMap = mutableMapOf<String, MutableList<AppPrivacyProfile>>()

        for (pkg in targetPackages) {
            val profile = evaluatePackage(pkg, pm)
            profiles.add(profile)

            for (perm in profile.sensitivePermissions) {
                categoryMap.getOrPut(perm.category) { mutableListOf() }.add(profile)
            }
        }

        // Calculate overall device Privacy Health Score (0 - 100)
        // High risk apps deduct points proportionally
        val highRiskCount = profiles.count { it.riskLevel == PrivacyRiskLevel.CRITICAL || it.riskLevel == PrivacyRiskLevel.HIGH }
        val mediumRiskCount = profiles.count { it.riskLevel == PrivacyRiskLevel.MEDIUM }

        var calculatedScore = 100 - (highRiskCount * 12) - (mediumRiskCount * 4)
        calculatedScore = calculatedScore.coerceIn(10, 100)

        return PrivacyAuditReport(
            totalAppsAudited = profiles.size,
            highRiskAppsCount = highRiskCount,
            privacyScore = calculatedScore,
            profiles = profiles.sortedByDescending { it.riskScore },
            categorizedApps = categoryMap
        )
    }

    fun evaluatePackage(pkg: PackageInfo, pm: PackageManager? = null): AppPrivacyProfile {
        val isSystem = (pkg.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM) ?: 0) != 0
        val appName = try {
            if (pm != null && pkg.applicationInfo != null) {
                pm.getApplicationLabel(pkg.applicationInfo!!).toString()
            } else {
                pkg.packageName
            }
        } catch (_: Exception) {
            pkg.packageName
        }

        val requested = pkg.requestedPermissions?.toList() ?: emptyList()
        val detectedSensitive = mutableListOf<SensitivePermission>()
        var scoreAccumulator = 0

        for (permName in requested) {
            val catalogEntry = SENSITIVE_PERMISSIONS_CATALOG[permName]
            if (catalogEntry != null) {
                detectedSensitive.add(catalogEntry)
                scoreAccumulator += catalogEntry.riskWeight
            }
        }

        // Cap individual app risk score at 100
        val cappedRiskScore = scoreAccumulator.coerceIn(0, 100)

        val riskLevel = when {
            cappedRiskScore >= 50 -> PrivacyRiskLevel.CRITICAL
            cappedRiskScore >= 30 -> PrivacyRiskLevel.HIGH
            cappedRiskScore >= 15 -> PrivacyRiskLevel.MEDIUM
            else -> PrivacyRiskLevel.LOW
        }

        val recommendation = when (riskLevel) {
            PrivacyRiskLevel.CRITICAL -> "App holds excessive high-risk permissions. Review and revoke unneeded permissions in App Settings."
            PrivacyRiskLevel.HIGH -> "App accesses sensitive device hardware or personal data. Ensure it comes from a verified developer."
            PrivacyRiskLevel.MEDIUM -> "App requests standard privacy-impacting capabilities."
            PrivacyRiskLevel.LOW -> "Minimal sensitive permission footprint."
        }

        return AppPrivacyProfile(
            packageName = pkg.packageName,
            appName = appName,
            versionName = pkg.versionName ?: "1.0",
            isSystemApp = isSystem,
            sensitivePermissions = detectedSensitive,
            riskScore = cappedRiskScore,
            riskLevel = riskLevel,
            recommendation = recommendation
        )
    }

    fun createAppDetailsIntent(packageName: String): Intent {
        return Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.fromParts("package", packageName, null)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }
}
