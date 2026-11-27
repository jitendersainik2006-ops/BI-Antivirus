package com.biantivirus.security.core

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.biantivirus.security.model.ScanResult
import com.biantivirus.security.model.ScanVerdict
import com.biantivirus.security.model.ThreatSeverity
import com.biantivirus.security.storage.ScanHistoryDatabase
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.UUID

data class InstalledAppThreat(
    val packageName: String,
    val appName: String,
    val versionName: String,
    val versionCode: Long,
    val apkPath: String,
    val apkSize: Long,
    val isSystemApp: Boolean,
    val sha256: String,
    val md5: String,
    val verdict: ScanVerdict,
    val threatName: String?,
    val threatFamily: String?,
    val severity: ThreatSeverity,
    val matchedRules: List<String>,
    val suspiciousPermissions: List<String>,
    val confidenceScore: Int = 0,
    val explainableReason: String = ""
)

data class AppScanProgress(
    val currentAppName: String,
    val currentPackageName: String,
    val scannedCount: Int,
    val totalCount: Int,
    val threatCount: Int,
    val percentage: Float
)

class AppScannerEngine(
    private val context: Context? = null,
    private val signatureDb: SignatureDatabase,
    private val historyDb: ScanHistoryDatabase? = null
) {

    private val DANGEROUS_PERMISSIONS = setOf(
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS"
    )

    fun scanAllApps(
        includeSystemApps: Boolean = false,
        onProgress: ((AppScanProgress) -> Unit)? = null
    ): List<InstalledAppThreat> {
        val ctx = context ?: return emptyList()
        val pm = ctx.packageManager
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION")
            PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNATURES
        }

        val allPackages = try {
            pm.getInstalledPackages(flags)
        } catch (e: Exception) {
            emptyList<PackageInfo>()
        }

        // Filter: prioritize third-party apps, optionally scan system apps
        val targetPackages = allPackages.filter { pkg ->
            val isSystem = (pkg.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM) ?: 0) != 0
            includeSystemApps || !isSystem
        }

        val total = targetPackages.size
        var scanned = 0
        var threatsFound = 0
        val results = mutableListOf<InstalledAppThreat>()

        for (pkg in targetPackages) {
            val appInfo = pkg.applicationInfo ?: continue
            val appName = try {
                pm.getApplicationLabel(appInfo).toString()
            } catch (_: Exception) {
                pkg.packageName
            }

            scanned++
            val progressPercent = if (total > 0) scanned.toFloat() / total.toFloat() else 1.0f
            onProgress?.invoke(
                AppScanProgress(
                    currentAppName = appName,
                    currentPackageName = pkg.packageName,
                    scannedCount = scanned,
                    totalCount = total,
                    threatCount = threatsFound,
                    percentage = progressPercent
                )
            )

            val threat = scanPackage(pkg, appName)
            if (threat.verdict == ScanVerdict.THREAT_DETECTED || threat.verdict == ScanVerdict.SUSPICIOUS) {
                threatsFound++
                results.add(threat)
            } else {
                results.add(threat)
            }
        }

        return results
    }

    fun scanPackage(pkg: PackageInfo, appName: String): InstalledAppThreat {
        val appInfo = pkg.applicationInfo
        val isSystem = (appInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM) ?: 0) != 0
        val apkPath = appInfo?.sourceDir ?: ""
        val apkFile = File(apkPath)
        val apkSize = if (apkFile.exists()) apkFile.length() else 0L

        val vCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pkg.longVersionCode
        } else {
            @Suppress("DEPRECATION")
            pkg.versionCode.toLong()
        }
        val vName = pkg.versionName ?: "1.0"

        // Calculate APK digests (read streaming safely up to 32MB for quick analysis)
        var sha256 = ""
        var md5 = ""
        if (apkFile.exists() && apkFile.canRead()) {
            try {
                val hashes = calculateApkHashes(apkFile)
                sha256 = hashes.first
                md5 = hashes.second
            } catch (_: Exception) {
                // Fallback if permissions restrict reading
            }
        }

        // 1. Signature Database Lookup
        val sigMatch = if (sha256.isNotEmpty()) signatureDb.findBySha256(sha256) else null
            ?: if (md5.isNotEmpty()) signatureDb.findByMd5(md5) else null

        if (sigMatch != null) {
            val threat = InstalledAppThreat(
                packageName = pkg.packageName,
                appName = appName,
                versionName = vName,
                versionCode = vCode,
                apkPath = apkPath,
                apkSize = apkSize,
                isSystemApp = isSystem,
                sha256 = sha256,
                md5 = md5,
                verdict = ScanVerdict.THREAT_DETECTED,
                threatName = sigMatch.name,
                threatFamily = sigMatch.family,
                severity = sigMatch.severity,
                matchedRules = listOf("SIG:EXACT_HASH_MATCH (${sigMatch.id})"),
                suspiciousPermissions = emptyList(),
                confidenceScore = 99,
                explainableReason = "Exact cryptographic hash match found in Black Intel threat intelligence database (${sigMatch.id}). Confirmed malicious package signature."
            )
            recordThreatInHistory(threat)
            return threat
        }

        // 2. Permission Profiling & Anomaly Detection
        val requested = pkg.requestedPermissions?.toList() ?: emptyList()
        val suspiciousPerms = requested.filter { it in DANGEROUS_PERMISSIONS }

        val hasAccessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in requested
        val hasOverlay = "android.permission.SYSTEM_ALERT_WINDOW" in requested
        val hasSms = "android.permission.RECEIVE_SMS" in requested || "android.permission.READ_SMS" in requested
        val hasDeviceAdmin = "android.permission.BIND_DEVICE_ADMIN" in requested
        val hasInstallPackages = "android.permission.REQUEST_INSTALL_PACKAGES" in requested

        val matchedRules = mutableListOf<String>()
        var verdict = ScanVerdict.CLEAN
        var threatName: String? = null
        var threatFamily: String? = null
        var severity = ThreatSeverity.NONE
        var confidence = 5
        var reason = "No known malicious signatures or hazardous permission abuse combinations detected."

        // Heuristic Banking Trojan Pattern: Accessibility + Overlay + SMS
        if (hasAccessibility && (hasOverlay || hasSms)) {
            verdict = ScanVerdict.THREAT_DETECTED
            threatName = "Trojan.AndroidOS.Banker.Heur"
            threatFamily = "BankingTrojan"
            severity = ThreatSeverity.CRITICAL
            confidence = 85
            matchedRules.add("HEUR:BANKING_TROJAN_PROFILE (Accessibility + Overlay/SMS intercept)")
            reason = "Application requests Accessibility Service (BIND_ACCESSIBILITY_SERVICE) combined with SYSTEM_ALERT_WINDOW or SMS access. This behavior is strongly characteristic of overlay banking trojans and credential harvesting."
        } else if (hasOverlay && hasInstallPackages && !isSystem) {
            verdict = ScanVerdict.SUSPICIOUS
            threatName = "Dropper.AndroidOS.Generic"
            threatFamily = "Dropper"
            severity = ThreatSeverity.HIGH
            confidence = 70
            matchedRules.add("HEUR:DROPPER_PROFILE (Overlay + RequestInstallPackages)")
            reason = "Application requests permission to overlay system windows and trigger APK installations, matching known dropper/loader staging patterns."
        } else if (hasDeviceAdmin && hasSms && !isSystem) {
            verdict = ScanVerdict.SUSPICIOUS
            threatName = "Spyware.AndroidOS.SmsStealer"
            threatFamily = "Spyware"
            severity = ThreatSeverity.HIGH
            confidence = 75
            matchedRules.add("HEUR:SMS_STEALER_PROFILE (DeviceAdmin + SMS Access)")
            reason = "Application requests Device Administrator privileges alongside SMS interception capabilities, characteristic of persistent SMS spyware."
        } else if (suspiciousPerms.size >= 5 && !isSystem) {
            verdict = ScanVerdict.SUSPICIOUS
            threatName = "Heuristic.HighRiskPermissions"
            threatFamily = "PrivilegeAbuse"
            severity = ThreatSeverity.MEDIUM
            confidence = 45
            matchedRules.add("HEUR:EXCESSIVE_DANGEROUS_PERMISSIONS (${suspiciousPerms.size} high-risk)")
            reason = "Application requests ${suspiciousPerms.size} high-risk permissions without matching a specific known malware family. User review recommended before granting runtime privileges."
        }

        val result = InstalledAppThreat(
            packageName = pkg.packageName,
            appName = appName,
            versionName = vName,
            versionCode = vCode,
            apkPath = apkPath,
            apkSize = apkSize,
            isSystemApp = isSystem,
            sha256 = sha256,
            md5 = md5,
            verdict = verdict,
            threatName = threatName,
            threatFamily = threatFamily,
            severity = severity,
            matchedRules = matchedRules,
            suspiciousPermissions = suspiciousPerms,
            confidenceScore = confidence,
            explainableReason = reason
        )

        if (verdict != ScanVerdict.CLEAN) {
            recordThreatInHistory(result)
        }

        return result
    }

    private fun calculateApkHashes(apkFile: File): Pair<String, String> {
        val sha256Digest = MessageDigest.getInstance("SHA-256")
        val md5Digest = MessageDigest.getInstance("MD5")
        val buffer = ByteArray(65536)

        FileInputStream(apkFile).use { input ->
            var bytesRead: Int
            while (input.read(buffer).also { bytesRead = it } != -1) {
                sha256Digest.update(buffer, 0, bytesRead)
                md5Digest.update(buffer, 0, bytesRead)
            }
        }

        val sha256 = sha256Digest.digest().joinToString("") { "%02x".format(it) }
        val md5 = md5Digest.digest().joinToString("") { "%02x".format(it) }
        return Pair(sha256, md5)
    }

    private fun recordThreatInHistory(threat: InstalledAppThreat) {
        historyDb?.recordScan(
            ScanResult(
                scanId = "APP-" + UUID.randomUUID().toString().substring(0, 8).uppercase(),
                fileName = "${threat.appName} (${threat.packageName})",
                filePath = threat.apkPath,
                fileSize = threat.apkSize,
                sha256 = threat.sha256,
                md5 = threat.md5,
                entropy = 0.0,
                verdict = threat.verdict,
                threatName = threat.threatName,
                threatFamily = threat.threatFamily,
                severity = threat.severity,
                matchedRules = threat.matchedRules
            )
        )
    }
}
