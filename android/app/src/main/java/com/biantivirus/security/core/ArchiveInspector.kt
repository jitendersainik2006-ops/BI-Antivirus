package com.biantivirus.security.core

import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

data class ArchiveInspectionResult(
    val fileName: String,
    val totalEntries: Int,
    val isZipSlipAttempt: Boolean,
    val isZipBombAttempt: Boolean,
    val suspiciousEntries: List<String>,
    val containsExecutables: Boolean,
    val containsLooseApk: Boolean,
    val isSafe: Boolean,
    val details: String
)

data class LooseApkInspectionResult(
    val fileName: String,
    val packageName: String?,
    val versionName: String?,
    val versionCode: Long,
    val sha256: String,
    val isCorrupted: Boolean,
    val requestedPermissions: List<String>,
    val isSuspicious: Boolean,
    val riskReason: String?
)

class ArchiveInspector {

    companion object {
        private const val MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024L // 50MB safety limit on mobile
        private const val MAX_COMPRESSION_RATIO = 100.0 // Zip bomb ratio threshold

        private val EXECUTABLE_EXTENSIONS = setOf(
            "dex", "apk", "exe", "dll", "so", "elf", "bat", "cmd", "sh", "vbs", "js", "ps1"
        )
    }

    fun inspectZipStream(
        fileName: String,
        inputStream: InputStream,
        targetDir: File? = null
    ): ArchiveInspectionResult {
        var totalEntries = 0
        var totalUncompressedSize = 0L
        var totalCompressedSize = 0L
        var isZipSlip = false
        var isZipBomb = false
        var hasExecutables = false
        var hasLooseApk = false
        val suspiciousEntries = mutableListOf<String>()

        val canonicalTarget = targetDir?.canonicalFile

        try {
            ZipInputStream(inputStream).use { zis ->
                var entry: ZipEntry? = zis.nextEntry
                while (entry != null) {
                    totalEntries++
                    val entryName = entry.name

                    // 1. Strict Zip Slip Protection (Anti-Path Traversal)
                    if (entryName.contains("..") || entryName.startsWith("/") || entryName.startsWith("\\")) {
                        isZipSlip = true
                        suspiciousEntries.add("PATH_TRAVERSAL: $entryName")
                        break
                    }

                    if (canonicalTarget != null) {
                        val destinationFile = File(canonicalTarget, entryName)
                        val canonicalDest = destinationFile.canonicalPath
                        if (!canonicalDest.startsWith(canonicalTarget.path + File.separator) &&
                            canonicalDest != canonicalTarget.path
                        ) {
                            isZipSlip = true
                            suspiciousEntries.add("PATH_ESCAPING: $entryName")
                            break
                        }
                    }

                    // 2. Executable & APK detection
                    val ext = entryName.substringAfterLast('.', "").lowercase()
                    if (ext in EXECUTABLE_EXTENSIONS) {
                        hasExecutables = true
                        suspiciousEntries.add("EXECUTABLE_ENTRY: $entryName")
                    }
                    if (ext == "apk") {
                        hasLooseApk = true
                    }

                    // 3. Zip Bomb Detection (Streaming Byte Count & Compression Ratio)
                    val buffer = ByteArray(4096)
                    var bytesRead: Int
                    var entryBytes = 0L

                    while (zis.read(buffer).also { bytesRead = it } != -1) {
                        entryBytes += bytesRead
                        totalUncompressedSize += bytesRead

                        if (totalUncompressedSize > MAX_UNCOMPRESSED_BYTES) {
                            isZipBomb = true
                            suspiciousEntries.add("ZIP_BOMB_EXCEEDS_SIZE_LIMIT (${totalUncompressedSize / (1024 * 1024)}MB)")
                            break
                        }
                    }

                    val compressedEntrySize = entry.compressedSize
                    if (compressedEntrySize > 0) {
                        totalCompressedSize += compressedEntrySize
                        val ratio = entryBytes.toDouble() / compressedEntrySize.toDouble()
                        if (ratio > MAX_COMPRESSION_RATIO && entryBytes > 10 * 1024 * 1024) {
                            isZipBomb = true
                            suspiciousEntries.add("ZIP_BOMB_ANOMALOUS_RATIO (${ratio.toInt()}:1)")
                            break
                        }
                    }

                    zis.closeEntry()
                    if (isZipBomb) break
                    entry = zis.nextEntry
                }
            }
        } catch (e: Exception) {
            // Malformed ZIP structure
            return ArchiveInspectionResult(
                fileName = fileName,
                totalEntries = totalEntries,
                isZipSlipAttempt = isZipSlip,
                isZipBombAttempt = isZipBomb,
                suspiciousEntries = suspiciousEntries,
                containsExecutables = hasExecutables,
                containsLooseApk = hasLooseApk,
                isSafe = false,
                details = "Archive reading failed or corrupted: ${e.localizedMessage}"
            )
        }

        val isSafe = !isZipSlip && !isZipBomb && suspiciousEntries.isEmpty()
        val details = when {
            isZipSlip -> "CRITICAL THREAT: Archive contains malicious directory traversal sequences (Zip Slip attack blocked)."
            isZipBomb -> "CRITICAL THREAT: Archive exhibits decompression bomb characteristics designed to exhaust memory."
            hasExecutables -> "SUSPICIOUS: Archive contains executable binaries or scripts (${suspiciousEntries.joinToString(", ")})."
            else -> "Archive structure verified clean ($totalEntries entries inspected, 0 path traversals)."
        }

        return ArchiveInspectionResult(
            fileName = fileName,
            totalEntries = totalEntries,
            isZipSlipAttempt = isZipSlip,
            isZipBombAttempt = isZipBomb,
            suspiciousEntries = suspiciousEntries,
            containsExecutables = hasExecutables,
            containsLooseApk = hasLooseApk,
            isSafe = isSafe,
            details = details
        )
    }

    fun inspectLooseApk(apkFile: File, pm: PackageManager? = null): LooseApkInspectionResult {
        if (!apkFile.exists() || !apkFile.canRead()) {
            return LooseApkInspectionResult(
                fileName = apkFile.name,
                packageName = null,
                versionName = null,
                versionCode = 0L,
                sha256 = "",
                isCorrupted = true,
                requestedPermissions = emptyList(),
                isSuspicious = true,
                riskReason = "File does not exist or cannot be read."
            )
        }

        // Compute SHA-256 hash
        val sha256 = try {
            val digest = MessageDigest.getInstance("SHA-256")
            FileInputStream(apkFile).use { fis ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (fis.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            ""
        }

        // Attempt package archive parsing
        val pkgInfo: PackageInfo? = try {
            pm?.getPackageArchiveInfo(apkFile.absolutePath, PackageManager.GET_PERMISSIONS)
        } catch (_: Exception) {
            null
        }

        if (pkgInfo == null) {
            return LooseApkInspectionResult(
                fileName = apkFile.name,
                packageName = null,
                versionName = null,
                versionCode = 0L,
                sha256 = sha256,
                isCorrupted = true,
                requestedPermissions = emptyList(),
                isSuspicious = true,
                riskReason = "Corrupted or non-standard APK package archive structure."
            )
        }

        val permissions = pkgInfo.requestedPermissions?.toList() ?: emptyList()
        val hasOverlay = "android.permission.SYSTEM_ALERT_WINDOW" in permissions
        val hasAccessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions
        val hasInstall = "android.permission.REQUEST_INSTALL_PACKAGES" in permissions

        var isSuspicious = false
        var reason: String? = null

        if (hasAccessibility && hasOverlay) {
            isSuspicious = true
            reason = "Loose APK requests dangerous combination of Accessibility Service and System Overlay."
        } else if (hasInstall && hasOverlay) {
            isSuspicious = true
            reason = "Loose APK requests App Dropper capabilities (Install Packages + Overlay)."
        }

        val vCode = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            pkgInfo.longVersionCode
        } else {
            @Suppress("DEPRECATION")
            pkgInfo.versionCode.toLong()
        }

        return LooseApkInspectionResult(
            fileName = apkFile.name,
            packageName = pkgInfo.packageName,
            versionName = pkgInfo.versionName,
            versionCode = vCode,
            sha256 = sha256,
            isCorrupted = false,
            requestedPermissions = permissions,
            isSuspicious = isSuspicious,
            riskReason = reason
        )
    }
}
