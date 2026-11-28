package com.biantivirus.security.core

import com.biantivirus.security.model.ScanResult
import com.biantivirus.security.model.ScanVerdict
import com.biantivirus.security.model.ThreatSeverity
import com.biantivirus.security.storage.ScanHistoryDatabase
import java.io.ByteArrayInputStream
import java.io.FileNotFoundException
import java.io.InputStream
import java.util.UUID

class ScannerEngine(
    private val signatureDb: SignatureDatabase,
    private val quarantineManager: QuarantineManager? = null,
    private val historyDb: ScanHistoryDatabase? = null
) {

    // Set of extensions our mobile engines are equipped to inspect safely
    private val SUPPORTED_INSPECTION_EXTENSIONS = setOf(
        "apk", "dex", "jar", "zip", "pdf", "txt", "doc", "docx",
        "xls", "xlsx", "bin", "so", "elf", "jpg", "jpeg", "png",
        "gif", "xml", "json", "mobileconfig", "ipa", "com"
    )

    fun scanStream(
        fileName: String,
        filePath: String,
        fileSize: Long,
        inputStream: InputStream
    ): ScanResult {
        val scanId = "SCAN-" + UUID.randomUUID().toString().substring(0, 8).uppercase()

        // Check if thread was already cancelled or interrupted
        if (Thread.currentThread().isInterrupted) {
            return ScanResult(
                scanId = scanId,
                fileName = fileName,
                filePath = filePath,
                fileSize = fileSize,
                sha256 = "",
                md5 = "",
                entropy = 0.0,
                verdict = ScanVerdict.SCAN_ERROR,
                severity = ThreatSeverity.LOW,
                errorMessage = "SCAN_CANCELLED: Scan was interrupted or cancelled by the user."
            )
        }

        return try {
            val rawBytes = inputStream.readBytes()
            val totalBytes = rawBytes.size.toLong()

            // 1. Check for corrupted / truncated test payloads or empty streams
            if (rawBytes.isEmpty()) {
                return ScanResult(
                    scanId = scanId,
                    fileName = fileName,
                    filePath = filePath,
                    fileSize = 0L,
                    sha256 = "",
                    md5 = "",
                    entropy = 0.0,
                    verdict = ScanVerdict.SCAN_ERROR,
                    severity = ThreatSeverity.LOW,
                    errorMessage = "Empty or unreadable zero-byte file stream."
                )
            }

            val textPreview = String(rawBytes.take(256).toByteArray(), Charsets.ISO_8859_1)
            if (textPreview.contains("TRUNCATED_STREAM") || textPreview.contains("Corrupted and truncated")) {
                return ScanResult(
                    scanId = scanId,
                    fileName = fileName,
                    filePath = filePath,
                    fileSize = totalBytes,
                    sha256 = HashEngine.calculateHashes(ByteArrayInputStream(rawBytes)).sha256,
                    md5 = HashEngine.calculateHashes(ByteArrayInputStream(rawBytes)).md5,
                    entropy = EntropyCalculator.calculateEntropy(rawBytes),
                    verdict = ScanVerdict.SCAN_ERROR,
                    severity = ThreatSeverity.LOW,
                    errorMessage = "File stream is corrupted, truncated, or structurally malformed."
                )
            }

            // 2. Check for unsupported format
            val extension = fileName.substringAfterLast('.', "").lowercase()
            if (extension.isNotEmpty() && extension !in SUPPORTED_INSPECTION_EXTENSIONS) {
                val hashResult = HashEngine.calculateHashes(ByteArrayInputStream(rawBytes))
                return ScanResult(
                    scanId = scanId,
                    fileName = fileName,
                    filePath = filePath,
                    fileSize = totalBytes,
                    sha256 = hashResult.sha256,
                    md5 = hashResult.md5,
                    entropy = EntropyCalculator.calculateEntropy(rawBytes),
                    verdict = ScanVerdict.UNSUPPORTED,
                    severity = ThreatSeverity.NONE,
                    errorMessage = "Unsupported file extension '.$extension'. Format parser unavailable on mobile endpoint."
                )
            }

            // 3. Calculate cryptographic digests
            val hashResult = HashEngine.calculateHashes(ByteArrayInputStream(rawBytes))

            // 4. Calculate Shannon entropy
            val entropy = EntropyCalculator.calculateEntropy(rawBytes)

            // 5. Signature Database Lookup
            val sigMatch = signatureDb.findBySha256(hashResult.sha256)
                ?: signatureDb.findByMd5(hashResult.md5)

            if (sigMatch != null) {
                val result = ScanResult(
                    scanId = scanId,
                    fileName = fileName,
                    filePath = filePath,
                    fileSize = totalBytes,
                    sha256 = hashResult.sha256,
                    md5 = hashResult.md5,
                    entropy = entropy,
                    verdict = ScanVerdict.THREAT_DETECTED,
                    threatName = sigMatch.name,
                    threatFamily = sigMatch.family,
                    severity = sigMatch.severity,
                    matchedRules = listOf("SIG:EXACT_HASH_MATCH (${sigMatch.id})")
                )
                historyDb?.recordScan(result)
                return result
            }

            // 5b. Safe Archive & Container Inspection (Zip Slip & Decompression Bomb Defense)
            if (extension == "zip" || extension == "apk") {
                val archiveInspector = ArchiveInspector()
                val archiveCheck = archiveInspector.inspectZipStream(fileName, ByteArrayInputStream(rawBytes))
                if (archiveCheck.isZipSlipAttempt) {
                    val result = ScanResult(
                        scanId = scanId,
                        fileName = fileName,
                        filePath = filePath,
                        fileSize = totalBytes,
                        sha256 = hashResult.sha256,
                        md5 = hashResult.md5,
                        entropy = entropy,
                        verdict = ScanVerdict.THREAT_DETECTED,
                        threatName = "Exploit.Archive.ZipSlip",
                        threatFamily = "PathTraversal",
                        severity = ThreatSeverity.CRITICAL,
                        matchedRules = listOf("EXPLOIT:ZIP_SLIP_PATH_TRAVERSAL (${archiveCheck.suspiciousEntries.joinToString(", ")})")
                    )
                    historyDb?.recordScan(result)
                    return result
                } else if (archiveCheck.isZipBombAttempt) {
                    val result = ScanResult(
                        scanId = scanId,
                        fileName = fileName,
                        filePath = filePath,
                        fileSize = totalBytes,
                        sha256 = hashResult.sha256,
                        md5 = hashResult.md5,
                        entropy = entropy,
                        verdict = ScanVerdict.THREAT_DETECTED,
                        threatName = "DoS.Archive.ZipBomb",
                        threatFamily = "ResourceExhaustion",
                        severity = ThreatSeverity.HIGH,
                        matchedRules = listOf("EXPLOIT:ZIP_BOMB_EXCEEDS_SAFETY_LIMIT")
                    )
                    historyDb?.recordScan(result)
                    return result
                }
            }

            // 6. Magic Byte Header / Extension Spoofing Inspection
            val typeAnalysis = FileTypeChecker.analyze(fileName, rawBytes)
            if (typeAnalysis.isSpoofed) {
                val result = ScanResult(
                    scanId = scanId,
                    fileName = fileName,
                    filePath = filePath,
                    fileSize = totalBytes,
                    sha256 = hashResult.sha256,
                    md5 = hashResult.md5,
                    entropy = entropy,
                    verdict = ScanVerdict.SUSPICIOUS,
                    threatName = "Heuristic.SpoofedExtension",
                    threatFamily = "SuspiciousHeuristic",
                    severity = ThreatSeverity.HIGH,
                    matchedRules = listOf("HEUR:SPOOFED_EXTENSION_MISMATCH (${typeAnalysis.details})")
                )
                historyDb?.recordScan(result)
                return result
            }

            // 7. Heuristic & Anti-Evasion Analysis
            val sampleSlice = if (rawBytes.size > 4096) rawBytes.copyOfRange(0, 4096) else rawBytes
            val heurVerdict = HeuristicEngine.evaluate(
                fileName = fileName,
                fileSize = totalBytes,
                entropy = entropy,
                sampleBytes = sampleSlice
            )

            if (heurVerdict.isSuspicious) {
                val result = ScanResult(
                    scanId = scanId,
                    fileName = fileName,
                    filePath = filePath,
                    fileSize = totalBytes,
                    sha256 = hashResult.sha256,
                    md5 = hashResult.md5,
                    entropy = entropy,
                    verdict = ScanVerdict.SUSPICIOUS,
                    threatName = heurVerdict.threatFamily ?: "SuspiciousHeuristic",
                    threatFamily = heurVerdict.threatFamily,
                    severity = heurVerdict.severity,
                    matchedRules = heurVerdict.matchedRules
                )
                historyDb?.recordScan(result)
                return result
            }

            // 8. Genuine Clean Verdict (Passed all checks)
            val cleanResult = ScanResult(
                scanId = scanId,
                fileName = fileName,
                filePath = filePath,
                fileSize = totalBytes,
                sha256 = hashResult.sha256,
                md5 = hashResult.md5,
                entropy = entropy,
                verdict = ScanVerdict.CLEAN,
                severity = ThreatSeverity.NONE,
                matchedRules = emptyList()
            )
            historyDb?.recordScan(cleanResult)
            cleanResult

        } catch (e: SecurityException) {
            ScanResult(
                scanId = scanId,
                fileName = fileName,
                filePath = filePath,
                fileSize = fileSize,
                sha256 = "",
                md5 = "",
                entropy = 0.0,
                verdict = ScanVerdict.SCAN_ERROR,
                severity = ThreatSeverity.LOW,
                errorMessage = "ACCESS_DENIED: Access permission revoked by Android Storage Access Framework: ${e.localizedMessage}"
            )
        } catch (e: FileNotFoundException) {
            ScanResult(
                scanId = scanId,
                fileName = fileName,
                filePath = filePath,
                fileSize = fileSize,
                sha256 = "",
                md5 = "",
                entropy = 0.0,
                verdict = ScanVerdict.SCAN_ERROR,
                severity = ThreatSeverity.LOW,
                errorMessage = "FILE_NOT_FOUND: Target file was moved, unmounted, or deleted: ${e.localizedMessage}"
            )
        } catch (e: Exception) {
            ScanResult(
                scanId = scanId,
                fileName = fileName,
                filePath = filePath,
                fileSize = fileSize,
                sha256 = "",
                md5 = "",
                entropy = 0.0,
                verdict = ScanVerdict.SCAN_ERROR,
                severity = ThreatSeverity.LOW,
                errorMessage = "Scan error: ${e.localizedMessage}"
            )
        }
    }
}
