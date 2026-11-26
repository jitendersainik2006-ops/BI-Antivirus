package com.biantivirus.security.core

import com.biantivirus.security.model.ThreatSeverity

data class HeuristicVerdict(
    val isSuspicious: Boolean,
    val matchedRules: List<String>,
    val threatFamily: String? = null,
    val severity: ThreatSeverity = ThreatSeverity.NONE
)

object HeuristicEngine {

    const val DEFAULT_ENTROPY_THRESHOLD = 7.2

    private val SUSPICIOUS_DOUBLE_EXTENSIONS = listOf(
        ".pdf.apk", ".jpg.apk", ".png.apk", ".doc.apk", ".docx.apk",
        ".pdf.dex", ".xlsx.apk", ".mp4.apk", ".txt.apk", ".pdf.ipa"
    )

    private val SUSPICIOUS_STRINGS = listOf(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*",
        "su -c ",
        "/system/xbin/su",
        "/system/bin/su"
    )

    fun evaluate(
        fileName: String,
        fileSize: Long,
        entropy: Double,
        sampleBytes: ByteArray? = null
    ): HeuristicVerdict {
        val matchedRules = mutableListOf<String>()

        // 1. Double extension anomaly check
        val lowerName = fileName.lowercase()
        for (doubleExt in SUSPICIOUS_DOUBLE_EXTENSIONS) {
            if (lowerName.endsWith(doubleExt)) {
                matchedRules.add("HEUR:SUSPICIOUS_DOUBLE_EXTENSION ($doubleExt)")
                break
            }
        }

        // 2. High Shannon entropy threshold check
        if (entropy >= DEFAULT_ENTROPY_THRESHOLD && fileSize > 1024) {
            matchedRules.add("HEUR:HIGH_SHANNON_ENTROPY (${entropy} >= ${DEFAULT_ENTROPY_THRESHOLD})")
        }

        // 3. Known suspicious string inspection
        if (sampleBytes != null && sampleBytes.isNotEmpty()) {
            val sampleText = String(sampleBytes, Charsets.ISO_8859_1)
            for (suspicious in SUSPICIOUS_STRINGS) {
                if (sampleText.contains(suspicious)) {
                    if (suspicious.startsWith("X5O!P%@AP")) {
                        matchedRules.add("HEUR:EICAR_PATTERN_DETECTED")
                    } else {
                        matchedRules.add("HEUR:SUSPICIOUS_ROOT_EXEC_STRING ($suspicious)")
                    }
                }
            }
        }

        if (matchedRules.isEmpty()) {
            return HeuristicVerdict(
                isSuspicious = false,
                matchedRules = emptyList()
            )
        }

        val isEicar = matchedRules.any { it.contains("EICAR") }
        val severity = when {
            isEicar -> ThreatSeverity.CRITICAL
            matchedRules.size >= 2 -> ThreatSeverity.HIGH
            else -> ThreatSeverity.MEDIUM
        }

        val family = when {
            isEicar -> "TestVirus"
            lowerName.endsWith(".apk") -> "Android.Heuristic.Dropper"
            else -> "SuspiciousHeuristic"
        }

        return HeuristicVerdict(
            isSuspicious = true,
            matchedRules = matchedRules,
            threatFamily = family,
            severity = severity
        )
    }
}
