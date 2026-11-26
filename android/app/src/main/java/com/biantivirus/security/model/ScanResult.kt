package com.biantivirus.security.model

data class ScanResult(
    val scanId: String,
    val timestamp: Long = System.currentTimeMillis(),
    val fileName: String,
    val filePath: String,
    val fileSize: Long,
    val sha256: String,
    val md5: String,
    val entropy: Double,
    val verdict: ScanVerdict,
    val threatName: String? = null,
    val threatFamily: String? = null,
    val severity: ThreatSeverity = ThreatSeverity.NONE,
    val matchedRules: List<String> = emptyList(),
    val isQuarantined: Boolean = false,
    val errorMessage: String? = null
)
