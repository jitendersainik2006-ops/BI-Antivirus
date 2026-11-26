package com.biantivirus.security.model

data class ThreatSignature(
    val id: String,
    val name: String,
    val family: String,
    val severity: ThreatSeverity,
    val sha256: String,
    val md5: String,
    val description: String
)
