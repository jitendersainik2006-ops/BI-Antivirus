package com.biantivirus.security.model

enum class ScanVerdict {
    CLEAN,
    THREAT_DETECTED,
    SUSPICIOUS,
    UNSUPPORTED,
    SCAN_ERROR;

    val isThreat: Boolean
        get() = this == THREAT_DETECTED || this == SUSPICIOUS

    val isActionable: Boolean
        get() = this == THREAT_DETECTED || this == SUSPICIOUS || this == SCAN_ERROR
}

enum class ThreatSeverity {
    NONE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
