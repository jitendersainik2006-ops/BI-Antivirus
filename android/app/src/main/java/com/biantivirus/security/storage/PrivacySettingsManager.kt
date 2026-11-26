package com.biantivirus.security.storage

import android.content.Context
import android.content.SharedPreferences

data class SecurityRecommendation(
    val id: String,
    val title: String,
    val description: String,
    val severity: String,
    val actionText: String
)

class PrivacySettingsManager(context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences("bi_privacy_settings", Context.MODE_PRIVATE)

    companion object {
        private const val KEY_TELEMETRY_ENABLED = "pref_telemetry_enabled"
        private const val KEY_CLOUD_REPUTATION_LOOKUP = "pref_cloud_reputation_lookup"
        private const val KEY_HISTORY_RETENTION_DAYS = "pref_history_retention_days"
        private const val KEY_AUTO_QUARANTINE_CRITICAL = "pref_auto_quarantine_critical"
    }

    // By default, strict privacy: NO telemetry, NO cloud lookup, 100% on-device
    var isTelemetryEnabled: Boolean
        get() = prefs.getBoolean(KEY_TELEMETRY_ENABLED, false)
        set(value) = prefs.edit().putBoolean(KEY_TELEMETRY_ENABLED, value).apply()

    var isCloudLookupEnabled: Boolean
        get() = prefs.getBoolean(KEY_CLOUD_REPUTATION_LOOKUP, false)
        set(value) = prefs.edit().putBoolean(KEY_CLOUD_REPUTATION_LOOKUP, value).apply()

    var historyRetentionDays: Int
        get() = prefs.getInt(KEY_HISTORY_RETENTION_DAYS, 90)
        set(value) = prefs.edit().putInt(KEY_HISTORY_RETENTION_DAYS, value).apply()

    var isAutoQuarantineCritical: Boolean
        get() = prefs.getBoolean(KEY_AUTO_QUARANTINE_CRITICAL, false)
        set(value) = prefs.edit().putBoolean(KEY_AUTO_QUARANTINE_CRITICAL, value).apply()

    fun generateRecommendations(
        hasLockScreen: Boolean,
        isEncrypted: Boolean,
        isUsbDebuggingEnabled: Boolean,
        isRooted: Boolean
    ): List<SecurityRecommendation> {
        val recs = mutableListOf<SecurityRecommendation>()

        if (!hasLockScreen) {
            recs.add(
                SecurityRecommendation(
                    id = "REC-LOCK-001",
                    title = "Enable Device Screen Lock",
                    description = "No PIN, password, or biometric lock is configured. Anyone with physical access can view your data.",
                    severity = "CRITICAL",
                    actionText = "Open Security Settings"
                )
            )
        }

        if (!isEncrypted) {
            recs.add(
                SecurityRecommendation(
                    id = "REC-ENC-002",
                    title = "Enable Device Storage Encryption",
                    description = "Device hardware encryption is not active. Enable encryption to protect confidential files at rest.",
                    severity = "HIGH",
                    actionText = "Configure Encryption"
                )
            )
        }

        if (isUsbDebuggingEnabled) {
            recs.add(
                SecurityRecommendation(
                    id = "REC-ADB-003",
                    title = "Disable USB Debugging (ADB)",
                    description = "USB debugging allows unauthorized computer connections to execute shell commands and extract application data.",
                    severity = "HIGH",
                    actionText = "Developer Options"
                )
            )
        }

        if (isRooted) {
            recs.add(
                SecurityRecommendation(
                    id = "REC-ROOT-004",
                    title = "Device Integrity Compromised (Rooted)",
                    description = "Su binary or root management framework detected. Android sandbox protections may be bypassed.",
                    severity = "CRITICAL",
                    actionText = "Review Device Root Status"
                )
            )
        }

        return recs
    }
}
