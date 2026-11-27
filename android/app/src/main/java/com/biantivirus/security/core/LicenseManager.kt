package com.biantivirus.security.core

import android.content.Context
import android.content.SharedPreferences
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

enum class Edition {
    FREE,
    PREMIUM
}

data class LicenseStatusSummary(
    val edition: Edition,
    val isPremium: Boolean,
    val licenseKey: String?,
    val scansUsedToday: Int,
    val maxFreeScansPerDay: Int,
    val remainingScans: Int, // -1 for unlimited
    val resetTimeRemainingText: String,
    val isTamperDetected: Boolean
)

class LicenseManager(context: Context? = null) {

    private val prefs: SharedPreferences? = context?.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    companion object {
        private const val PREFS_NAME = "bi_license_entitlement"
        private const val KEY_EDITION = "edition"
        private const val KEY_LICENSE_KEY = "license_key"
        private const val KEY_ACTIVATED_AT = "activated_at"
        private const val KEY_SCANS_USED_TODAY = "scans_used_today"
        private const val KEY_LAST_RESET_DATE = "last_reset_date"
        private const val KEY_MAX_FREE_SCANS = "max_free_scans_per_day"
        private const val KEY_HMAC = "_hmac"

        const val DEFAULT_MAX_FREE_SCANS = 5

        private val KEY_SALT = "BLACK_INTEL_717_LICENSE_VERIFICATION_SECRET_SALT_2026".toByteArray(StandardCharsets.UTF_8)
        private val ENTITLEMENT_SALT = "BLACK_INTEL_ENTITLEMENT_INTEGRITY_SALT_2026".toByteArray(StandardCharsets.UTF_8)

        fun computeKeyChecksum(payload: String): String {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(KEY_SALT, "HmacSHA256"))
            val hash = mac.doFinal(payload.toByteArray(StandardCharsets.UTF_8))
            val hex = hash.joinToString("") { "%02x".format(it) }
            return hex.substring(0, 4).uppercase(Locale.ROOT)
        }

        fun validateKey(rawKey: String): Triple<Boolean, Edition, String> {
            if (rawKey.isBlank()) {
                return Triple(false, Edition.FREE, "License key cannot be empty.")
            }

            val clean = rawKey.trim().uppercase(Locale.ROOT)
            val tier: Edition
            val bodyParts: List<String>

            if (clean.startsWith("BI-PREM-")) {
                tier = Edition.PREMIUM
                bodyParts = clean.removePrefix("BI-PREM-").split("-")
            } else if (clean.startsWith("BI-ENTP-")) {
                tier = Edition.PREMIUM
                bodyParts = clean.removePrefix("BI-ENTP-").split("-")
            } else {
                return Triple(false, Edition.FREE, "Invalid license key format. Expected format: BI-PREM-XXXX-XXXX-XXXX-XXXX")
            }

            if (bodyParts.size != 4) {
                return Triple(false, Edition.FREE, "Invalid license block count. Expected format: BI-PREM-XXXX-XXXX-XXXX-XXXX")
            }

            for (b in bodyParts) {
                if (b.length != 4 || !b.all { it.isLetterOrDigit() }) {
                    return Triple(false, Edition.FREE, "Each license key block must contain exactly 4 alphanumeric characters.")
                }
            }

            val basePayload = "BI-${if (clean.startsWith("BI-PREM-")) "PREM" else "ENTP"}-${bodyParts[0]}-${bodyParts[1]}-${bodyParts[2]}"
            val expectedChecksum = computeKeyChecksum(basePayload)

            if (bodyParts[3] != expectedChecksum) {
                return Triple(false, Edition.FREE, "Cryptographic license checksum validation failed. Key is invalid or mistyped.")
            }

            return Triple(true, tier, "Valid ${tier.name} license.")
        }
    }

    private var inMemoryEdition = Edition.FREE
    private var inMemoryKey: String? = null
    private var inMemoryScansUsed = 0
    private var inMemoryLastReset = getTodayString()
    private var inMemoryMaxScans = DEFAULT_MAX_FREE_SCANS
    private var isTampered = false

    init {
        loadEntitlement()
    }

    private fun getTodayString(): String {
        val sdf = SimpleDateFormat("yyyy-MM-dd", Locale.ROOT)
        return sdf.format(Date())
    }

    private fun loadEntitlement() {
        val p = prefs ?: return
        checkDailyReset()

        val storedEditionStr = p.getString(KEY_EDITION, Edition.FREE.name) ?: Edition.FREE.name
        val storedKey = p.getString(KEY_LICENSE_KEY, null)
        val storedUsed = p.getInt(KEY_SCANS_USED_TODAY, 0)
        val storedReset = p.getString(KEY_LAST_RESET_DATE, getTodayString()) ?: getTodayString()
        val storedMax = p.getInt(KEY_MAX_FREE_SCANS, DEFAULT_MAX_FREE_SCANS)
        val storedHmac = p.getString(KEY_HMAC, "") ?: ""

        val payload = "$storedEditionStr:$storedKey:$storedUsed:$storedReset:$storedMax"
        val expectedHmac = signPayload(payload)

        if (storedHmac.isNotEmpty() && storedHmac != expectedHmac) {
            // Tamper detected
            isTampered = true
            inMemoryEdition = Edition.FREE
            inMemoryKey = null
            saveEntitlement()
            return
        }

        isTampered = false
        inMemoryEdition = try { Edition.valueOf(storedEditionStr) } catch (_: Exception) { Edition.FREE }
        inMemoryKey = storedKey
        inMemoryScansUsed = storedUsed
        inMemoryLastReset = storedReset
        inMemoryMaxScans = storedMax

        if (inMemoryEdition == Edition.PREMIUM && storedKey != null) {
            val (valid, _, _) = validateKey(storedKey)
            if (!valid) {
                inMemoryEdition = Edition.FREE
                inMemoryKey = null
                saveEntitlement()
            }
        }
    }

    private fun saveEntitlement() {
        val p = prefs ?: return
        val payload = "${inMemoryEdition.name}:$inMemoryKey:$inMemoryScansUsed:$inMemoryLastReset:$inMemoryMaxScans"
        val hmac = signPayload(payload)

        p.edit()
            .putString(KEY_EDITION, inMemoryEdition.name)
            .putString(KEY_LICENSE_KEY, inMemoryKey)
            .putInt(KEY_SCANS_USED_TODAY, inMemoryScansUsed)
            .putString(KEY_LAST_RESET_DATE, inMemoryLastReset)
            .putInt(KEY_MAX_FREE_SCANS, inMemoryMaxScans)
            .putString(KEY_HMAC, hmac)
            .apply()
    }

    private fun signPayload(payload: String): String {
        return try {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(ENTITLEMENT_SALT, "HmacSHA256"))
            val hash = mac.doFinal(payload.toByteArray(StandardCharsets.UTF_8))
            hash.joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            ""
        }
    }

    private fun checkDailyReset() {
        val today = getTodayString()
        if (inMemoryLastReset != today) {
            inMemoryScansUsed = 0
            inMemoryLastReset = today
            saveEntitlement()
        }
    }

    fun getEdition(): Edition {
        checkDailyReset()
        return inMemoryEdition
    }

    fun isPremium(): Boolean {
        return getEdition() == Edition.PREMIUM
    }

    fun getRemainingScans(): Int {
        if (isPremium()) return -1
        checkDailyReset()
        return (inMemoryMaxScans - inMemoryScansUsed).coerceAtLeast(0)
    }

    fun getResetTimeRemaining(): String {
        val cal = Calendar.getInstance()
        val now = cal.timeInMillis
        cal.set(Calendar.HOUR_OF_DAY, 24)
        cal.set(Calendar.MINUTE, 0)
        cal.set(Calendar.SECOND, 0)
        val midnight = cal.timeInMillis
        val diffSecs = ((midnight - now) / 1000).coerceAtLeast(0)
        val hours = diffSecs / 3600
        val mins = (diffSecs % 3600) / 60
        return "${hours}h ${mins}m"
    }

    fun canPerformScan(isDeepScan: Boolean = false): Pair<Boolean, String> {
        checkDailyReset()

        if (isDeepScan && !isPremium()) {
            return Pair(
                false,
                "Deep Scan is an exclusive BI Antivirus Premium capability.\n" +
                "It inspects all system storage, loose APKs, archives, and applies advanced behavioral heuristics.\n\n" +
                "Activate Premium to unlock Deep Scan."
            )
        }

        if (isPremium()) {
            return Pair(true, "")
        }

        if (inMemoryScansUsed >= inMemoryMaxScans) {
            val resetTime = getResetTimeRemaining()
            return Pair(
                false,
                "Free edition daily scan allowance reached ($inMemoryScansUsed/$inMemoryMaxScans scans used today).\n" +
                "Your allowance resets in $resetTime at midnight.\n\n" +
                "Activate BI Antivirus Premium for unlimited scans."
            )
        }

        return Pair(true, "")
    }

    fun recordScanPerformed(isDeepScan: Boolean = false) {
        checkDailyReset()
        if (!isPremium()) {
            inMemoryScansUsed++
            saveEntitlement()
        }
    }

    fun activate(key: String): Pair<Boolean, String> {
        val (valid, tier, msg) = validateKey(key)
        if (!valid) {
            return Pair(false, msg)
        }

        inMemoryEdition = tier
        inMemoryKey = key.trim().uppercase(Locale.ROOT)
        isTampered = false
        saveEntitlement()

        return Pair(true, "BI Antivirus ${tier.name.lowercase().replaceFirstChar { it.uppercase() }} successfully activated! Unlimited defense unlocked.")
    }

    fun deactivate(): Pair<Boolean, String> {
        inMemoryEdition = Edition.FREE
        inMemoryKey = null
        saveEntitlement()
        return Pair(true, "Reverted to BI Antivirus Free edition.")
    }

    fun getStatusSummary(): LicenseStatusSummary {
        checkDailyReset()
        return LicenseStatusSummary(
            edition = getEdition(),
            isPremium = isPremium(),
            licenseKey = inMemoryKey,
            scansUsedToday = inMemoryScansUsed,
            maxFreeScansPerDay = inMemoryMaxScans,
            remainingScans = getRemainingScans(),
            resetTimeRemainingText = getResetTimeRemaining(),
            isTamperDetected = isTampered
        )
    }
}
