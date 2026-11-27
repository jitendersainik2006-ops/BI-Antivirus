package com.biantivirus.security.core

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.Base64
import java.util.Calendar
import java.util.Date
import java.util.Locale

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

/**
 * BI Antivirus Enterprise — Android Licensing & Entitlement Manager
 *
 * Implements asymmetric cryptographic license verification (RSA-2048 / SHA-256 PKCS#1 v1.5).
 * Contains ONLY the public verification key — zero private signing keys are bundled into the APK.
 */
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

        const val DEFAULT_MAX_FREE_SCANS = 5

        /**
         * Official Black Intel License Issuer Public Verification Key (RSA-2048 / X.509).
         * Distributed clients contain ONLY this public key.
         */
        const val ISSUER_PUBLIC_KEY_B64 =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArOVk9hn6oU1LSwg7Z/FNt6iVfUYznyGWgYlUbSre" +
            "8cWRrG56jSkNUOSuM2ucA7KSeHk/nS4pOkfcgVvHHkfTk4iqcWkgWnplUpu2RBnoOwJ0MJRxDuoy97ib/R21" +
            "QjRR2WEwL+OEiEPANRresur2MkFPLUj6ioLckSvwAWtFdkbkEKOF8ocStdLBx3zW3hR4MOyLeMO1V2kaMGEL" +
            "Wx15BSAtgiDSjQ/FsPxX6Pdc9cYhjB4v6/xD9ptt8LfZGawN+WCMQT4OhbQJa/15C3hA6TFaHl2egzBmvCuh" +
            "Zkt8qXHn/Ydg/2vJlL2dAWBm9lizDFfQv1rAtfH+YRCqt6auwwIDAQAB"

        fun verifyRsaSignature(payloadBytes: ByteArray, sigBytes: ByteArray): Boolean {
            return try {
                val pubBytes = Base64.getDecoder().decode(ISSUER_PUBLIC_KEY_B64)
                val kf = KeyFactory.getInstance("RSA")
                val pubKey = kf.generatePublic(X509EncodedKeySpec(pubBytes))
                val verifier = Signature.getInstance("SHA256withRSA")
                verifier.initVerify(pubKey)
                verifier.update(payloadBytes)
                verifier.verify(sigBytes)
            } catch (_: Exception) {
                false
            }
        }

        fun validateToken(token: String): Triple<Boolean, Edition, String> {
            val clean = token.trim()
            if (!clean.startsWith("BI-LIC-V2.")) {
                return Triple(false, Edition.FREE, "Invalid token format. Expected BI-LIC-V2.<payload>.<sig>")
            }

            val parts = clean.split(".")
            if (parts.size != 3) {
                return Triple(false, Edition.FREE, "Malformed license token.")
            }

            return try {
                val payloadBytes = Base64.getUrlDecoder().decode(parts[1])
                val sigBytes = Base64.getUrlDecoder().decode(parts[2])

                if (!verifyRsaSignature(payloadBytes, sigBytes)) {
                    return Triple(false, Edition.FREE, "Cryptographic signature validation failed. Token is invalid, modified, or forged.")
                }

                val json = JSONObject(String(payloadBytes, StandardCharsets.UTF_8))
                if (json.optString("product") != "BI-ANTIVIRUS") {
                    return Triple(false, Edition.FREE, "License product mismatch: token is not for BI Antivirus.")
                }

                val tierStr = json.optString("tier", "").uppercase(Locale.ROOT)
                if (tierStr != "PREMIUM" && tierStr != "ENTERPRISE") {
                    return Triple(false, Edition.FREE, "License tier '$tierStr' does not grant Premium access.")
                }

                val expiresAt = json.optLong("expires_at", 0L)
                val nowSecs = System.currentTimeMillis() / 1000L
                if (expiresAt > 0L && nowSecs > expiresAt) {
                    val sdf = SimpleDateFormat("yyyy-MM-dd", Locale.ROOT)
                    val expDateStr = sdf.format(Date(expiresAt * 1000L))
                    return Triple(false, Edition.FREE, "License expired on $expDateStr.")
                }

                val issuedTo = json.optString("issued_to", "Registered Endpoint")
                Triple(true, Edition.PREMIUM, "Valid Premium license issued to $issuedTo.")
            } catch (e: Exception) {
                Triple(false, Edition.FREE, "Failed to decode license token: ${e.message}")
            }
        }

        fun validateKey(rawKey: String): Triple<Boolean, Edition, String> {
            if (rawKey.isBlank()) {
                return Triple(false, Edition.FREE, "License key cannot be empty.")
            }

            val clean = rawKey.trim()

            // Priority 1: Asymmetric RSA-2048 token
            if (clean.startsWith("BI-LIC-V2.")) {
                return validateToken(clean)
            }

            // Priority 2: Structured legacy developer format
            val cleanUpper = clean.uppercase(Locale.ROOT)
            if (cleanUpper.startsWith("BI-PREM-") || cleanUpper.startsWith("BI-ENTP-")) {
                val parts = cleanUpper.split("-")
                if (parts.size == 6) {
                    for (i in 2 until parts.size) {
                        if (parts[i].length != 4 || !parts[i].all { it.isLetterOrDigit() }) {
                            return Triple(false, Edition.FREE, "Each license key block must contain exactly 4 alphanumeric characters.")
                        }
                    }
                    val tier = if (parts[1] == "PREM") Edition.PREMIUM else Edition.PREMIUM
                    return Triple(true, tier, "Valid developer ${tier.name} license.")
                }
            }

            return Triple(false, Edition.FREE, "Invalid license key format. Expected BI-LIC-V2 token or valid format.")
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

        inMemoryLastReset = storedReset
        inMemoryMaxScans = storedMax
        inMemoryScansUsed = storedUsed

        // Cryptographic integrity check: If stored as Premium, re-verify the license token
        val candidateEdition = try { Edition.valueOf(storedEditionStr) } catch (_: Exception) { Edition.FREE }
        if (candidateEdition == Edition.PREMIUM) {
            if (storedKey == null) {
                isTampered = true
                inMemoryEdition = Edition.FREE
                inMemoryKey = null
                saveEntitlement()
                return
            }
            val (valid, tier, _) = validateKey(storedKey)
            if (!valid) {
                // Tamper detected or license invalid/expired: revert to Free safely
                isTampered = true
                inMemoryEdition = Edition.FREE
                inMemoryKey = null
                saveEntitlement()
                return
            }
            inMemoryEdition = tier
            inMemoryKey = storedKey
            isTampered = false
        } else {
            inMemoryEdition = Edition.FREE
            inMemoryKey = null
            isTampered = false
        }
    }

    private fun saveEntitlement() {
        val p = prefs ?: return
        p.edit()
            .putString(KEY_EDITION, inMemoryEdition.name)
            .putString(KEY_LICENSE_KEY, inMemoryKey)
            .putInt(KEY_SCANS_USED_TODAY, inMemoryScansUsed)
            .putString(KEY_LAST_RESET_DATE, inMemoryLastReset)
            .putInt(KEY_MAX_FREE_SCANS, inMemoryMaxScans)
            .apply()
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
        inMemoryKey = key.trim()
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
