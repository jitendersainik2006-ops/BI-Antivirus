package com.biantivirus.security.core

import java.net.URI
import java.util.Locale

enum class WebVerdict {
    SAFE,
    SUSPICIOUS,
    PHISHING,
    MALICIOUS
}

data class WebReputationResult(
    val url: String,
    val domain: String,
    val verdict: WebVerdict,
    val riskScore: Int,
    val reasons: List<String>
)

/**
 * On-Device Privacy-Preserving Web & URL Security Auditor.
 * Evaluates suspicious domains, homograph patterns, and phishing heuristics without outbound telemetry.
 */
class WebReputationAuditor {

    private val suspiciousTlds = setOf(
        "top", "xyz", "buzz", "click", "rest", "cam", "fit", "work", "tk", "ml", "ga", "cf", "gq"
    )

    private val phishingKeywords = setOf(
        "login-verify", "account-update", "secure-banking", "recover-wallet",
        "confirm-identity", "password-reset-alert", "auth-token-claim", "signin-service"
    )

    fun auditUrl(urlString: String): WebReputationResult {
        val cleanUrl = urlString.trim()
        val reasons = mutableListOf<String>()
        var score = 0

        val domain: String = try {
            val uri = if (!cleanUrl.startsWith("http://") && !cleanUrl.startsWith("https://")) {
                URI("https://$cleanUrl")
            } else {
                URI(cleanUrl)
            }
            uri.host?.lowercase(Locale.ROOT) ?: cleanUrl
        } catch (e: Exception) {
            cleanUrl.lowercase(Locale.ROOT)
        }

        // 1. IP Address Host Check (Common in malicious C2 / phishing)
        val ipPattern = Regex("""^(\d{1,3}\.){3}\d{1,3}$""")
        if (ipPattern.matches(domain)) {
            score += 35
            reasons.add("Raw IP address used instead of verified domain name")
        }

        // 2. Suspicious TLD check
        val parts = domain.split(".")
        if (parts.size >= 2) {
            val tld = parts.last()
            if (suspiciousTlds.contains(tld)) {
                score += 25
                reasons.add("Domain uses high-abuse top-level domain (.$tld)")
            }
        }

        // 3. Excessive Subdomains (Domain shadowing / Fast-flux indicator)
        if (parts.size > 4) {
            score += 20
            reasons.add("Excessive subdomain depth (${parts.size} levels)")
        }

        // 4. Phishing Keywords in Hostname or Path
        for (kw in phishingKeywords) {
            if (cleanUrl.lowercase(Locale.ROOT).contains(kw)) {
                score += 40
                reasons.add("Contains known phishing credential-harvesting token: '$kw'")
            }
        }

        // 5. Homoglyph / Punycode International Domain Name check (xn--)
        if (domain.startsWith("xn--") || domain.contains(".xn--")) {
            score += 35
            reasons.add("Punycode encoded domain (potential homograph impersonation attack)")
        }

        val verdict = when {
            score >= 60 -> WebVerdict.PHISHING
            score >= 35 -> WebVerdict.SUSPICIOUS
            else -> WebVerdict.SAFE
        }

        return WebReputationResult(
            url = cleanUrl,
            domain = domain,
            verdict = verdict,
            riskScore = score.coerceIn(0, 100),
            reasons = reasons
        )
    }
}
