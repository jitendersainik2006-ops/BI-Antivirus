import Foundation

public enum WebVerdict: String, Codable {
    case safe = "SAFE"
    case suspicious = "SUSPICIOUS"
    case phishing = "PHISHING"
    case malicious = "MALICIOUS"
}

public struct WebReputationResult: Codable {
    public let url: String
    public let domain: String
    public let verdict: WebVerdict
    public let riskScore: Int
    public let reasons: [String]
}

/**
 * On-Device Privacy-Preserving Web & URL Security Auditor for iOS.
 * Evaluates malicious links, homoglyph punycode attacks, and credential phishing heuristics.
 */
public final class WebReputationAuditor {

    public static let shared = WebReputationAuditor()

    private let suspiciousTlds: Set<String> = [
        "top", "xyz", "buzz", "click", "rest", "cam", "fit", "work", "tk", "ml", "ga", "cf", "gq"
    ]

    private let phishingKeywords: [String] = [
        "login-verify", "account-update", "secure-banking", "recover-wallet",
        "confirm-identity", "password-reset-alert", "auth-token-claim", "signin-service"
    ]

    public func auditUrl(_ urlString: String) -> WebReputationResult {
        let cleanUrl = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        var reasons: [String] = []
        var score = 0

        var domain = cleanUrl.lowercased()
        let formattedUrlString = cleanUrl.hasPrefix("http://") || cleanUrl.hasPrefix("https://") ? cleanUrl : "https://\(cleanUrl)"
        if let url = URL(string: formattedUrlString), let host = url.host {
            domain = host.lowercased()
        }

        // 1. IP Address Host Check
        let ipRegex = try? NSRegularExpression(pattern: #"^(\d{1,3}\.){3}\d{1,3}$"#)
        let isIp = ipRegex?.firstMatch(in: domain, range: NSRange(location: 0, length: domain.utf16.count)) != nil
        if isIp {
            score += 35
            reasons.append("Raw IP address used instead of verified domain name")
        }

        // 2. Suspicious TLD check
        let parts = domain.components(separatedBy: ".")
        if let tld = parts.last, suspiciousTlds.contains(tld) {
            score += 25
            reasons.append("Domain uses high-abuse top-level domain (.\(tld))")
        }

        // 3. Excessive Subdomains
        if parts.count > 4 {
            score += 20
            reasons.append("Excessive subdomain depth (\(parts.count) levels)")
        }

        // 4. Phishing Keywords
        let lowerUrl = cleanUrl.lowercased()
        for kw in phishingKeywords {
            if lowerUrl.contains(kw) {
                score += 40
                reasons.append("Contains known phishing credential-harvesting token: '\(kw)'")
            }
        }

        // 5. Punycode (xn--) Homoglyph impersonation
        if domain.hasPrefix("xn--") || domain.contains(".xn--") {
            score += 30
            reasons.append("Punycode encoded domain (potential homograph impersonation attack)")
        }

        let verdict: WebVerdict
        if score >= 60 {
            verdict = .phishing
        } else if score >= 35 {
            verdict = .suspicious
        } else {
            verdict = .safe
        }

        return WebReputationResult(
            url: cleanUrl,
            domain: domain,
            verdict: verdict,
            riskScore: min(100, max(0, score)),
            reasons: reasons
        )
    }
}
