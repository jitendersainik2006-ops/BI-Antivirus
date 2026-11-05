"""
BI Antivirus - Web & URL Protection Shield
Audits URLs, domains, and web destinations against local reputation database
and heuristic threat patterns (typosquatting, raw IP addresses, suspicious TLDs, phishing cues).
Safely inspects URLs without fetching or executing remote untrusted payloads.
"""

import re
import urllib.parse
from typing import Dict, Any, Optional
from bi_antivirus.config import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_CLEAN,
)
from bi_antivirus.database.signatures import SignatureDatabase

# High-risk TLDs commonly abused in automated phishing / malvertising campaigns
SUSPICIOUS_TLDS = {".top", ".xyz", ".tk", ".cf", ".gq", ".ml", ".ga", ".fit", ".work", ".click", ".country"}

# Raw IPv4 regex pattern in URL host
IP_HOST_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")

# Phishing parameter heuristics in query strings
PHISHING_QUERY_PATTERN = re.compile(r"(?i)(pass(word)?|pin|secret|token|ssn|auth_key)=")


class WebProtection:
    """Evaluates URLs and domains against reputation rules and phishing heuristics."""

    def __init__(self, signature_db: Optional[SignatureDatabase] = None):
        self.sig_db = signature_db or SignatureDatabase()

    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a full URL for web threats, phishing parameters, and reputation flags.
        """
        cleaned_url = url.strip()
        if not cleaned_url.startswith(("http://", "https://", "ftp://")):
            cleaned_url = "http://" + cleaned_url

        try:
            parsed = urllib.parse.urlparse(cleaned_url)
            host = (parsed.hostname or "").lower()
            path = parsed.path
            query = parsed.query
        except Exception as e:
            return {
                "url": url,
                "is_threat": False,
                "error": f"Invalid URL structure: {e}",
                "severity": SEVERITY_CLEAN,
            }

        # Step 1: Check Database Reputation
        rep = self.sig_db.lookup_domain(host)
        if rep:
            return {
                "url": url,
                "host": host,
                "is_threat": True,
                "threat_name": f"Web.{rep['threat_category']}.Blocked",
                "category": rep["threat_category"],
                "severity": rep["severity"],
                "reason": rep.get("description", "Known malicious domain in reputation database"),
                "risk_score": 95,
            }

        # Step 2: Safe Heuristic Checks
        risk_score = 0
        reasons = []

        # Check 2.1: Raw IP Address Host
        if IP_HOST_PATTERN.match(host):
            risk_score += 45
            reasons.append("Direct IP address access without domain name")

        # Check 2.2: Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                risk_score += 35
                reasons.append(f"High-risk top level domain: {tld}")
                break

        # Check 2.3: Phishing query parameters
        if PHISHING_QUERY_PATTERN.search(query):
            risk_score += 40
            reasons.append("Sensitive authentication parameters exposed in URL query")

        # Check 2.4: Suspicious executable download in URL path
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        if ext in {"exe", "scr", "vbs", "ps1", "bat", "hta", "pif"}:
            risk_score += 45
            reasons.append(f"URL directly links to executable download: .{ext}")

        if risk_score >= 70:
            return {
                "url": url,
                "host": host,
                "is_threat": True,
                "threat_name": "Web.Heuristic.MaliciousLink",
                "category": "SuspiciousURL",
                "severity": SEVERITY_HIGH,
                "reason": "; ".join(reasons),
                "risk_score": min(risk_score, 100),
            }
        elif risk_score >= 35:
            return {
                "url": url,
                "host": host,
                "is_threat": False,
                "threat_name": "Web.Warning.PotentialRisk",
                "category": "PotentialRisk",
                "severity": SEVERITY_MEDIUM,
                "reason": "; ".join(reasons),
                "risk_score": risk_score,
            }

        return {
            "url": url,
            "host": host,
            "is_threat": False,
            "severity": SEVERITY_CLEAN,
            "reason": "URL verified clean by local reputation shield",
            "risk_score": 0,
        }
