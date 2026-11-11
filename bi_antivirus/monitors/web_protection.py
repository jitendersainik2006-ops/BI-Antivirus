"""
BI Antivirus - Web & URL Protection Shield
Audits URLs, domains, and web destinations against local reputation database
and heuristic threat patterns (typosquatting, raw IP addresses, suspicious TLDs, phishing cues).
Safely inspects URLs without fetching or executing remote untrusted payloads.
"""

import re
import ipaddress
import urllib.parse
from typing import Dict, Any, Optional, List, Set
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

# Content and Threat Categories
CATEGORY_KEYWORDS = {
    "Phishing": {"login-verification", "account-update", "secure-bank", "paypal-security", "wallet-connect"},
    "Malware_C2": {"botnet", "beacon", "dropper", "c2-gate", "rat-server"},
    "Cryptomining": {"coinhive", "cryptoloot", "minexmr", "monerominer", "webminerpool"},
    "Gambling": {"bet365", "casino", "poker", "jackpot", "sportsbetting", "roulette"},
}


class WebProtection:
    """
    Evaluates URLs, domains, and IP endpoints against reputation rules,
    category filters (Phishing, Malware/C2, Cryptomining, Gambling), CIDR blocklists,
    and enterprise web access policies.
    """

    def __init__(self, signature_db: Optional[SignatureDatabase] = None):
        self.sig_db = signature_db or SignatureDatabase()
        self.custom_blocked_categories: Set[str] = set()
        self.custom_blocked_cidrs: List[ipaddress.IPv4Network] = []
        self.whitelist_domains: Set[str] = {"google.com", "microsoft.com", "github.com"}
        self.blacklist_domains: Set[str] = set()

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

    def add_blocked_cidr(self, cidr_str: str) -> bool:
        """Add a CIDR subnet block to WebProtection."""
        try:
            net = ipaddress.ip_network(cidr_str.strip(), strict=False)
            self.custom_blocked_cidrs.append(net)
            return True
        except Exception:
            return False

    def add_blocked_category(self, category_name: str) -> None:
        """Block an entire web content category."""
        self.custom_blocked_categories.add(category_name.strip())

    def evaluate_policy(self, url: str, policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Evaluate URL against enterprise access policies:
        - Domain whitelist / blacklist
        - Content categories (Phishing, Malware/C2, Cryptomining, Gambling)
        - Blocked CIDR ranges
        - Base heuristic checks
        """
        cleaned_url = url.strip()
        if not cleaned_url.startswith(("http://", "https://", "ftp://")):
            cleaned_url = "http://" + cleaned_url

        try:
            parsed = urllib.parse.urlparse(cleaned_url)
            host = (parsed.hostname or "").lower()
            path_query = (parsed.path + " " + parsed.query).lower()
        except Exception:
            host = ""
            path_query = ""

        # 1. Whitelist Check (Overrides all blocks)
        whitelist = policy.get("whitelist_domains", self.whitelist_domains) if policy else self.whitelist_domains
        for wl in whitelist:
            if host == wl.lower() or host.endswith("." + wl.lower()):
                return {
                    "url": url,
                    "action": "ALLOW",
                    "reason": f"Whitelisted domain: {wl}",
                    "category": "Whitelisted",
                    "severity": SEVERITY_CLEAN,
                    "is_blocked": False,
                }

        # 2. Blacklist Check
        blacklist = policy.get("blacklist_domains", self.blacklist_domains) if policy else self.blacklist_domains
        for bl in blacklist:
            if host == bl.lower() or host.endswith("." + bl.lower()):
                return {
                    "url": url,
                    "action": "BLOCK",
                    "reason": f"Blacklisted domain rule: {bl}",
                    "category": "Blacklisted",
                    "severity": SEVERITY_HIGH,
                    "is_blocked": True,
                }

        # 3. CIDR Block Check (if host is an IP address)
        blocked_cidrs = self.custom_blocked_cidrs[:]
        if policy and "blocked_cidrs" in policy:
            for c in policy["blocked_cidrs"]:
                try:
                    blocked_cidrs.append(ipaddress.ip_network(c, strict=False))
                except Exception:
                    pass

        try:
            ip_obj = ipaddress.ip_address(host)
            for net in blocked_cidrs:
                if ip_obj in net:
                    return {
                        "url": url,
                        "action": "BLOCK",
                        "reason": f"Destination IP {host} falls within blocked CIDR subnet {net}",
                        "category": "BlockedCIDR",
                        "severity": SEVERITY_HIGH,
                        "is_blocked": True,
                    }
        except ValueError:
            pass

        # 4. Content Category Filtering
        blocked_cats = set(self.custom_blocked_categories)
        if policy and "blocked_categories" in policy:
            blocked_cats.update(policy["blocked_categories"])

        for cat, kw_set in CATEGORY_KEYWORDS.items():
            if cat in blocked_cats:
                for kw in kw_set:
                    if kw in host or kw in path_query:
                        return {
                            "url": url,
                            "action": "BLOCK",
                            "reason": f"Destination matches prohibited web category: {cat} (keyword: {kw})",
                            "category": cat,
                            "severity": SEVERITY_HIGH,
                            "is_blocked": True,
                        }

        # 5. Base Threat Check
        base_res = self.check_url(url)
        if base_res.get("is_threat"):
            return {
                "url": url,
                "action": "BLOCK",
                "reason": base_res.get("reason", "Heuristic web threat detected"),
                "category": base_res.get("category", "Threat"),
                "severity": base_res.get("severity", SEVERITY_HIGH),
                "is_blocked": True,
                "risk_score": base_res.get("risk_score", 80),
            }

        return {
            "url": url,
            "action": "ALLOW",
            "reason": "Passed enterprise policy inspection",
            "category": "Clean",
            "severity": SEVERITY_CLEAN,
            "is_blocked": False,
        }
