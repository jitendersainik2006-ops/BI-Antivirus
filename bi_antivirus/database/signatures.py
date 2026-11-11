"""
BI Antivirus - Malware Signature Database
Stores and queries SHA-256 hashes, byte patterns, and malicious domain reputations
using an SQLite database located on D: drive.
Seeds harmless standard test signatures including EICAR and behavioral patterns.
"""

import sqlite3
import re
import json
import logging
import threading
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
from bi_antivirus.config import (
    SIGNATURES_DB_PATH,
    SIGNATURE_DB_VERSION,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    FAMILY_TEST_VIRUS,
    FAMILY_RANSOMWARE,
    FAMILY_DROPPER,
    FAMILY_SPYWARE,
    FAMILY_TROJAN,
)

logger = logging.getLogger("bi_antivirus.signatures")

# EICAR Harmless Standard Test String (Official standard for AV validation)
EICAR_PLAIN = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


class SignatureDatabase:
    """Manages malware signatures, hash indexes, byte pattern rules, and web reputation."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path or SIGNATURES_DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._compiled_patterns_cache: Optional[List[Tuple[str, str, Any, str, str]]] = None
        self._cache_lock = threading.Lock()
        self._init_db()
        self._ensure_seeds()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA busy_timeout=5000;")
        except Exception:
            pass
        return conn

    def _init_db(self) -> None:
        """Create tables and indexes if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Hash Signature Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hash_signatures (
                    sha256 TEXT PRIMARY KEY,
                    threat_name TEXT NOT NULL,
                    threat_family TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Byte / Regex Pattern Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pattern_signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT UNIQUE NOT NULL,
                    threat_family TEXT NOT NULL,
                    pattern_regex TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    is_active INTEGER DEFAULT 1
                )
            """)

            # Web Domain Reputation Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS web_reputation (
                    domain_or_url TEXT PRIMARY KEY,
                    threat_category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Metadata Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS db_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)

            # High-throughput performance indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_pattern_active ON pattern_signatures (is_active);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_web_rep_domain ON web_reputation (domain_or_url);")

            cursor.execute("""
                INSERT OR REPLACE INTO db_metadata (key, value)
                VALUES ('version', ?), ('engine', 'BI-Engine')
            """, (SIGNATURE_DB_VERSION,))
            
            conn.commit()

    def _ensure_seeds(self) -> None:
        """Seed harmless test signatures and known threat heuristics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Seed standard test hashes
            seeds_hashes = [
                (
                    "4ee2d52572864d2d41d63f2bd5555a62dbabe917599d753da2e213c9cfd85d8d",
                    "BI-Standard-Validation-Test-Signature",
                    FAMILY_TEST_VIRUS,
                    SEVERITY_CRITICAL,
                    "Official BI Antivirus safe testing payload signature (with newline)",
                ),
                (
                    "d90ee3272e2091d2af15537b4ea38ec4abbcaa3fac63e7a14c595b0c87f04118",
                    "BI-Standard-Validation-Test-Signature",
                    FAMILY_TEST_VIRUS,
                    SEVERITY_CRITICAL,
                    "Official BI Antivirus safe testing payload signature",
                ),
                (
                    EICAR_SHA256,
                    "EICAR-Standard-AV-Test-File",
                    FAMILY_TEST_VIRUS,
                    SEVERITY_CRITICAL,
                    "Standard harmless test file defined by the European Institute for Computer Antivirus Research",
                ),
                (
                    "44d88612fea8a8f36de82e1278abb02f", # MD5 for legacy test (if checked)
                    "EICAR-Test-File-MD5",
                    FAMILY_TEST_VIRUS,
                    SEVERITY_CRITICAL,
                    "Standard test file signature",
                ),
                (
                    "b026324c6904b2a9cb4b88d6d61c81d1ff6f6c91a0c71a393fb7c6a91703ab34",
                    "BI-Simulated-Trojan-TestPayload",
                    FAMILY_TROJAN,
                    SEVERITY_HIGH,
                    "Internal harmless test payload fixture for CI/CD",
                ),
                (
                    "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
                    "BI-Simulated-Ransomware-TestFixture",
                    FAMILY_RANSOMWARE,
                    SEVERITY_CRITICAL,
                    "Internal harmless test payload for ransomware recovery tests",
                ),
            ]

            # Purge deprecated seed signatures that could cause false positives on empty files
            cursor.execute("DELETE FROM hash_signatures WHERE threat_name = 'Empty-Payload-ZeroByte' OR sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'")

            for h, name, fam, sev, desc in seeds_hashes:
                cursor.execute("""
                    INSERT OR IGNORE INTO hash_signatures (sha256, threat_name, threat_family, severity, description)
                    VALUES (?, ?, ?, ?, ?)
                """, (h.lower(), name, fam, sev, desc))

            # Seed byte/regex patterns
            patterns = [
                (
                    "RULE_EICAR_EXACT",
                    FAMILY_TEST_VIRUS,
                    re.escape(EICAR_PLAIN),
                    SEVERITY_CRITICAL,
                    "Exact EICAR antivirus test payload string",
                ),
                (
                    "RULE_RANSOM_SHADOW_DELETE",
                    FAMILY_RANSOMWARE,
                    r"(?i)vssadmin\s+delete\s+shadows(\s+/all|\s+/quiet)*",
                    SEVERITY_CRITICAL,
                    "Heuristic: Shadow volume deletion command line commonly executed by ransomware",
                ),
                (
                    "RULE_RANSOM_NOTE_DECRYPT_FILES",
                    FAMILY_RANSOMWARE,
                    r"(?i)your files (have been|are) encrypted.*(bitcoin|btc|decrypt|ransom)",
                    SEVERITY_HIGH,
                    "Heuristic: Standard extortion and ransom demand note text pattern",
                ),
                (
                    "RULE_POWERSHELL_SUSPICIOUS_EXEC",
                    FAMILY_DROPPER,
                    r"(?i)powershell(\.exe)?\s+(-w(indowstyle)?\s+hidden|-enc(odedcommand)?)",
                    SEVERITY_HIGH,
                    "Heuristic: Hidden or base64-encoded PowerShell execution dropper",
                ),
                (
                    "RULE_MIMIKATZ_SEKURLSA",
                    FAMILY_SPYWARE,
                    r"(?i)sekurlsa::(logonpasswords|minidump|pth)",
                    SEVERITY_CRITICAL,
                    "Signature: Credential dumping utility signature",
                ),
                (
                    "RULE_DOWNLOAD_CRADLE_BITSADMIN",
                    FAMILY_DROPPER,
                    r"(?i)bitsadmin(\.exe)?\s+/transfer\s+\S+\s+http",
                    SEVERITY_HIGH,
                    "Heuristic: LOLBin background downloader command pattern",
                ),
                (
                    "RULE_PERSISTENCE_REG_RUN",
                    FAMILY_TROJAN,
                    r"(?i)CurrentVersion\\Run.*\.exe",
                    SEVERITY_MEDIUM,
                    "Heuristic: Registry autorun persistence string",
                ),
            ]

            for rule, fam, pat, sev, desc in patterns:
                cursor.execute("""
                    INSERT OR IGNORE INTO pattern_signatures (rule_name, threat_family, pattern_regex, severity, description)
                    VALUES (?, ?, ?, ?, ?)
                """, (rule, fam, pat, sev, desc))

            # Seed test web reputations
            reputations = [
                ("malware-traffic-analysis.test", "Malware Test Host", SEVERITY_HIGH, "Testing domain"),
                ("phishing-bank-update.test", "Phishing Credential Harvester", SEVERITY_CRITICAL, "Simulated phishing domain"),
                ("cryptominer-pool.test", "Crypto Mining Network", SEVERITY_HIGH, "Simulated unauthorized mining endpoint"),
                ("eicar.org", "Antivirus Test Source", SEVERITY_LOW, "Official EICAR distribution domain"),
                ("trojan-c2-listener.test", "C2 Command & Control", SEVERITY_CRITICAL, "Simulated C2 network hub"),
            ]

            for domain, cat, sev, desc in reputations:
                cursor.execute("""
                    INSERT OR IGNORE INTO web_reputation (domain_or_url, threat_category, severity, description)
                    VALUES (?, ?, ?, ?)
                """, (domain.lower(), cat, sev, desc))

            conn.commit()

    def lookup_hash(self, sha256_hash: str) -> Optional[Dict[str, Any]]:
        """Look up file SHA-256 hash in signature database."""
        sha256_clean = sha256_hash.strip().lower()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT sha256, threat_name, threat_family, severity, description
                FROM hash_signatures
                WHERE sha256 = ?
            """, (sha256_clean,))
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def invalidate_pattern_cache(self) -> None:
        """Invalidate in-memory compiled pattern cache."""
        with self._cache_lock:
            self._compiled_patterns_cache = None

    def _load_compiled_patterns(self) -> List[Tuple[str, str, Any, str, str]]:
        """Pre-compile active regex patterns into memory once for high-throughput scanning."""
        with self._cache_lock:
            if self._compiled_patterns_cache is not None:
                return self._compiled_patterns_cache

            compiled = []
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT rule_name, threat_family, pattern_regex, severity, description
                    FROM pattern_signatures
                    WHERE is_active = 1
                """)
                for row in cursor.fetchall():
                    rule_name = row["rule_name"]
                    pattern = row["pattern_regex"]
                    try:
                        compiled_re = re.compile(pattern)
                        compiled.append((rule_name, row["threat_family"], compiled_re, row["severity"], row["description"]))
                    except Exception as e:
                        logger.debug(f"Failed to pre-compile pattern for {rule_name}: {e}")

            self._compiled_patterns_cache = compiled
            return self._compiled_patterns_cache

    def match_patterns(self, file_content: bytes, max_bytes: int = 1048576) -> List[Dict[str, Any]]:
        """Scan file bytes (up to max_bytes) against active regex and byte rules using cached compiled patterns."""
        sample = file_content[:max_bytes]
        matched = []

        try:
            sample_text = sample.decode("utf-8", errors="ignore")
        except Exception:
            sample_text = ""

        patterns = self._load_compiled_patterns()
        for rule_name, threat_family, pattern_re, severity, description in patterns:
            try:
                if pattern_re.search(sample_text):
                    matched.append({
                        "rule_name": rule_name,
                        "threat_name": f"{threat_family}.Heuristic.{rule_name}",
                        "threat_family": threat_family,
                        "severity": severity,
                        "description": description,
                    })
            except Exception as e:
                logger.debug(f"Pattern regex evaluation failed for {rule_name}: {e}")

        return matched

    def lookup_domain(self, domain_or_url: str) -> Optional[Dict[str, Any]]:
        """Check domain or URL against blocked reputation list."""
        cleaned = domain_or_url.strip().lower()
        # strip protocol if present
        if "://" in cleaned:
            cleaned = cleaned.split("://", 1)[1]
        cleaned = cleaned.split("/")[0].split(":")[0]

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT domain_or_url, threat_category, severity, description
                FROM web_reputation
                WHERE domain_or_url = ? OR ? LIKE '%' || domain_or_url
            """, (cleaned, cleaned))
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def add_hash_signature(
        self,
        sha256: str,
        threat_name: str,
        threat_family: str,
        severity: str,
        description: str = "",
    ) -> bool:
        """Add a new hash signature to the database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO hash_signatures (sha256, threat_name, threat_family, severity, description)
                VALUES (?, ?, ?, ?, ?)
            """, (sha256.strip().lower(), threat_name, threat_family, severity, description))
            conn.commit()
            return True

    def get_stats(self) -> Dict[str, Any]:
        """Return total signature counts and version info."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM hash_signatures")
            hash_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM pattern_signatures WHERE is_active = 1")
            pattern_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM web_reputation")
            web_count = cursor.fetchone()[0]

            cursor.execute("SELECT value FROM db_metadata WHERE key = 'version'")
            row = cursor.fetchone()
            version = row[0] if row else SIGNATURE_DB_VERSION

            return {
                "version": version,
                "total_hash_signatures": hash_count,
                "total_pattern_rules": pattern_count,
                "total_web_reputations": web_count,
                "total_indicators": hash_count + pattern_count + web_count,
                "database_path": str(self.db_path),
            }

    def export_signatures_json(self) -> str:
        """Export signature database to a portable JSON format."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sha256, threat_name, threat_family, severity, description FROM hash_signatures")
            hashes = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT rule_name, threat_family, pattern_regex, severity, description FROM pattern_signatures")
            patterns = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT domain_or_url, threat_category, severity, description FROM web_reputation")
            domains = [dict(r) for r in cursor.fetchall()]

            payload = {
                "version": SIGNATURE_DB_VERSION,
                "hashes": hashes,
                "patterns": patterns,
                "domains": domains,
            }
            return json.dumps(payload, indent=2)

    def import_signatures_json(self, json_string: str) -> int:
        """Import signature update payload from JSON string."""
        data = json.loads(json_string)
        imported_count = 0
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for h in data.get("hashes", []):
                cursor.execute("""
                    INSERT OR REPLACE INTO hash_signatures (sha256, threat_name, threat_family, severity, description)
                    VALUES (?, ?, ?, ?, ?)
                """, (h["sha256"].lower(), h["threat_name"], h["threat_family"], h["severity"], h.get("description", "")))
                imported_count += 1

            for p in data.get("patterns", []):
                cursor.execute("""
                    INSERT OR REPLACE INTO pattern_signatures (rule_name, threat_family, pattern_regex, severity, description)
                    VALUES (?, ?, ?, ?, ?)
                """, (p["rule_name"], p["threat_family"], p["pattern_regex"], p["severity"], p.get("description", "")))
                imported_count += 1

            for d in data.get("domains", []):
                cursor.execute("""
                    INSERT OR REPLACE INTO web_reputation (domain_or_url, threat_category, severity, description)
                    VALUES (?, ?, ?, ?)
                """, (d["domain_or_url"].lower(), d["threat_category"], d["severity"], d.get("description", "")))
                imported_count += 1

            if "version" in data:
                cursor.execute("INSERT OR REPLACE INTO db_metadata (key, value) VALUES ('version', ?)", (data["version"],))

            conn.commit()
        self.invalidate_pattern_cache()
        return imported_count
