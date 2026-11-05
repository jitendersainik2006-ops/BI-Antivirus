"""
BI Antivirus - Threat Detection Engine
Multi-layered threat analysis:
1. Streaming SHA-256 / MD5 hashing
2. Exact signature database matching
3. Deep regex and byte pattern scanning
4. Safe heuristic indicators (Shannon entropy, double extensions, masquerading PE files, dropper scripts)
Never executes untrusted files during analysis.
"""

import hashlib
import math
import os
import re
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from bi_antivirus.config import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_CLEAN,
    FAMILY_HEURISTIC,
    FAMILY_TROJAN,
    FAMILY_DROPPER,
)
from bi_antivirus.database.signatures import SignatureDatabase

# Suspicious double extension regex pattern (e.g., document.pdf.exe, invoice.docx.vbs)
DOUBLE_EXT_PATTERN = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|rtf|zip|mp3|mp4)\.(exe|vbs|vbe|bat|cmd|ps1|scr|pif|hta|cpl|wsf|jar)$",
    re.IGNORECASE,
)

# Known risky standalone executable extensions
EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".hta", ".cpl", ".wsf", ".vbs", ".vbe", ".bat", ".cmd", ".ps1", ".com", ".gadget"
}

# Suspicious script patterns for heuristic analysis
HEURISTIC_SCRIPT_PATTERNS = [
    (re.compile(r"(?i)powershell(\.exe)?\s+-[eE](nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}"), "Heuristic.Script.EncodedPowerShell", 35),
    (re.compile(r"(?i)FromBase64String\s*\("), "Heuristic.Script.Base64Decoder", 20),
    (re.compile(r"(?i)WScript\.Shell.*\.Run"), "Heuristic.Script.WScriptExecution", 25),
    (re.compile(r"(?i)certutil(\.exe)?\s+(-urlcache|-split|-f)\s+http"), "Heuristic.Dropper.CertutilDownload", 40),
    (re.compile(r"(?i)mshta(\.exe)?\s+http"), "Heuristic.Dropper.MshtaDownload", 40),
    (re.compile(r"(?i)rundll32(\.exe)?\s+javascript:"), "Heuristic.Dropper.Rundll32Script", 40),
    (re.compile(r"(?i)vssadmin\s+delete\s+shadows"), "Heuristic.Ransomware.ShadowDelete", 50),
    (re.compile(r"(?i)AutoOpen\(\)|Workbook_Open\(\)"), "Heuristic.Macro.AutoExec", 30),
]


class ThreatDetector:
    """Detection engine combining hash lookups, byte signatures, and heuristics."""

    def __init__(self, signature_db: Optional[SignatureDatabase] = None, enable_heuristics: bool = True):
        self.sig_db = signature_db or SignatureDatabase()
        self.enable_heuristics = enable_heuristics

    @staticmethod
    def calculate_file_hash(file_path: Path, max_bytes: int = 200 * 1024 * 1024) -> Tuple[str, str, int]:
        """
        Stream file content to calculate SHA-256 and MD5 hashes safely.
        Returns: (sha256_hex, md5_hex, total_bytes_read)
        """
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        bytes_read = 0

        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                md5.update(chunk)
                bytes_read += len(chunk)
                if bytes_read > max_bytes:
                    break

        return sha256.hexdigest().lower(), md5.hexdigest().lower(), bytes_read

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """
        Compute Shannon Entropy of byte buffer (0.0 to 8.0).
        High entropy (>7.2) indicates compressed, packed, or encrypted data.
        """
        if not data:
            return 0.0

        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1

        total = len(data)
        entropy = 0.0
        for count in frequency:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        return round(entropy, 3)

    @staticmethod
    def inspect_pe_header(header_bytes: bytes) -> Dict[str, Any]:
        """
        Safely inspect PE/DOS headers for executable structures without executing.
        Checks for MZ header and PE signature offset.
        """
        is_pe = False
        is_dll = False
        subsystem = None

        if len(header_bytes) >= 64 and header_bytes[:2] == b"MZ":
            # Offset to PE signature is located at 0x3C in DOS header
            try:
                pe_offset = int.from_bytes(header_bytes[0x3C:0x40], byteorder="little")
                if len(header_bytes) >= pe_offset + 4:
                    if header_bytes[pe_offset:pe_offset+4] == b"PE\x00\x00":
                        is_pe = True
            except Exception:
                pass

        return {
            "has_mz": header_bytes[:2] == b"MZ",
            "is_pe": is_pe,
        }

    def analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Perform complete multi-layered security analysis of a single file.
        Returns detailed report dictionary.
        """
        path = Path(file_path)
        if not path.is_file():
            return {
                "file_path": str(path),
                "is_threat": False,
                "error": "File not found or inaccessible",
                "severity": SEVERITY_CLEAN,
            }

        try:
            file_size = path.stat().st_size
        except Exception as e:
            return {
                "file_path": str(path),
                "is_threat": False,
                "error": str(e),
                "severity": SEVERITY_CLEAN,
            }

        # Step 1: Calculate Hashes
        try:
            sha256_hash, md5_hash, read_bytes = self.calculate_file_hash(path)
        except Exception as e:
            return {
                "file_path": str(path),
                "file_size": file_size,
                "is_threat": False,
                "error": f"Failed reading file for hash: {e}",
                "severity": SEVERITY_CLEAN,
            }

        # Step 2: Exact Signature Hash Lookup
        known_threat = self.sig_db.lookup_hash(sha256_hash)
        if known_threat:
            return {
                "file_path": str(path),
                "file_name": path.name,
                "file_hash": sha256_hash,
                "md5_hash": md5_hash,
                "file_size": file_size,
                "is_threat": True,
                "threat_name": known_threat["threat_name"],
                "threat_family": known_threat["threat_family"],
                "severity": known_threat["severity"],
                "detection_type": "SIGNATURE_HASH",
                "description": known_threat["description"],
                "risk_score": 100,
                "heuristic_flags": [],
            }

        # Read sample bytes for inspection (up to 1MB)
        try:
            with open(path, "rb") as f:
                sample_bytes = f.read(1024 * 1024)
        except Exception as e:
            return {
                "file_path": str(path),
                "file_hash": sha256_hash,
                "is_threat": False,
                "error": f"Failed reading sample bytes: {e}",
                "severity": SEVERITY_CLEAN,
            }

        # Step 3: Pattern & Regex Signature Matching
        pattern_matches = self.sig_db.match_patterns(sample_bytes)
        if pattern_matches:
            top_match = pattern_matches[0]
            return {
                "file_path": str(path),
                "file_name": path.name,
                "file_hash": sha256_hash,
                "md5_hash": md5_hash,
                "file_size": file_size,
                "is_threat": True,
                "threat_name": top_match["threat_name"],
                "threat_family": top_match["threat_family"],
                "severity": top_match["severity"],
                "detection_type": "SIGNATURE_PATTERN",
                "description": top_match["description"],
                "risk_score": 90,
                "heuristic_flags": [m["rule_name"] for m in pattern_matches],
            }

        # Step 4: Safe Heuristic Analysis
        if not self.enable_heuristics:
            return {
                "file_path": str(path),
                "file_name": path.name,
                "file_hash": sha256_hash,
                "md5_hash": md5_hash,
                "file_size": file_size,
                "is_threat": False,
                "severity": SEVERITY_CLEAN,
                "risk_score": 0,
            }

        risk_score = 0
        heuristic_flags = []
        ext = path.suffix.lower()

        # Heuristic 4.1: Double Extension Anomaly (e.g. document.pdf.exe)
        if DOUBLE_EXT_PATTERN.search(path.name):
            risk_score += 65
            heuristic_flags.append(f"SuspiciousDoubleExtension:{path.name}")

        # Heuristic 4.2: Masquerading PE Executable (e.g. file is named .png or .jpg but starts with MZ/PE)
        pe_info = self.inspect_pe_header(sample_bytes[:1024])
        non_pe_extensions = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".csv", ".docx", ".xlsx"}
        if ext in non_pe_extensions and pe_info["is_pe"]:
            risk_score += 80
            heuristic_flags.append(f"ExecutableMasqueradingAs:{ext}")

        # Heuristic 4.3: Shannon Entropy Analysis
        # Check entropy on binary/executable files
        if ext in EXECUTABLE_EXTENSIONS or pe_info["is_pe"]:
            entropy = self.calculate_shannon_entropy(sample_bytes)
            if entropy >= 7.3 and file_size > 10240:
                risk_score += 35
                heuristic_flags.append(f"HighEntropyPacking:{entropy}")

        # Heuristic 4.4: Embedded Script & Dropper Inspection
        try:
            sample_text = sample_bytes.decode("utf-8", errors="ignore")
            for pattern_re, rule_id, weight in HEURISTIC_SCRIPT_PATTERNS:
                if pattern_re.search(sample_text):
                    risk_score += weight
                    heuristic_flags.append(rule_id)
        except Exception:
            pass

        # Risk Classification Assessment
        if risk_score >= 70:
            severity = SEVERITY_HIGH if risk_score < 90 else SEVERITY_CRITICAL
            return {
                "file_path": str(path),
                "file_name": path.name,
                "file_hash": sha256_hash,
                "md5_hash": md5_hash,
                "file_size": file_size,
                "is_threat": True,
                "threat_name": f"Heuristic.Suspicious.{heuristic_flags[0] if heuristic_flags else 'Generic'}",
                "threat_family": FAMILY_HEURISTIC,
                "severity": severity,
                "detection_type": "HEURISTIC_INDICATOR",
                "description": f"Heuristic threat score: {risk_score}/100. Flags: {', '.join(heuristic_flags[:3])}",
                "risk_score": min(risk_score, 100),
                "heuristic_flags": heuristic_flags,
            }
        elif risk_score >= 40:
            return {
                "file_path": str(path),
                "file_name": path.name,
                "file_hash": sha256_hash,
                "md5_hash": md5_hash,
                "file_size": file_size,
                "is_threat": True,
                "threat_name": f"Heuristic.Warning.{heuristic_flags[0] if heuristic_flags else 'Generic'}",
                "threat_family": FAMILY_HEURISTIC,
                "severity": SEVERITY_MEDIUM,
                "detection_type": "HEURISTIC_SUSPICIOUS",
                "description": f"Suspicious file indicators detected (Score: {risk_score}/100).",
                "risk_score": risk_score,
                "heuristic_flags": heuristic_flags,
            }

        return {
            "file_path": str(path),
            "file_name": path.name,
            "file_hash": sha256_hash,
            "md5_hash": md5_hash,
            "file_size": file_size,
            "is_threat": False,
            "severity": SEVERITY_CLEAN,
            "risk_score": risk_score,
            "heuristic_flags": heuristic_flags,
        }
