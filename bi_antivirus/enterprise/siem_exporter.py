"""
BI Antivirus - SIEM Exporter & Cryptographic Hash Chaining Sentinel
Formats and exports enterprise security telemetry to SIEM repositories:
1. CEF (Common Event Format - ArcSight / QRadar / Splunk)
2. RFC 5424 Syslog (Structured Syslog with Enterprise Extension)
3. Structured JSON Lines

Integrity Guarantee:
Cryptographic Hash Chaining:
Each log record entry_i includes a backward hash pointer:
H_i = SHA256(H_{i-1} || canonical_json(entry_i))
This mathematically guarantees tamper-evidence: any modification, deletion,
or reordering of log records invalidates the cryptographic verification chain.
"""

import time
import json
import hashlib
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("BI_SIEMExporter")

GENESIS_HASH = hashlib.sha256(b"BI_ANTIVIRUS_GENESIS_AUDIT_LOG_2026_SECURE").hexdigest()


@dataclass
class ChainedAuditEntry:
    """Audit log entry secured by cryptographic hash chaining."""
    sequence_id: int
    timestamp: float
    event_type: str
    severity: str
    actor: str
    action: str
    details: Dict[str, Any]
    prev_hash: str
    current_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SIEMExporter:
    """Formats enterprise telemetry and manages tamper-evident cryptographic hash chains."""

    def __init__(self, genesis_hash: Optional[str] = None):
        self.current_head_hash: str = genesis_hash or GENESIS_HASH
        self.sequence_counter: int = 0
        self.chain: List[ChainedAuditEntry] = []

    def _canonicalize_entry(
        self,
        sequence_id: int,
        timestamp: float,
        event_type: str,
        severity: str,
        actor: str,
        action: str,
        details: Dict[str, Any],
        prev_hash: str,
    ) -> bytes:
        """Create canonical representation for deterministic SHA-256 hashing."""
        data = {
            "sequence_id": sequence_id,
            "timestamp": round(timestamp, 4),
            "event_type": event_type,
            "severity": severity,
            "actor": actor,
            "action": action,
            "details": details,
            "prev_hash": prev_hash,
        }
        canonical_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return canonical_str.encode("utf-8")

    def record_audit_entry(
        self,
        event_type: str,
        action: str,
        actor: str = "SYSTEM",
        severity: str = "INFO",
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[float] = None,
    ) -> ChainedAuditEntry:
        """
        Record and cryptographically link a new audit log entry into the hash chain.
        """
        ts = timestamp if timestamp is not None else time.time()
        self.sequence_counter += 1
        seq = self.sequence_counter
        prev_h = self.current_head_hash
        det = details or {}

        canonical_bytes = self._canonicalize_entry(
            sequence_id=seq,
            timestamp=ts,
            event_type=event_type,
            severity=severity,
            actor=actor,
            action=action,
            details=det,
            prev_hash=prev_h,
        )

        curr_h = hashlib.sha256(canonical_bytes).hexdigest()
        entry = ChainedAuditEntry(
            sequence_id=seq,
            timestamp=ts,
            event_type=event_type,
            severity=severity,
            actor=actor,
            action=action,
            details=det,
            prev_hash=prev_h,
            current_hash=curr_h,
        )

        self.current_head_hash = curr_h
        self.chain.append(entry)
        return entry

    def verify_chain(self, chain_to_verify: Optional[List[ChainedAuditEntry]] = None) -> Tuple[bool, Optional[int], str]:
        """
        Mathematically verify the entire audit log hash chain.
        Returns: (is_valid, failing_index, reason)
        """
        chain = chain_to_verify if chain_to_verify is not None else self.chain
        if not chain:
            return True, None, "Chain is empty (valid)."

        expected_prev = GENESIS_HASH

        for idx, entry in enumerate(chain):
            # 1. Verify backward link
            if entry.prev_hash != expected_prev:
                return False, idx, f"Broken chain link at index {idx} (seq {entry.sequence_id}): expected prev_hash {expected_prev[:12]}, got {entry.prev_hash[:12]}"

            # 2. Recompute current hash
            canonical_bytes = self._canonicalize_entry(
                sequence_id=entry.sequence_id,
                timestamp=entry.timestamp,
                event_type=entry.event_type,
                severity=entry.severity,
                actor=entry.actor,
                action=entry.action,
                details=entry.details,
                prev_hash=entry.prev_hash,
            )
            recalculated = hashlib.sha256(canonical_bytes).hexdigest()

            if recalculated != entry.current_hash:
                return False, idx, f"Tampered entry detected at index {idx} (seq {entry.sequence_id}): signature mismatch!"

            expected_prev = entry.current_hash

        return True, None, f"Audit chain verified valid ({len(chain)} entries intact)."

    # Format Exporters
    @staticmethod
    def format_cef(
        device_vendor: str = "Black Intel",
        device_product: str = "BI Antivirus",
        device_version: str = "1.1.0-PRO",
        signature_id: str = "THREAT-001",
        name: str = "Security Alert",
        severity: int = 7,  # 0 to 10
        extension_dict: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Format event in ArcSight Common Event Format (CEF):
        CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        """
        ext_parts = []
        if extension_dict:
            for k, v in sorted(extension_dict.items()):
                clean_v = str(v).replace("\\", "\\\\").replace("=", "\\=")
                ext_parts.append(f"{k}={clean_v}")
        ext_str = " ".join(ext_parts)
        return f"CEF:0|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}|{ext_str}"

    @staticmethod
    def format_rfc5424_syslog(
        app_name: str = "BIAntivirus",
        proc_id: str = "1001",
        msg_id: str = "SEC_EVENT",
        structured_data_id: str = "threat@41058",
        sd_params: Optional[Dict[str, str]] = None,
        message: str = "Threat detected and quarantined.",
        facility: int = 16,  # local0
        severity: int = 3,  # Error / High
    ) -> str:
        """
        Format event in RFC 5424 Syslog standard:
        <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
        """
        pri = (facility * 8) + severity
        iso_timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        hostname = "endpoint.local"

        sd_str = "-"
        if sd_params:
            params = " ".join(f'{k}="{v}"' for k, v in sorted(sd_params.items()))
            sd_str = f"[{structured_data_id} {params}]"

        return f"<{pri}>1 {iso_timestamp} {hostname} {app_name} {proc_id} {msg_id} {sd_str} {message}"

    @staticmethod
    def format_json(entry: Dict[str, Any]) -> str:
        """Format event as structured JSON Line."""
        return json.dumps(entry, sort_keys=True)

    def export_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Export a security event to SIEM format, cryptographically chaining the entry.
        Returns a dict with format, payload, hash, and sequence.
        """
        event_type = event_data.get("event_type", "SECURITY_EVENT")
        action = event_data.get("action", event_data.get("message", "SIEM Export"))
        severity = event_data.get("severity", "INFO")
        actor = event_data.get("actor", event_data.get("source", "SYSTEM"))
        details = {k: v for k, v in event_data.items() if k not in ("event_type", "action", "severity", "actor", "timestamp")}
        ts = event_data.get("timestamp", time.time())

        entry = self.record_audit_entry(
            event_type=event_type,
            action=action,
            actor=actor,
            severity=severity,
            details=details,
            timestamp=ts,
        )

        cef = self.format_cef(
            name=action,
            severity=7 if severity in ("HIGH", "CRITICAL") else 3,
            extension_dict=details,
        )
        syslog = self.format_rfc5424_syslog(
            message=action,
            severity=3 if severity in ("HIGH", "CRITICAL") else 6,
        )

        return {
            "success": True,
            "hash": entry.current_hash,
            "sequence_id": entry.sequence_id,
            "cef": cef,
            "syslog": syslog,
        }

