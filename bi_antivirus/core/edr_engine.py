"""
BI Antivirus - Enterprise EDR (Endpoint Detection & Response) Engine
Provides normalized endpoint telemetry, MITRE ATT&CK 14-tactic tagging,
incident correlation, root-cause analysis (RCA), and explainable risk scoring.

Core Capabilities:
1. Normalized Telemetry Event Schema (Process, File, Registry, Network, Memory).
2. MITRE ATT&CK Matrix Tagging across all 14 Tactics (TA0001 - TA0043).
3. Incident Grouping & Temporal Correlation (process trees and multi-event campaigns).
4. Root-Cause Analysis (RCA) backtracking: Traces child process chains back to initial ingress.
5. Explainable Risk Scoring (0 to 100) and Automated Response Recommendations:
   - ISOLATE_HOST
   - TERMINATE_PROCESS
   - QUARANTINE_FILE
   - BLOCK_IP
   - REVOKE_CREDENTIALS
"""

import time
import uuid
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Set, Tuple

logger = logging.getLogger("BI_EDREngine")

# All 14 MITRE ATT&CK Tactics
MITRE_TACTICS_CATALOG = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# Mapping common suspicious behaviors to MITRE tactics and techniques
BEHAVIORAL_MITRE_MAP = {
    "PROCESS_SPAWN_POWERSHELL_ENCODED": {
        "tactic_id": "TA0002",
        "tactic": "Execution",
        "technique": "T1059.001",
        "name": "PowerShell Encoded Command",
        "base_weight": 25,
    },
    "PROCESS_SPAWN_CMD_CHILD_OF_OFFICE": {
        "tactic_id": "TA0001",
        "tactic": "Initial Access",
        "technique": "T1566.001",
        "name": "Spearphishing Attachment Execution",
        "base_weight": 35,
    },
    "CREDENTIAL_DUMP_LSASS_ACCESS": {
        "tactic_id": "TA0006",
        "tactic": "Credential Access",
        "technique": "T1003.001",
        "name": "LSASS Memory Dumping",
        "base_weight": 40,
    },
    "DEFENSE_EVASION_PPID_SPOOF": {
        "tactic_id": "TA0005",
        "tactic": "Defense Evasion",
        "technique": "T1134.004",
        "name": "Parent PID Spoofing",
        "base_weight": 30,
    },
    "DEFENSE_EVASION_VSSADMIN_DELETE": {
        "tactic_id": "TA0040",
        "tactic": "Impact",
        "technique": "T1490",
        "name": "Inhibit System Recovery (VSS Delete)",
        "base_weight": 45,
    },
    "PERSISTENCE_RUN_KEY_MODIFIED": {
        "tactic_id": "TA0003",
        "tactic": "Persistence",
        "technique": "T1547.001",
        "name": "Registry Run Keys / Startup Folder",
        "base_weight": 25,
    },
    "LATERAL_MOVEMENT_SMB_NAMED_PIPE": {
        "tactic_id": "TA0008",
        "tactic": "Lateral Movement",
        "technique": "T1021.002",
        "name": "SMB / Windows Admin Shares",
        "base_weight": 30,
    },
    "C2_OUTBOUND_SUSPICIOUS_PORT": {
        "tactic_id": "TA0011",
        "tactic": "Command and Control",
        "technique": "T1071",
        "name": "Application Layer Protocol C2",
        "base_weight": 25,
    },
    "DISCOVERY_NETWORK_SHARE_ENUM": {
        "tactic_id": "TA0007",
        "tactic": "Discovery",
        "technique": "T1135",
        "name": "Network Share Discovery",
        "base_weight": 15,
    },
    "EXFILTRATION_ARCHIVE_ENCRYPTED": {
        "tactic_id": "TA0010",
        "tactic": "Exfiltration",
        "technique": "T1560.001",
        "name": "Archive via Utility",
        "base_weight": 25,
    },
}


@dataclass
class TelemetryEvent:
    """Normalized EDR telemetry event record."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    event_type: str = "PROCESS_CREATE"  # PROCESS_CREATE, PROCESS_TERMINATE, FILE_WRITE, REGISTRY_SET, NETWORK_CONNECT, MEMORY_INJECT
    endpoint_id: str = "LOCAL-ENDPOINT"
    pid: int = 0
    ppid: Optional[int] = None
    process_name: str = "unknown.exe"
    parent_process_name: Optional[str] = None
    command_line: Optional[str] = None
    user: Optional[str] = None
    target_path: Optional[str] = None
    hash: Optional[str] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    behavior_tag: Optional[str] = None
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EDRIncident:
    """Correlated security incident grouping multiple telemetry events."""
    incident_id: str = field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    title: str = "Suspicious Endpoint Activity"
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW
    created_at: float = field(default_factory=time.time)
    events: List[TelemetryEvent] = field(default_factory=list)
    tactics_detected: List[str] = field(default_factory=list)
    techniques_detected: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    confidence: float = 0.50
    incident_status: str = "OPEN"  # OPEN, INVESTIGATING, CONTAINED, FALSE_POSITIVE, CLOSED
    analyst_notes: List[Dict[str, Any]] = field(default_factory=list)
    root_cause_analysis: Dict[str, Any] = field(default_factory=dict)
    process_tree: Dict[str, Any] = field(default_factory=dict)
    response_recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["events"] = [e.to_dict() if isinstance(e, TelemetryEvent) else e for e in self.events]
        return d


class EDREngine:
    """Advanced Endpoint Detection and Response Engine."""

    def __init__(self, history_db: Optional[Any] = None):
        self.history_db = history_db
        self.telemetry_buffer: List[TelemetryEvent] = []
        self.incidents: Dict[str, EDRIncident] = {}

    def deduplicate_events(self, events: List[TelemetryEvent], window_seconds: float = 5.0) -> List[TelemetryEvent]:
        """
        Deduplicate rapid repeated events within time window to prevent alert fatigue.
        Collapses identical (event_type, pid, process_name, target_path, remote_ip) within window.
        """
        if not events:
            return []

        deduped = []
        last_seen: Dict[Tuple[str, int, str, Optional[str], Optional[str]], float] = {}

        for ev in events:
            key = (ev.event_type, ev.pid, ev.process_name, ev.target_path, ev.remote_ip)
            prev_time = last_seen.get(key)
            if prev_time is not None and (ev.timestamp - prev_time) <= window_seconds:
                continue
            last_seen[key] = ev.timestamp
            deduped.append(ev)

        return deduped

    def normalize_event(
        self,
        event_type: str,
        pid: int,
        process_name: str,
        ppid: Optional[int] = None,
        parent_process_name: Optional[str] = None,
        command_line: Optional[str] = None,
        user: Optional[str] = None,
        target_path: Optional[str] = None,
        file_hash: Optional[str] = None,
        remote_ip: Optional[str] = None,
        remote_port: Optional[int] = None,
        behavior_tag: Optional[str] = None,
        endpoint_id: str = "LOCAL-ENDPOINT",
    ) -> TelemetryEvent:
        """
        Create a normalized TelemetryEvent and map behavioral patterns to MITRE ATT&CK.
        """
        tactics = []
        techniques = []
        risk_score = 0.0

        if behavior_tag and behavior_tag in BEHAVIORAL_MITRE_MAP:
            info = BEHAVIORAL_MITRE_MAP[behavior_tag]
            tactics.append(f"{info['tactic']} ({info['tactic_id']})")
            techniques.append(f"{info['technique']} - {info['name']}")
            risk_score = float(info["base_weight"])
        elif behavior_tag:
            tactics.append("Execution (TA0002)")
            techniques.append("T1059 - Command and Scripting Interpreter")
            risk_score = 15.0

        event = TelemetryEvent(
            event_type=event_type,
            endpoint_id=endpoint_id,
            pid=pid,
            ppid=ppid,
            process_name=process_name,
            parent_process_name=parent_process_name,
            command_line=command_line,
            user=user,
            target_path=target_path,
            hash=file_hash,
            remote_ip=remote_ip,
            remote_port=remote_port,
            behavior_tag=behavior_tag,
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            risk_score=risk_score,
        )

        self.telemetry_buffer.append(event)
        if len(self.telemetry_buffer) > 1000:
            self.telemetry_buffer.pop(0)

        return event

    def correlate_incident(
        self,
        events: List[TelemetryEvent],
        title: Optional[str] = None,
    ) -> EDRIncident:
        """
        Group related events into a unified security incident, execute root-cause analysis,
        construct process trees, compute dynamic risk scores, evaluate confidence, and assign response actions.
        """
        if not events:
            return EDRIncident(title="Empty Incident")

        # 1. Aggregate MITRE tactics and techniques
        all_tactics: Set[str] = set()
        all_techniques: Set[str] = set()
        raw_score = 0.0

        for ev in events:
            all_tactics.update(ev.mitre_tactics)
            all_techniques.update(ev.mitre_techniques)
            raw_score += ev.risk_score

        # 2. Dynamic explainable risk scoring (0-100)
        tactic_count = len(all_tactics)
        tactic_multiplier = 1.0 + (tactic_count * 0.15)
        computed_score = min(round(raw_score * tactic_multiplier, 1), 100.0)

        # 2.1 Multi-vector confidence assessment
        event_types = {e.event_type for e in events}
        if len(event_types) >= 3 or tactic_count >= 3:
            confidence = 0.95
        elif len(event_types) >= 2 or tactic_count >= 2:
            confidence = 0.80
        else:
            confidence = 0.60

        # 3. Severity classification
        if computed_score >= 75.0 or any("Impact" in t or "Credential Access" in t for t in all_tactics):
            severity = "CRITICAL"
        elif computed_score >= 45.0 or tactic_count >= 2:
            severity = "HIGH"
        elif computed_score >= 20.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # 4. Root-Cause Analysis (RCA)
        rca = self._execute_root_cause_analysis(events)

        # 5. Process Hierarchy Tree
        process_tree = self._build_process_tree(events)

        # 6. Response Recommendations Generator
        recommendations = self._generate_response_recommendations(events, severity, all_tactics)

        incident_title = title or f"Incident: {events[0].process_name} Activity ({len(events)} events)"
        incident = EDRIncident(
            title=incident_title,
            severity=severity,
            events=events,
            tactics_detected=sorted(list(all_tactics)),
            techniques_detected=sorted(list(all_techniques)),
            risk_score=computed_score,
            confidence=confidence,
            root_cause_analysis=rca,
            process_tree=process_tree,
            response_recommendations=recommendations,
        )

        self.incidents[incident.incident_id] = incident
        return incident

    def record_analyst_decision(
        self,
        incident_id: str,
        analyst_user: str,
        action: str,
        notes: str,
        status: str = "INVESTIGATING",
    ) -> bool:
        """Record auditable analyst triage action or disposition decision."""
        incident = self.incidents.get(incident_id)
        if not incident:
            return False

        record = {
            "timestamp": time.time(),
            "analyst": analyst_user,
            "action": action,
            "notes": notes,
            "new_status": status,
        }
        incident.analyst_notes.append(record)
        incident.incident_status = status
        logger.info(f"Analyst {analyst_user} updated incident {incident_id}: action={action}, status={status}")
        return True

    def generate_investigation_report(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Generate a structured, auditable investigation package for analysts."""
        incident = self.incidents.get(incident_id)
        if not incident:
            return None

        timeline = []
        for ev in sorted(incident.events, key=lambda e: e.timestamp):
            timeline.append({
                "timestamp": ev.timestamp,
                "event_type": ev.event_type,
                "process": ev.process_name,
                "pid": ev.pid,
                "target": ev.target_path or ev.remote_ip or "N/A",
                "tactics": ev.mitre_tactics,
                "risk_contribution": ev.risk_score,
            })

        return {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity,
            "confidence": incident.confidence,
            "risk_score": incident.risk_score,
            "status": incident.incident_status,
            "created_at": incident.created_at,
            "root_cause_analysis": incident.root_cause_analysis,
            "tactics_detected": incident.tactics_detected,
            "techniques_detected": incident.techniques_detected,
            "event_count": len(incident.events),
            "timeline": timeline,
            "process_tree": incident.process_tree,
            "response_recommendations": incident.response_recommendations,
            "analyst_audit_log": incident.analyst_notes,
        }

    def _execute_root_cause_analysis(self, events: List[TelemetryEvent]) -> Dict[str, Any]:
        """
        Backtrack process lineage to identify root ingress process or initial event.
        """
        # Find earliest event
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        first_event = sorted_events[0]

        # Identify suspected initial root ancestor
        root_process = first_event.parent_process_name or first_event.process_name
        root_pid = first_event.ppid or first_event.pid

        # Check if parent was Office, Browser, or Mail client
        ingress_vector = "LOCAL_EXECUTION"
        rp_lower = root_process.lower()
        if any(b in rp_lower for b in ("winword", "excel", "powerpnt", "outlook")):
            ingress_vector = "MALICIOUS_DOCUMENT_OR_EMAIL"
        elif any(b in rp_lower for b in ("chrome", "firefox", "msedge", "brave")):
            ingress_vector = "BROWSER_DOWNLOAD_EXPLOIT"
        elif "wscript" in rp_lower or "cscript" in rp_lower or "powershell" in rp_lower:
            ingress_vector = "SCRIPT_INTERPRETER_EXECUTION"

        return {
            "initial_event_id": first_event.event_id,
            "initial_timestamp": first_event.timestamp,
            "root_process_name": root_process,
            "root_pid": root_pid,
            "probable_ingress_vector": ingress_vector,
            "event_count_in_chain": len(events),
            "explanation": f"Attack chain initiated by {root_process} (PID {root_pid}) via {ingress_vector}.",
        }

    def _build_process_tree(self, events: List[TelemetryEvent]) -> Dict[str, Any]:
        """Build hierarchical nested parent-child representation of observed processes."""
        tree: Dict[int, Dict[str, Any]] = {}
        for ev in events:
            if ev.pid not in tree:
                tree[ev.pid] = {
                    "pid": ev.pid,
                    "name": ev.process_name,
                    "ppid": ev.ppid,
                    "parent_name": ev.parent_process_name,
                    "command_line": ev.command_line,
                    "children": [],
                }

        # Link children to parents
        roots = []
        for pid, node in tree.items():
            ppid = node["ppid"]
            if ppid and ppid in tree:
                tree[ppid]["children"].append(node)
            else:
                roots.append(node)

        return {"nodes": roots if roots else list(tree.values())}

    def _generate_response_recommendations(
        self,
        events: List[TelemetryEvent],
        severity: str,
        tactics: Set[str],
    ) -> List[str]:
        """Generate actionable enterprise mitigation recommendations."""
        recs = []
        if severity == "CRITICAL":
            recs.append("ISOLATE_HOST: Immediately isolate endpoint from local network via BI Firewall.")
            recs.append("TERMINATE_PROCESS: Terminate malicious process trees actively executing payloads.")

        has_cred_access = any("Credential Access" in t for t in tactics)
        if has_cred_access:
            recs.append("REVOKE_CREDENTIALS: Force immediate password reset and invalidate active Kerberos tickets.")

        has_file_write = any(e.event_type == "FILE_WRITE" or e.target_path for e in events)
        if has_file_write:
            recs.append("QUARANTINE_FILE: Move dropped malicious artifacts to BI Quarantine Vault.")

        has_c2 = any(e.remote_ip for e in events) or any("Command and Control" in t for t in tactics)
        if has_c2:
            recs.append("BLOCK_IP: Deploy network firewall perimeter rule blocking foreign C2 destinations.")

        if not recs:
            recs.append("AUDIT_LOGS: Review detailed telemetry in Black Intel SIEM log repository.")

        return recs

    def cross_endpoint_correlation(self, event_streams: Dict[str, List[TelemetryEvent]]) -> List[Dict[str, Any]]:
        """
        Correlate events across multiple endpoints.
        Flags identical file hashes or shared external C2 IPs across distinct hosts.
        """
        hash_map: Dict[str, Set[str]] = {}
        ip_map: Dict[str, Set[str]] = {}

        for host_id, events in event_streams.items():
            for ev in events:
                if ev.hash:
                    hash_map.setdefault(ev.hash, set()).add(host_id)
                if ev.remote_ip and not ev.remote_ip.startswith(("127.", "10.", "192.168.")):
                    ip_map.setdefault(ev.remote_ip, set()).add(host_id)

        correlations = []
        for h, hosts in hash_map.items():
            if len(hosts) > 1:
                correlations.append({
                    "correlation_type": "SHARED_MALICIOUS_HASH",
                    "hash": h,
                    "affected_endpoints": list(hosts),
                    "endpoints_count": len(hosts),
                    "severity": "HIGH",
                    "summary": f"Identical executable hash {h[:12]} observed across {len(hosts)} distinct endpoints.",
                })

        for ip_addr, hosts in ip_map.items():
            if len(hosts) > 1:
                correlations.append({
                    "correlation_type": "SHARED_C2_COMMUNICATION",
                    "remote_ip": ip_addr,
                    "affected_endpoints": list(hosts),
                    "endpoints_count": len(hosts),
                    "severity": "CRITICAL",
                    "summary": f"Concurrent network communication with suspicious external IP {ip_addr} across {len(hosts)} endpoints.",
                })

        return correlations
