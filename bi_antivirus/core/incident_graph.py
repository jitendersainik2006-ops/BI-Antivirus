"""
BI Antivirus - Enterprise EDR Incident Graph Engine
Correlates security telemetry across multiple protection vectors:
- Process creation and parent-child hierarchy
- Filesystem detections and real-time quarantine actions
- Network socket events and firewall blocks
- USB removable media mount and policy actions
- Application control whitelisting/blacklisting decisions
- Memory exploit & RWX unbacked execution anomalies

Features:
- Structured Incident Graph (Nodes, Edges, Properties)
- Chronological forensic event timeline
- Genuine evidence-backed MITRE ATT&CK technique mapping
- Severity and confidence scoring
- JSON and Markdown SOC forensic export
- Persistent database synchronization
"""

import os
import time
import json
import uuid
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field, asdict
from pathlib import Path

logger = logging.getLogger("BI_IncidentGraph")


@dataclass
class IncidentNode:
    """Represents an entity in the EDR incident graph."""
    node_id: str
    node_type: str  # PROCESS, FILE, NETWORK, DEVICE, MEMORY, POLICY
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentEdge:
    """Represents a directional relationship between two incident entities."""
    source_id: str
    target_id: str
    relation: str  # SPAWNED, DROPPED, ACCESSED, QUARANTINED, BLOCKED, CONNECTED_TO, INJECTED_INTO, MOUNTED
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MitreTechnique:
    """Represents an observable MITRE ATT&CK technique backed by concrete evidence."""
    id: str
    name: str
    tactic: str
    evidence: str
    evidence_type: str = "OBSERVED_FACT"  # OBSERVED_FACT, SUSPICIOUS_INDICATOR, CONFIRMED_DETECTION
    evidence_confidence: float = 1.0
    source_reference: str = "SecurityCore"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)



class EDRIncident:
    """Represents a correlated security incident encompassing nodes, edges, timeline, and tactics."""

    def __init__(
        self,
        incident_id: str,
        title: str,
        severity: str = "MEDIUM",
        confidence: float = 0.5,
        root_entity_id: str = "",
        status: str = "ACTIVE",
    ):
        self.incident_id = incident_id
        self.title = title
        self.severity = severity
        self.confidence = confidence
        self.root_entity_id = root_entity_id
        self.status = status
        self.created_at = time.time()
        self.updated_at = time.time()

        self.nodes: Dict[str, IncidentNode] = {}
        self.edges: List[IncidentEdge] = []
        self.mitre_techniques: List[MitreTechnique] = []
        self.timeline: List[Dict[str, Any]] = []

    def add_node(self, node: IncidentNode) -> None:
        if node.node_id not in self.nodes:
            self.nodes[node.node_id] = node
            self.updated_at = time.time()

    def add_edge(self, edge: IncidentEdge) -> None:
        # Avoid duplicate edges
        for existing in self.edges:
            if (
                existing.source_id == edge.source_id
                and existing.target_id == edge.target_id
                and existing.relation == edge.relation
            ):
                return
        self.edges.append(edge)
        self.updated_at = time.time()

    def add_timeline_event(self, event_type: str, source: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        self.timeline.append({
            "timestamp": time.time(),
            "timestamp_iso": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "event_type": event_type,
            "source": source,
            "message": message,
            "details": details or {},
        })
        self.timeline.sort(key=lambda x: x["timestamp"])
        self.updated_at = time.time()

    def add_mitre_technique(
        self,
        tech_id: str,
        name: str,
        tactic: str,
        evidence: str,
        evidence_type: str = "OBSERVED_FACT",
        evidence_confidence: float = 1.0,
        source_reference: str = "SecurityCore",
    ) -> None:
        for existing in self.mitre_techniques:
            if existing.id == tech_id:
                # Append additional evidence if not present
                if evidence not in existing.evidence:
                    existing.evidence += f" | {evidence}"
                return
        self.mitre_techniques.append(MitreTechnique(
            id=tech_id,
            name=name,
            tactic=tactic,
            evidence=evidence,
            evidence_type=evidence_type,
            evidence_confidence=evidence_confidence,
            source_reference=source_reference,
        ))
        self.updated_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "root_entity_id": self.root_entity_id,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "mitre_techniques": [t.to_dict() for t in self.mitre_techniques],
            "timeline": self.timeline,
        }


class IncidentGraphEngine:
    """Master correlation engine synthesizing security events into an EDR incident graph."""

    # Well-known LOLBins for MITRE T1218 classification
    LOLBINS = {
        "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
        "wmic.exe", "cscript.exe", "wscript.exe", "bitsadmin.exe",
        "installutil.exe", "regasm.exe", "regsvcs.exe",
    }

    def __init__(self, history_db: Optional[Any] = None, max_memory_incidents: int = 500):
        self.history_db = history_db
        self.max_memory_incidents = max_memory_incidents
        self.incidents: Dict[str, EDRIncident] = {}
        # Entity-to-incident index for fast correlation: {entity_key: incident_id}
        self._entity_index: Dict[str, str] = {}

    def _prune_memory_cache(self) -> None:
        """Prune oldest non-active incidents from memory to enforce bounded memory usage."""
        non_active_ids = [iid for iid, inc in self.incidents.items() if inc.status != "ACTIVE"]
        if len(non_active_ids) < 50:
            sorted_all = sorted(self.incidents.items(), key=lambda item: item[1].created_at)
            to_remove = [iid for iid, _ in sorted_all[:50]]
        else:
            to_remove = non_active_ids[:50]

        for iid in to_remove:
            self.incidents.pop(iid, None)

        stale_keys = [k for k, iid in self._entity_index.items() if iid in to_remove]
        for k in stale_keys:
            self._entity_index.pop(k, None)

    def _generate_incident_id(self) -> str:
        date_str = time.strftime("%Y%m%d")
        rand_suffix = uuid.uuid4().hex[:6]
        return f"INC-{date_str}-{rand_suffix}"

    def ingest_event(self, event_type: str, data: Dict[str, Any]) -> str:
        """
        Ingest a security event from any protection subsystem and correlate it into the graph.
        Returns the incident_id associated with this event.
        """
        if len(self.incidents) >= self.max_memory_incidents:
            self._prune_memory_cache()

        # Determine or correlate incident
        incident = self._correlate_incident(event_type, data)

        # Process event by subsystem type
        if event_type == "PROCESS_SPAWN":
            self._handle_process_spawn(incident, data)
        elif event_type in ("THREAT_DETECTED", "FILE_QUARANTINED", "FILE_RESTORED"):
            self._handle_file_threat(incident, event_type, data)
        elif event_type == "RANSOMWARE_ALERT":
            self._handle_ransomware_alert(incident, data)
        elif event_type == "NETWORK_CONNECTION":
            self._handle_network_event(incident, data)
        elif event_type == "USB_DEVICE_EVENT":
            self._handle_usb_event(incident, data)
        elif event_type == "APP_CONTROL_VIOLATION":
            self._handle_app_control(incident, data)
        elif event_type == "MEMORY_EXPLOIT_ALERT":
            self._handle_memory_exploit(incident, data)
        else:
            self._handle_generic_event(incident, event_type, data)

        # Recalculate severity and confidence
        self._score_incident(incident)

        # Sync to persistent database
        self._persist_incident(incident)

        return incident.incident_id

    def _correlate_incident(self, event_type: str, data: Dict[str, Any]) -> EDRIncident:
        """Find an existing related active incident or spawn a new correlated incident."""
        candidate_keys = []

        pid = data.get("pid")
        ppid = data.get("ppid")
        file_path = data.get("file_path")
        drive_letter = data.get("drive_letter")

        if pid:
            candidate_keys.append(f"proc:{pid}")
        if ppid:
            candidate_keys.append(f"proc:{ppid}")
        if file_path:
            candidate_keys.append(f"file:{str(file_path).lower()}")
        if drive_letter:
            candidate_keys.append(f"dev:{str(drive_letter).upper()}")

        # Look up existing active incident
        for k in candidate_keys:
            if k in self._entity_index:
                inc_id = self._entity_index[k]
                if inc_id in self.incidents and self.incidents[inc_id].status == "ACTIVE":
                    incident = self.incidents[inc_id]
                    # Update index with all new candidate keys
                    for ck in candidate_keys:
                        self._entity_index[ck] = incident.incident_id
                    return incident

        # If no match found, create a new incident
        inc_id = self._generate_incident_id()
        root_entity = candidate_keys[0] if candidate_keys else f"event:{event_type}"
        title = self._derive_title(event_type, data)

        incident = EDRIncident(
            incident_id=inc_id,
            title=title,
            severity="MEDIUM",
            confidence=0.5,
            root_entity_id=root_entity,
        )

        self.incidents[inc_id] = incident
        for k in candidate_keys:
            self._entity_index[k] = inc_id

        return incident

    def _derive_title(self, event_type: str, data: Dict[str, Any]) -> str:
        if event_type == "RANSOMWARE_ALERT":
            return f"Ransomware Encryption Activity Detected ({data.get('pattern', 'Burst/Note')})"
        elif event_type == "MEMORY_EXPLOIT_ALERT":
            return f"Memory Exploit / RWX Injection ({data.get('process_name', 'Unknown')})"
        elif event_type == "APP_CONTROL_VIOLATION":
            return f"Application Execution Violation ({Path(data.get('path', 'Unknown')).name})"
        elif event_type in ("THREAT_DETECTED", "FILE_QUARANTINED"):
            return f"Malware Detection: {data.get('threat_name', 'Unknown Threat')}"
        elif event_type == "USB_DEVICE_EVENT":
            return f"Removable Storage Anomaly on Drive {data.get('drive_letter', 'USB')}"
        elif event_type == "PROCESS_SPAWN":
            return f"Suspicious Process Execution: {data.get('process_name', 'Unknown')}"
        return f"Correlated Security Incident: {event_type}"

    def _handle_process_spawn(self, incident: EDRIncident, data: Dict[str, Any]) -> None:
        pid = data.get("pid", 0)
        ppid = data.get("ppid", 0)
        name = data.get("process_name", "unknown.exe")
        cmdline = data.get("cmdline", "")
        proc_node_id = f"proc:{pid}"

        # Child process node
        incident.add_node(IncidentNode(
            node_id=proc_node_id,
            node_type="PROCESS",
            label=f"{name} (PID: {pid})",
            properties={"pid": pid, "ppid": ppid, "cmdline": cmdline, "name": name},
        ))

        # Parent process node and edge
        if ppid > 0:
            parent_node_id = f"proc:{ppid}"
            parent_name = data.get("parent_name", f"parent_{ppid}")
            incident.add_node(IncidentNode(
                node_id=parent_node_id,
                node_type="PROCESS",
                label=f"{parent_name} (PID: {ppid})",
                properties={"pid": ppid, "name": parent_name},
            ))
            incident.add_edge(IncidentEdge(
                source_id=parent_node_id,
                target_id=proc_node_id,
                relation="SPAWNED",
                metadata={"cmdline": cmdline},
            ))

        incident.add_timeline_event(
            event_type="PROCESS_SPAWN",
            source="ProcessMonitor",
            message=f"Process '{name}' (PID: {pid}) spawned by PPID {ppid}.",
            details={"cmdline": cmdline},
        )

        # MITRE ATT&CK Checks
        name_lower = name.lower()
        cmd_lower = cmdline.lower()

        if "powershell" in name_lower:
            is_obfuscated = any(flg in cmd_lower for flg in ("-enc", "-encodedcommand", "downloadstring", "iex", "-w hidden", "-nop"))
            evidence = f"PowerShell execution: {cmdline[:120]}"
            if is_obfuscated:
                evidence += " [Obfuscated / Encoded execution arguments detected]"
            incident.add_mitre_technique(
                "T1059.001",
                "Command and Scripting Interpreter: PowerShell",
                "Execution",
                evidence,
                evidence_type="SUSPICIOUS_INDICATOR" if is_obfuscated else "OBSERVED_FACT",
                evidence_confidence=0.85 if is_obfuscated else 0.60,
                source_reference="Win32.ProcessCreation",
            )

        if name_lower in ("cmd.exe", "conhost.exe") and ("/c" in cmd_lower or "/k" in cmd_lower):
            incident.add_mitre_technique(
                "T1059.003",
                "Command and Scripting Interpreter: Windows Command Shell",
                "Execution",
                f"Command prompt execution: {cmdline[:120]}",
                evidence_type="OBSERVED_FACT",
                evidence_confidence=0.70,
                source_reference="Win32.ProcessCreation",
            )

        if name_lower in self.LOLBINS:
            incident.add_mitre_technique(
                "T1218",
                "System Binary Proxy Execution (LOLBins)",
                "Defense Evasion",
                f"Execution of trusted LOLBin binary '{name}' with args: {cmdline[:120]}",
                evidence_type="SUSPICIOUS_INDICATOR",
                evidence_confidence=0.75,
                source_reference="LOLBinSentinel",
            )

        if any(tool in cmd_lower for tool in ("vssadmin", "wmic shadowcopy", "bcdedit")):
            if "delete" in cmd_lower or "recoveryenabled" in cmd_lower:
                incident.add_mitre_technique(
                    "T1490",
                    "Inhibit System Recovery",
                    "Impact",
                    f"Command attempting backup/shadow-copy deletion: {cmdline[:120]}",
                    evidence_type="CONFIRMED_DETECTION",
                    evidence_confidence=0.95,
                    source_reference="ProcessCreation.CmdlineAnalyzer",
                )

    def _handle_file_threat(self, incident: EDRIncident, event_type: str, data: Dict[str, Any]) -> None:
        file_path = data.get("file_path", "")
        file_node_id = f"file:{str(file_path).lower()}"
        file_name = Path(file_path).name if file_path else "unknown_file"

        incident.add_node(IncidentNode(
            node_id=file_node_id,
            node_type="FILE",
            label=f"{file_name}",
            properties={
                "path": file_path,
                "threat_name": data.get("threat_name", ""),
                "severity": data.get("severity", "HIGH"),
                "hash": data.get("file_hash", ""),
            },
        ))

        pid = data.get("pid")
        if pid:
            proc_node_id = f"proc:{pid}"
            incident.add_edge(IncidentEdge(
                source_id=proc_node_id,
                target_id=file_node_id,
                relation="ACCESSED" if event_type == "THREAT_DETECTED" else "QUARANTINED",
            ))

        action_label = "Quarantined in encrypted vault" if event_type == "FILE_QUARANTINED" else "Threat flagged"
        incident.add_timeline_event(
            event_type=event_type,
            source="ThreatDetector",
            message=f"{action_label}: '{file_name}' ({data.get('threat_name')})",
            details=data,
        )

        # Check for EICAR / known malware
        if "eicar" in str(data.get("threat_name", "")).lower():
            incident.add_mitre_technique(
                "T1204.002",
                "User Execution: Malicious File",
                "Execution",
                f"Standard validation payload detected in {file_name}",
                evidence_type="CONFIRMED_DETECTION",
                evidence_confidence=1.0,
                source_reference="ThreatDetector.SignatureMatch",
            )

    def _handle_ransomware_alert(self, incident: EDRIncident, data: Dict[str, Any]) -> None:
        pattern = data.get("pattern", "RANSOMWARE_MUTATION")
        ext = data.get("extension", "")

        incident.add_timeline_event(
            event_type="RANSOMWARE_ALERT",
            source="RansomwareShield",
            message=f"Ransomware activity flagged: {data.get('message', 'High-frequency file mutations')}",
            details=data,
        )

        incident.add_mitre_technique(
            "T1486",
            "Data Encrypted for Impact",
            "Impact",
            f"Detected rapid mutation burst / extortion note matching ransomware signature ({ext or pattern})",
            evidence_type="CONFIRMED_DETECTION",
            evidence_confidence=0.90,
            source_reference="RansomwareShield.EntropyBurst",
        )

    def _handle_network_event(self, incident: EDRIncident, data: Dict[str, Any]) -> None:
        dest_ip = data.get("dest_ip", "0.0.0.0")
        dest_port = data.get("dest_port", 0)
        proto = data.get("protocol", "TCP")
        net_node_id = f"net:{dest_ip}:{dest_port}"

        incident.add_node(IncidentNode(
            node_id=net_node_id,
            node_type="NETWORK",
            label=f"{dest_ip}:{dest_port} ({proto})",
            properties=data,
        ))

        pid = data.get("pid")
        if pid:
            proc_node_id = f"proc:{pid}"
            incident.add_edge(IncidentEdge(
                source_id=proc_node_id,
                target_id=net_node_id,
                relation="CONNECTED_TO",
            ))

        incident.add_timeline_event(
            event_type="NETWORK_SOCKET",
            source="FirewallMonitor",
            message=f"Outbound network socket opened to {dest_ip}:{dest_port}",
            details=data,
        )

        if dest_port in (80, 443, 8080, 8443):
            # Observable network fact: standard socket opening is an observed fact, not standalone proof of compromise
            incident.add_mitre_technique(
                "T1071.001",
                "Application Layer Protocol: Web Protocols",
                "Command and Control",
                f"Outbound web connection to external IP {dest_ip}:{dest_port} (Observed network socket; non-conclusive alone without corroborating payload)",
                evidence_type="OBSERVED_FACT",
                evidence_confidence=0.60,
                source_reference="FirewallMonitor.SocketQuery",
            )

    def _handle_usb_event(self, incident: EDRIncident, data: Dict[str, Any]) -> None:
        drive = data.get("drive_letter", "USB")
        dev_node_id = f"dev:{drive}"

        incident.add_node(IncidentNode(
            node_id=dev_node_id,
            node_type="DEVICE",
            label=f"Removable Drive ({drive})",
            properties=data,
        ))

        incident.add_timeline_event(
            event_type="USB_EVENT",
            source="USBSentinel",
            message=f"Removable storage activity on drive {drive}: {data.get('action', 'Mounted')}",
            details=data,
        )

        if data.get("threat_found") or data.get("worms_detected"):
            incident.add_mitre_technique(
                "T1091",
                "Replication Through Removable Media",
                "Lateral Movement / Initial Access",
                f"Autorun.inf / LNK worm pattern detected on removable drive {drive}",
                evidence_type="CONFIRMED_DETECTION",
                evidence_confidence=0.95,
                source_reference="USBSentinel",
            )

    def _handle_app_control(self, incident: EDRIncident, data: Dict[str, Any]) -> None:
        file_path = data.get("path", "")
        sha256 = data.get("hash", "")
        decision = data.get("decision", "BLOCKED")
        file_node_id = f"file:{str(file_path).lower()}"

        incident.add_node(IncidentNode(
            node_id=file_node_id,
            node_type="FILE",
            label=f"{Path(file_path).name}",
            properties={"path": file_path, "sha256": sha256, "decision": decision},
        ))

        incident.add_timeline_event(
            event_type="APP_CONTROL",
            source="ApplicationControl",
            message=f"Application execution {decision}: '{Path(file_path).name}' ({data.get('reason')})",
            details=data,
        )

        if decision == "BLOCKED":
            incident.add_mitre_technique(
                "T1204.002",
                "User Execution: Malicious File",
                "Execution",
                f"Execution blocked by application control policy: {Path(file_path).name}",
                evidence_type="CONFIRMED_DETECTION",
                evidence_confidence=1.0,
                source_reference="ApplicationControl",
            )

    def _handle_memory_exploit(self, incident: EDRIncident, data: Dict[str, Any]) -> None:
        pid = data.get("pid", 0)
        proc_name = data.get("process_name", "unknown")
        proc_node_id = f"proc:{pid}"

        incident.add_node(IncidentNode(
            node_id=proc_node_id,
            node_type="PROCESS",
            label=f"{proc_name} (PID: {pid})",
            properties=data,
        ))

        incident.add_timeline_event(
            event_type="MEMORY_EXPLOIT",
            source="ExploitShield",
            message=f"Memory anomaly detected in {proc_name} (PID: {pid}): {', '.join(data.get('findings', []))}",
            details=data,
        )

        if data.get("rwx_regions_count", 0) > 0 or data.get("unbacked_executable_count", 0) > 0:
            # Memory indicator: RWX memory is an anomaly/suspicious indicator, requiring corroborating telemetry
            incident.add_mitre_technique(
                "T1055",
                "Process Injection",
                "Defense Evasion / Privilege Escalation",
                f"Detected {data.get('rwx_regions_count', 0)} RWX memory pages and {data.get('unbacked_executable_count', 0)} unbacked executable code regions in {proc_name} (Suspicious memory indicator; non-conclusive alone without payload corroboration)",
                evidence_type="SUSPICIOUS_INDICATOR",
                evidence_confidence=0.70,
                source_reference="ExploitShield.VirtualQueryEx",
            )

    def _handle_generic_event(self, incident: EDRIncident, event_type: str, data: Dict[str, Any]) -> None:
        incident.add_timeline_event(
            event_type=event_type,
            source=data.get("source", "SecurityCore"),
            message=data.get("message", f"Event {event_type} registered"),
            details=data,
        )

    def _score_incident(self, incident: EDRIncident) -> None:
        """Dynamically compute incident severity and confidence based on correlated evidence."""
        # Confidence calculation
        unique_node_types = {n.node_type for n in incident.nodes.values()}
        unique_sources = {e["source"] for e in incident.timeline}

        # Multi-vector correlation increases confidence
        conf = 0.50 + min(len(unique_node_types) * 0.15, 0.30) + min(len(unique_sources) * 0.05, 0.15)
        incident.confidence = min(conf, 0.99)

        # Severity calculation
        tech_ids = {t.id for t in incident.mitre_techniques}

        if "T1486" in tech_ids or "T1055" in tech_ids or "T1490" in tech_ids:
            incident.severity = "CRITICAL"
        elif "T1059.001" in tech_ids or "T1218" in tech_ids or "T1091" in tech_ids:
            incident.severity = "HIGH"
        elif len(incident.nodes) >= 3 or len(incident.timeline) >= 4:
            incident.severity = "MEDIUM"
        else:
            incident.severity = "LOW"

    def _persist_incident(self, incident: EDRIncident) -> None:
        """Safely record incident into the persistent history database."""
        if not self.history_db or not hasattr(self.history_db, "record_edr_incident"):
            return

        try:
            self.history_db.record_edr_incident(
                incident_id=incident.incident_id,
                title=incident.title,
                severity=incident.severity,
                confidence=incident.confidence,
                root_entity=incident.root_entity_id,
                mitre_techniques=[t.to_dict() for t in incident.mitre_techniques],
                timeline=incident.timeline,
                status=incident.status,
            )
        except Exception as e:
            logger.error(f"Failed persisting EDR incident {incident.incident_id}: {e}", exc_info=True)

    def export_incident_json(self, incident_id: str) -> str:
        """Export canonical JSON representation of the incident for SIEM or external analysis."""
        if incident_id not in self.incidents:
            return json.dumps({"error": f"Incident {incident_id} not found"}, indent=2)
        return json.dumps(self.incidents[incident_id].to_dict(), indent=2)

    def export_incident_markdown(self, incident_id: str) -> str:
        """Generate a complete SOC-grade forensic investigation report in Markdown."""
        if incident_id not in self.incidents:
            return f"# Error\n\nIncident `{incident_id}` was not found."

        inc = self.incidents[incident_id]
        created_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(inc.created_at))
        updated_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(inc.updated_at))

        lines = [
            f"# BI Antivirus EDR Forensic Investigation Report",
            f"**Incident ID:** `{inc.incident_id}`  ",
            f"**Title:** {inc.title}  ",
            f"**Severity:** `{inc.severity}`  ",
            f"**Correlation Confidence:** `{int(inc.confidence * 100)}%`  ",
            f"**Status:** `{inc.status}`  ",
            f"**Root Entity:** `{inc.root_entity_id}`  ",
            f"**Generated At:** {updated_str}  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            f"An endpoint detection and response (EDR) correlation alert was synthesized by BI Antivirus. "
            f"The incident involves **{len(inc.nodes)} correlated entities**, **{len(inc.edges)} relationship edges**, "
            f"and **{len(inc.mitre_techniques)} verified MITRE ATT&CK techniques** across the endpoint telemetry pipeline.",
            "",
            "---",
            "",
            "## 2. MITRE ATT&CK Matrix Alignment",
        ]

        if inc.mitre_techniques:
            lines.append("| Technique ID | Technique Name | Tactic | Evidence Classification | Confidence | Source Reference | Concrete Observable Evidence |")
            lines.append("|---|---|---|---|---|---|---|")
            for t in inc.mitre_techniques:
                clean_ev = t.evidence.replace("|", "/")
                lines.append(
                    f"| `{t.id}` | **{t.name}** | {t.tactic} | `{t.evidence_type}` | {int(t.evidence_confidence * 100)}% | `{t.source_reference}` | {clean_ev} |"
                )
        else:
            lines.append("*(No specific MITRE ATT&CK matrix mappings matched for this baseline event)*")

        lines.extend([
            "",
            "---",
            "",
            "## 3. Chronological Forensic Timeline",
            "| Time (Local) | Source Subsystem | Event Type | Description |",
            "|---|---|---|---|",
        ])

        for ev in inc.timeline:
            time_iso = ev.get("timestamp_iso", time.strftime("%H:%M:%S", time.localtime(ev["timestamp"])))
            src = ev.get("source", "Core")
            etype = ev.get("event_type", "EVENT")
            msg = ev.get("message", "").replace("|", "/")
            lines.append(f"| {time_iso} | `{src}` | `{etype}` | {msg} |")

        lines.extend([
            "",
            "---",
            "",
            "## 4. Entity Graph & Process Tree",
            "### Correlated Entities (Nodes)",
        ])

        for n in inc.nodes.values():
            lines.append(f"- **`{n.node_id}`** (`{n.node_type}`): {n.label}")

        lines.extend([
            "",
            "### Entity Relationships (Edges)",
        ])

        if inc.edges:
            for e in inc.edges:
                lines.append(f"- `{e.source_id}` ──[ **{e.relation}** ]──▶ `{e.target_id}`")
        else:
            lines.append("- *(No inter-process or process-to-file relationships established)*")

        lines.extend([
            "",
            "---",
            "",
            "## 5. Recommended Remediation & Containment Actions",
            "1. **Host Isolation:** If Severity is `CRITICAL`, engage Network Isolation via BI Antivirus Firewall.",
            "2. **Process Termination:** Terminate identified rogue process trees via Application Control sentinel.",
            "3. **Quarantine Audit:** Inspect target files in `📦 Quarantine Vault` and verify HMAC signatures.",
            "4. **Memory Verification:** Run Exploit Shield memory audit on parent and descendant PIDs.",
            "5. **Policy Hardening:** Update Application Control hashes or untrusted directory execution rules.",
            "",
            "---",
            f"*Report generated by BI Antivirus Enterprise EDR Engine — Storage: D:\\bit defender*",
        ])

        return "\n".join(lines)
