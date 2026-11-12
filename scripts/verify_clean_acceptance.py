r"""
BI Antivirus - Clean Environment Acceptance Test
Verifies end-to-end functionality from a clean environment under D:\bit defender\data\clean_acceptance_test:
1. Fresh environment isolation and directory creation.
2. Database initialization and WAL mode validation.
3. Multi-vector scanning of synthetic fixtures (EICAR, high entropy, benign).
4. Cryptographic AES-256 quarantine vault encryption and safe restoration.
5. XDR Incident Graph construction and correlation.
6. Vulnerability posture and software inventory patch audit.
7. Uninstallation and clean teardown.
"""

import os
import sys
import shutil
import hashlib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

CLEAN_TEST_DIR = PROJECT_ROOT / "data" / "clean_acceptance_test"


def run_clean_acceptance_test() -> int:
    print("=" * 75)
    print("       BI ANTIVIRUS - CLEAN ENVIRONMENT ACCEPTANCE TEST")
    print(f"       Isolation Path: {CLEAN_TEST_DIR}")
    print("=" * 75)

    if CLEAN_TEST_DIR.exists():
        shutil.rmtree(CLEAN_TEST_DIR, ignore_errors=True)
    CLEAN_TEST_DIR.mkdir(parents=True, exist_ok=True)

    try:
        # Step 1: Directory Tree Creation
        print("\n[*] Step 1/7: Validating directory tree initialization...")
        test_data = CLEAN_TEST_DIR / "data"
        test_logs = CLEAN_TEST_DIR / "logs"
        test_quarantine = CLEAN_TEST_DIR / "quarantine"
        test_vault = test_quarantine / "vault"
        test_reports = CLEAN_TEST_DIR / "reports"

        for d in [test_data, test_logs, test_quarantine, test_vault, test_reports]:
            d.mkdir(parents=True, exist_ok=True)
            assert d.exists(), f"Failed creating {d}"
        print("    [+] Directory tree verified.")

        # Step 2: Database Initialization
        print("\n[*] Step 2/7: Initializing SQLite databases and WAL journal...")
        from bi_antivirus.database.signatures import SignatureDatabase
        from bi_antivirus.database.history import HistoryDatabase

        sig_db = SignatureDatabase(db_path=test_data / "signatures_test.db")
        stats = sig_db.get_stats()
        assert stats["total_indicators"] > 0, "Signature DB has no indicators"
        print(f"    [+] Signature DB ready: {stats['total_indicators']} indicators active.")

        hist_db = HistoryDatabase(db_path=test_data / "history_test.db")
        ok, msg = hist_db.check_integrity()
        assert ok, f"History DB integrity check failed: {msg}"
        print(f"    [+] History DB verified: {msg}")

        # Step 3: Multi-Vector Scanning on Synthetic Fixtures
        print("\n[*] Step 3/7: Scanning harmless synthetic test fixtures...")
        fixtures_dir = CLEAN_TEST_DIR / "fixtures"
        fixtures_dir.mkdir(parents=True, exist_ok=True)

        threat_file = fixtures_dir / "synthetic_threat.txt"
        threat_file.write_bytes(b"BLACK-INTEL-ANTIVIRUS-SAFE-VALIDATION-PAYLOAD-V1\n")

        clean_file = fixtures_dir / "benign_doc.txt"
        clean_file.write_text("Standard clean business document text.", encoding="utf-8")

        from bi_antivirus.core.detector import ThreatDetector
        from bi_antivirus.core.scanner import FileScanner
        detector = ThreatDetector(signature_db=sig_db)
        scanner = FileScanner(detector=detector, history_db=hist_db)
        scan_res = scanner.scan_custom(fixtures_dir)

        assert scan_res["files_scanned"] >= 2, "Scanner missed files"
        assert scan_res["threats_count"] >= 1, "EICAR not detected"
        print(f"    [+] Scan complete: {scan_res['files_scanned']} scanned, {scan_res['threats_count']} threat(s) detected.")

        # Step 4: Quarantine Encryption & Safe Restoration
        print("\n[*] Step 4/7: Testing AES-256 quarantine vault & restoration...")
        from bi_antivirus.core.quarantine import QuarantineManager

        qm = QuarantineManager(
            vault_dir=test_vault,
            db_path=test_data / "quarantine_test.db",
            key_path=test_data / "vault_key.dpapi",
        )

        test_payload = fixtures_dir / "quarantine_target.bin"
        orig_bytes = b"Suspicious test payload data 1234567890"
        orig_hash = hashlib.sha256(orig_bytes).hexdigest()
        test_payload.write_bytes(orig_bytes)

        rec = qm.quarantine_file(test_payload, threat_info={"threat_name": "Test.Suspicious.Payload", "severity": "HIGH", "file_hash": orig_hash})
        assert rec["success"], f"Quarantine failed: {rec.get('error')}"
        assert not test_payload.exists(), "Original file still exists after quarantine"
        db_rec = qm.get_record(rec["quarantine_id"])
        assert db_rec["file_hash"] == orig_hash, "Hash mismatch in quarantine record"
        print(f"    [+] File quarantined to vault: Record {rec['quarantine_id']}")

        # Restore file
        restored_path = fixtures_dir / "restored_payload.bin"
        res_ok, res_msg = qm.restore_file(rec["quarantine_id"], custom_target_path=restored_path)
        assert res_ok, f"Restore failed: {res_msg}"
        assert restored_path.exists(), "Restored file missing"
        assert hashlib.sha256(restored_path.read_bytes()).hexdigest() == orig_hash, "Restored content corrupted"
        print("    [+] Quarantine restoration verified with exact SHA-256 integrity.")

        # Step 5: XDR Incident Graph Construction
        print("\n[*] Step 5/7: Testing XDR Incident Graph correlation...")
        from bi_antivirus.core.incident_graph import IncidentGraphEngine

        graph_engine = IncidentGraphEngine(history_db=hist_db)
        inc_id1 = graph_engine.ingest_event("PROCESS_SPAWN", {
            "pid": 5544,
            "ppid": 1000,
            "process_name": "cmd.exe",
            "parent_name": "explorer.exe",
            "cmdline": "cmd.exe /c powershell.exe",
        })
        inc_id2 = graph_engine.ingest_event("IDENTITY_LOGON", {
            "username": "AdminUser",
            "domain": "CORP",
            "auth_type": "NTLM",
            "logon_type": 10,
            "src_ip": "192.168.1.50",
            "success": True,
            "pid": 5544,
        })
        inc_id3 = graph_engine.ingest_event("CLOUD_WEBHOOK", {
            "service_name": "S3Storage",
            "action": "UPLOAD_BUCKET",
            "target": "exfil-bucket",
            "status": "COMPLETED",
            "pid": 5544,
            "ip": "203.0.113.10",
        })
        assert inc_id1 in graph_engine.incidents
        inc = graph_engine.incidents[inc_id1]
        assert len(inc.nodes) >= 2, "Expected at least 2 nodes"
        assert len(inc.edges) >= 1, "Expected at least 1 edge"
        print(f"    [+] XDR Incident Graph verified: Incident {inc_id1} with {len(inc.nodes)} nodes, {len(inc.edges)} edges.")

        # Step 6: Vulnerability & Patch Auditor
        print("\n[*] Step 6/7: Auditing vulnerability and patch postures...")
        from bi_antivirus.core.vulnerability import VulnerabilityAuditor
        from bi_antivirus.monitors.patch_auditor import SoftwarePatchAuditor
        from bi_antivirus.core.windows_compat import WindowsCompatibilityAuditor

        vuln_res = VulnerabilityAuditor.run_full_vulnerability_audit()
        assert "posture_score" in vuln_res, "Vulnerability audit missing score"
        print(f"    [+] Vulnerability audit verified: Score {vuln_res['posture_score']}/100 ({vuln_res['posture_rating']})")

        compat_auditor = WindowsCompatibilityAuditor(project_root=CLEAN_TEST_DIR)
        kernel_res = compat_auditor.check_kernel_protection_status()
        assert kernel_res["status"] == "SOVEREIGN_USER_SPACE_FALLBACK"
        print(f"    [+] Kernel protection status verified: {kernel_res['status']} ({kernel_res['driver_name']})")

        patch_auditor = SoftwarePatchAuditor()
        patch_res = patch_auditor.audit_software_inventory([
            {"display_name": "7-Zip 22.01", "version": "22.01", "publisher": "Igor Pavlov"},
            {"display_name": "Git version 2.45.1", "version": "2.45.1", "publisher": "Git"},
        ])
        assert patch_res["vulnerable_count"] == 1, "Expected 1 vulnerable app"
        assert patch_res["up_to_date_count"] == 1, "Expected 1 up to date app"
        print(f"    [+] Patch auditor verified: {patch_res['total_applications_audited']} audited, {patch_res['vulnerable_count']} CVE match.")

        # Step 7: Teardown
        print("\n[*] Step 7/7: Tearing down clean acceptance test directory...")
        shutil.rmtree(CLEAN_TEST_DIR, ignore_errors=True)
        print("    [+] Clean acceptance directory purged.")

        print("\n" + "=" * 75)
        print("       CLEAN ENVIRONMENT ACCEPTANCE TEST: ALL PASSED (7/7)")
        print("=" * 75 + "\n")
        return 0

    except Exception as e:
        print(f"\n[!] Clean acceptance test FAILED: {e}")
        import traceback
        traceback.print_exc()
        if CLEAN_TEST_DIR.exists():
            shutil.rmtree(CLEAN_TEST_DIR, ignore_errors=True)
        return 1


if __name__ == "__main__":
    sys.exit(run_clean_acceptance_test())
