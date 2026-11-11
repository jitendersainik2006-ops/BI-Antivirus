"""
BI Antivirus - Sprint 11 Enterprise Scalability & Fleet Management Tests
Verifies:
1. Multi-endpoint registration and inventory counting (count_endpoints)
2. High-volume pagination and multi-attribute filtering (limit, offset)
3. Zero-lock atomic online database backup (backup_database)
4. Safe online database restore and disaster recovery (restore_database)
"""

import time
import shutil
import tempfile
import unittest
from pathlib import Path

from bi_antivirus.enterprise.fleet_database import FleetDatabase
from bi_antivirus.enterprise.fleet_models import EndpointDevice


class TestSprint11EnterpriseScalability(unittest.TestCase):
    """Test suite for Sprint 11 Enterprise Management and Scalability."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="bi_s11_test_")
        self.db_path = Path(self.temp_dir) / "test_fleet.db"
        self.backup_path = Path(self.temp_dir) / "backup_fleet.db"
        self.db = FleetDatabase(db_path=self.db_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_endpoint_pagination_and_counting(self):
        """Verify endpoint registration, total counting, and limit/offset pagination."""
        # Register 12 test endpoints
        for i in range(12):
            dev = EndpointDevice(
                id=f"EP-{i:03d}",
                hostname=f"WORKSTATION-{i:03d}",
                ip_address=f"10.0.1.{10 + i}",
                os_version="Windows 11 Pro",
                agent_version="2.4.0",
                last_seen=time.time(),
                health_status="HEALTHY" if i % 2 == 0 else "AT_RISK",
                assigned_policy_id="POL-DEFAULT",
                department="Finance" if i < 6 else "Engineering",
                registered_at=time.time(),
            )
            self.db.register_endpoint(dev)

        # Count total
        self.assertEqual(self.db.count_endpoints(), 12)
        self.assertEqual(self.db.count_endpoints(health_status="HEALTHY"), 6)
        self.assertEqual(self.db.count_endpoints(department="Finance"), 6)

        # Page 1 (limit=5, offset=0)
        page1 = self.db.list_endpoints(limit=5, offset=0)
        self.assertEqual(len(page1), 5)
        self.assertEqual(page1[0].hostname, "WORKSTATION-000")

        # Page 2 (limit=5, offset=5)
        page2 = self.db.list_endpoints(limit=5, offset=5)
        self.assertEqual(len(page2), 5)
        self.assertEqual(page2[0].hostname, "WORKSTATION-005")

        # Page 3 (limit=5, offset=10)
        page3 = self.db.list_endpoints(limit=5, offset=10)
        self.assertEqual(len(page3), 2)
        self.assertEqual(page3[0].hostname, "WORKSTATION-010")

    def test_02_online_database_backup_and_restore(self):
        """Verify atomic online database backup and safe disaster restore."""
        # 1. Populate DB
        for i in range(5):
            dev = EndpointDevice(
                id=f"BACKUP-EP-{i}",
                hostname=f"HOST-BACKUP-{i}",
                ip_address=f"192.168.1.{20 + i}",
                os_version="Windows 11 Enterprise",
                agent_version="2.4.0",
                last_seen=time.time(),
                registered_at=time.time(),
            )
            self.db.register_endpoint(dev)

        self.assertEqual(self.db.count_endpoints(), 5)

        # 2. Perform online backup
        ok_backup, msg_backup = self.db.backup_database(self.backup_path)
        self.assertTrue(ok_backup, msg_backup)
        self.assertTrue(self.backup_path.exists())

        # 3. Simulate disaster: delete endpoints in primary DB
        for i in range(5):
            self.db.delete_endpoint(f"BACKUP-EP-{i}")
        self.assertEqual(self.db.count_endpoints(), 0)

        # 4. Perform online restore from backup
        ok_restore, msg_restore = self.db.restore_database(self.backup_path)
        self.assertTrue(ok_restore, msg_restore)

        # 5. Verify restored state
        self.assertEqual(self.db.count_endpoints(), 5)
        ep = self.db.get_endpoint("BACKUP-EP-0")
        self.assertIsNotNone(ep)
        self.assertEqual(ep.hostname, "HOST-BACKUP-0")


if __name__ == "__main__":
    unittest.main()
