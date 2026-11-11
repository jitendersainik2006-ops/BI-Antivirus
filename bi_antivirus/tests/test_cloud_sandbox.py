"""
BI Antivirus - Cloud Sandbox Abstraction Tests
Verifies:
- Standard enterprise sandbox submission contract
- Local deterministic simulation provider
- Status polling and report retrieval
- Fallback behavior when remote cloud is unconfigured
- Diagnostic capability disclosure (LOCAL_SIMULATION vs REMOTE_CLOUD)
"""

import unittest
from bi_antivirus.enterprise.cloud_sandbox import (
    CloudSandboxClient,
    LocalSimulationSandboxProvider,
    SandboxSubmissionTicket,
    SandboxAnalysisReport,
)


class TestCloudSandbox(unittest.TestCase):
    """Test suite for Cloud Sandbox abstraction and local simulation provider."""

    def setUp(self):
        self.provider = LocalSimulationSandboxProvider()
        self.client = CloudSandboxClient(fallback_local=True)

    def test_01_local_provider_submission_and_report(self):
        """Verify local simulation provider accepts sample and returns structured report."""
        sample_bytes = b"MZ\x90\x00... harmless binary containing VirtualAlloc and connect test bytes"
        ticket = self.provider.submit(data=sample_bytes, file_name="suspect_sample.bin")
        self.assertIsInstance(ticket, SandboxSubmissionTicket)
        self.assertEqual(ticket.provider_type, "LOCAL_SIMULATION")

        report = self.provider.poll_status(ticket.ticket_id)
        self.assertIsInstance(report, SandboxAnalysisReport)
        self.assertEqual(report.status, "COMPLETED")
        self.assertIn(report.verdict, ("CLEAN", "SUSPICIOUS", "MALICIOUS"))
        self.assertGreaterEqual(report.threat_score, 0)
        self.assertLessEqual(report.threat_score, 100)

    def test_02_client_truthful_fallback_mode(self):
        """Verify client correctly reports unconfigured cloud and routes to local simulation."""
        self.assertFalse(self.client.is_cloud_configured)
        ticket = self.client.submit_sample(data=b"Test benign sample", file_name="calc.exe")
        self.assertEqual(ticket.provider_type, "LOCAL_SIMULATION")

        report = self.client.get_analysis_report(ticket.ticket_id)
        self.assertEqual(report.status, "COMPLETED")
        self.assertEqual(report.provider_name, "LOCAL_SIMULATION_ENGINE")

    def test_03_synthetic_ioc_generation_on_suspicious_primitives(self):
        """Verify sample with suspicious Win32 API calls triggers dynamic IOC detection."""
        suspicious_bytes = b"Payload sample: VirtualAlloc CreateRemoteThread CryptEncrypt"
        ticket = self.provider.submit(data=suspicious_bytes, file_name="dropper.bin")
        report = self.provider.poll_status(ticket.ticket_id)
        self.assertGreaterEqual(report.threat_score, 70)
        self.assertEqual(report.verdict, "MALICIOUS")
        self.assertGreater(len(report.behavioral_iocs), 0)
        self.assertTrue(any("T1055" in t for t in report.mitre_techniques))


if __name__ == "__main__":
    unittest.main()
