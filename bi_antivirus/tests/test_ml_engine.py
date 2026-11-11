"""
BI Antivirus - Local Machine Learning Inference Engine Tests
Verifies:
- Normalized 12-dimensional feature vector extraction
- Local logistic sigmoid inference and explainable risk factors
- HMAC-SHA256 signature verification and anti-tamper safeguards
- Monotonic versioning and anti-rollback enforcement
- Emergency model rollback to baseline v1
"""

import unittest
import shutil
import json
from pathlib import Path

from bi_antivirus.core.ml_engine import LocalMLEngine, FeatureExtractor, BASELINE_MODEL_V1
from bi_antivirus.config import SCRATCH_DIR


class TestMLEngine(unittest.TestCase):
    """Test suite for Local Machine Learning Inference Engine."""

    def setUp(self):
        self.test_dir = SCRATCH_DIR / "ml_test_dir"
        self.test_dir.mkdir(parents=True, exist_ok=True)
        self.engine = LocalMLEngine(model_dir=self.test_dir)

    def tearDown(self):
        try:
            shutil.rmtree(self.test_dir, ignore_errors=True)
        except Exception:
            pass

    def test_01_baseline_model_loaded(self):
        """Verify baseline ML model is properly loaded and verified."""
        self.assertEqual(self.engine.model_version, 1)
        self.assertEqual(self.engine.model_id, "BI-ML-PE-BASELINE-V1")
        self.assertTrue((self.test_dir / "active_model.json").exists())

    def test_02_feature_extraction_non_pe(self):
        """Verify feature extractor returns neutral vector for non-PE files."""
        extractor = FeatureExtractor()
        non_pe_data = b"Hello world, this is a plain text file, not a portable executable."
        features = extractor.extract_features(data=non_pe_data)
        self.assertEqual(len(features), 12)
        self.assertEqual(features["entropy_total"], 0.0)
        self.assertEqual(features["rwx_section_count"], 0.0)

    def test_03_inference_benign_non_pe(self):
        """Verify ML inference assigns benign verdict and high confidence to non-PE files."""
        pred = self.engine.predict(data=b"Just plain text data.")
        self.assertEqual(pred.verdict, "BENIGN")
        self.assertLess(pred.probability, 0.10)
        self.assertGreater(pred.confidence, 0.90)

    def test_04_synthetic_malicious_pe_prediction(self):
        """Verify that synthetic features with RWX sections and injection APIs produce MALICIOUS verdict."""
        mock_pe_info = {
            "is_pe": True,
            "overall_entropy": 7.5,
            "sections": [
                {"entropy": 7.8, "raw_size": 2048, "virtual_size": 10000, "is_rwx": True},
                {"entropy": 7.1, "raw_size": 4096, "virtual_size": 4096, "is_rwx": False},
            ],
            "has_packer_sections": True,
            "mitigations": {"dep": False, "aslr": False, "cfg": False},
            "suspicious_apis_by_category": {
                "PROCESS_INJECTION": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                "NETWORK_C2": ["InternetOpenA", "HttpSendRequestA"],
                "RANSOMWARE_CRYPTO": ["CryptEncrypt"],
            },
            "has_overlay": True,
            "data_directories": {"SECURITY": {"present": False}},
        }
        pred = self.engine.predict(pe_info=mock_pe_info)
        self.assertIn(pred.verdict, ("MALICIOUS", "SUSPICIOUS"))
        self.assertGreater(pred.probability, 0.70)
        self.assertGreater(len(pred.top_contributing_features), 0)

    def test_05_monotonic_version_upgrade(self):
        """Verify model upgrade requires monotonic version increment and valid HMAC signature."""
        new_model = dict(BASELINE_MODEL_V1)
        new_model["version"] = 2
        new_model["model_id"] = "BI-ML-PE-V2-EXPANDED"
        sig = self.engine._compute_model_signature(new_model)
        new_model["hmac_signature"] = sig

        success, msg = self.engine.update_model(new_model)
        self.assertTrue(success, msg)
        self.assertEqual(self.engine.model_version, 2)
        self.assertEqual(self.engine.model_id, "BI-ML-PE-V2-EXPANDED")

    def test_06_anti_rollback_version_rejection(self):
        """Verify that an incoming model with version <= current active version is rejected."""
        lower_model = dict(BASELINE_MODEL_V1)
        lower_model["version"] = 1  # Version 1 is <= current version (1)
        lower_model["hmac_signature"] = self.engine._compute_model_signature(lower_model)

        success, msg = self.engine.update_model(lower_model)
        self.assertFalse(success)
        self.assertIn("Anti-rollback rejection", msg)

    def test_07_tampered_model_signature_rejection(self):
        """Verify that tampered weights or invalid HMAC signature is rejected."""
        tampered_model = dict(BASELINE_MODEL_V1)
        tampered_model["version"] = 3
        tampered_model["bias"] = 10.0  # Tampered bias
        tampered_model["hmac_signature"] = "00112233445566778899aabbccddeeff"

        success, msg = self.engine.update_model(tampered_model)
        self.assertFalse(success)
        self.assertIn("integrity check failed", msg)

    def test_08_emergency_rollback(self):
        """Verify emergency rollback reverts active model to baseline v1."""
        # Upgrade to v2 first
        v2 = dict(BASELINE_MODEL_V1)
        v2["version"] = 2
        v2["hmac_signature"] = self.engine._compute_model_signature(v2)
        self.engine.update_model(v2)
        self.assertEqual(self.engine.model_version, 2)

        # Rollback
        success, msg = self.engine.rollback_model()
        self.assertTrue(success, msg)
        self.assertEqual(self.engine.model_version, 1)


if __name__ == "__main__":
    unittest.main()
