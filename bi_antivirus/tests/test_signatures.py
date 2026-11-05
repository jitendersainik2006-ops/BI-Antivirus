"""
Test Suite: Malware Signature Database and Rules
"""

import unittest
from pathlib import Path
from bi_antivirus.database.signatures import SignatureDatabase, EICAR_SHA256, EICAR_PLAIN

class TestSignatureDatabase(unittest.TestCase):

    def setUp(self):
        # Use an in-memory or dedicated test db
        test_db_path = Path(r"D:\bit defender\data\test_signatures.db")
        self.sig_db = SignatureDatabase(db_path=test_db_path)

    def test_eicar_hash_lookup(self):
        result = self.sig_db.lookup_hash(EICAR_SHA256)
        self.assertIsNotNone(result)
        self.assertEqual(result["threat_family"], "TestVirus")
        self.assertEqual(result["severity"], "CRITICAL")

    def test_eicar_pattern_matching(self):
        test_payload = EICAR_PLAIN.encode("utf-8")
        matches = self.sig_db.match_patterns(test_payload)
        self.assertTrue(len(matches) > 0)
        self.assertEqual(matches[0]["rule_name"], "RULE_EICAR_EXACT")

    def test_ransom_heuristic_pattern(self):
        payload = b"Notice: vssadmin delete shadows /all /quiet and your files are encrypted"
        matches = self.sig_db.match_patterns(payload)
        rule_names = [m["rule_name"] for m in matches]
        self.assertIn("RULE_RANSOM_SHADOW_DELETE", rule_names)

    def test_web_reputation_lookup(self):
        rep = self.sig_db.lookup_domain("phishing-bank-update.test")
        self.assertIsNotNone(rep)
        self.assertEqual(rep["severity"], "CRITICAL")

        clean = self.sig_db.lookup_domain("legitimate-example-domain.org")
        self.assertIsNone(clean)

    def test_json_export_and_import(self):
        exported = self.sig_db.export_signatures_json()
        self.assertIn("hashes", exported)
        self.assertIn("patterns", exported)
        imported_count = self.sig_db.import_signatures_json(exported)
        self.assertGreater(imported_count, 0)

if __name__ == "__main__":
    unittest.main()
