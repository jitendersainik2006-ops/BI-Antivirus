"""
BI Antivirus - Automated Test Suite Runner
Executes comprehensive tests across:
- File scanning
- Signature matching
- Hash verification
- False-positive handling
- Quarantine and reversible restore
- Scan history persistence
- Error handling and resilience
"""

import unittest
import sys
from pathlib import Path

# Ensure root path is in sys.path
PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

def run_all_tests():
    print("=" * 70)
    print("      BI ANTIVIRUS - AUTOMATED VALIDATION TEST SUITE")
    print("=" * 70)
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(PROJECT_DIR / "bi_antivirus" / "tests"), pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 70)
    print(f"Tests Run:      {result.testsRun}")
    print(f"Failures:       {len(result.failures)}")
    print(f"Errors:         {len(result.errors)}")
    print(f"Skipped:        {len(result.skipped)}")
    status_str = "SUCCESS (ALL TESTS PASSED)" if result.wasSuccessful() else "FAILED"
    print(f"Overall Status: {status_str}")
    print("=" * 70)

    return 0 if result.wasSuccessful() else 1

if __name__ == "__main__":
    sys.exit(run_all_tests())
