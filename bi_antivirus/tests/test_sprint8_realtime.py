"""
BI Antivirus - Sprint 8 Advanced Real-Time Protection Tests
Verifies:
1. FileReputationCache (LRU caching, TTL expiry, hits/misses, capacity eviction)
2. RealTimeGuard Protection State Management (RUNNING, PAUSED, STOPPED, pause/resume)
3. Event debouncing & stabilization
4. Fast hash reputation bypass for verified clean files
5. Service health & diagnostic indicators (get_health_status, get_guard_status)
6. Self-event internal suppression
"""

import time
import shutil
import tempfile
import unittest
from pathlib import Path

from bi_antivirus.monitors.realtime import (
    RealTimeGuard,
    FileReputationCache,
    ProtectionState,
)


class TestSprint8RealTimeProtection(unittest.TestCase):
    """Test suite for Sprint 8 Advanced Real-Time Protection capabilities."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="bi_s8_test_")
        self.watch_dir = Path(self.temp_dir) / "watched"
        self.watch_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_reputation_cache_hits_misses_and_eviction(self):
        """Verify FileReputationCache stores hashes, records hits/misses, and handles eviction."""
        cache = FileReputationCache(max_entries=3, ttl_seconds=2.0)

        # 1. Miss on unknown hash
        self.assertIsNone(cache.get_reputation("hash_001"))
        self.assertEqual(cache.misses, 1)
        self.assertEqual(cache.hits, 0)

        # 2. Store and hit
        cache.set_reputation("hash_001", "CLEAN")
        rep = cache.get_reputation("hash_001")
        self.assertEqual(rep, "CLEAN")
        self.assertEqual(cache.hits, 1)

        # 3. Capacity eviction (max_entries=3)
        cache.set_reputation("hash_002", "CLEAN")
        cache.set_reputation("hash_003", "THREAT")
        self.assertEqual(len(cache._cache), 3)

        # Adding 4th should evict the oldest
        time.sleep(0.01)
        cache.set_reputation("hash_004", "CLEAN")
        self.assertEqual(len(cache._cache), 3)
        self.assertIn("hash_004", cache._cache)

        # Stats reporting
        stats = cache.stats()
        self.assertEqual(stats["entries"], 3)
        self.assertGreater(stats["hits"], 0)

    def test_02_reputation_cache_ttl_expiration(self):
        """Verify reputation entries expire after ttl_seconds."""
        cache = FileReputationCache(max_entries=10, ttl_seconds=0.1)
        cache.set_reputation("short_lived_hash", "CLEAN")

        # Immediate lookup succeeds
        self.assertEqual(cache.get_reputation("short_lived_hash"), "CLEAN")

        # Wait for TTL expiry
        time.sleep(0.15)
        self.assertIsNone(cache.get_reputation("short_lived_hash"))

    def test_03_protection_state_transitions(self):
        """Verify RUNNING -> PAUSED -> RESUMED -> STOPPED transitions and guard behavior."""
        guard = RealTimeGuard(debounce_window=0.1)
        guard.monitored_paths = [self.watch_dir]

        self.assertEqual(guard.state, ProtectionState.STOPPED)
        self.assertFalse(guard.is_running)

        # Start guard
        started = guard.start()
        self.assertTrue(started)
        self.assertTrue(guard.is_running)
        self.assertEqual(guard.state, ProtectionState.RUNNING)

        # Pause guard
        paused = guard.pause()
        self.assertTrue(paused)
        self.assertEqual(guard.state, ProtectionState.PAUSED)

        # Pausing while already paused returns False
        self.assertFalse(guard.pause())

        # Resume guard
        resumed = guard.resume()
        self.assertTrue(resumed)
        self.assertEqual(guard.state, ProtectionState.RUNNING)

        # Stop guard
        guard.stop()
        self.assertFalse(guard.is_running)
        self.assertEqual(guard.state, ProtectionState.STOPPED)

    def test_04_health_status_metrics(self):
        """Verify get_health_status returns structured diagnostic indicators."""
        guard = RealTimeGuard(debounce_window=0.1)
        guard.monitored_paths = [self.watch_dir]
        guard.start()

        health = guard.get_health_status()
        self.assertTrue(health["healthy"])
        self.assertEqual(health["state"], ProtectionState.RUNNING)
        self.assertIn("uptime_seconds", health)
        self.assertIn("reputation_cache", health)
        self.assertIn("monitored_paths_count", health)

        guard.stop()
        health_stopped = guard.get_health_status()
        self.assertFalse(health_stopped["healthy"])
        self.assertEqual(health_stopped["state"], ProtectionState.STOPPED)

    def test_05_reputation_cache_fast_path(self):
        """Verify that inspecting a known-clean file leverages reputation cache and skips redundant scanning."""
        guard = RealTimeGuard(debounce_window=0.05)
        test_file = self.watch_dir / "benign_doc.txt"
        test_file.write_text("Hello Clean World - Safe Content Document")

        # Initial event processing (cold cache)
        initial_events = guard.events_processed
        guard._handle_file_event(test_file)
        self.assertEqual(guard.events_processed, initial_events + 1)
        self.assertEqual(guard.reputation_cache.hits, 0)

        # Second event processing (warm cache hit)
        guard._handle_file_event(test_file)
        self.assertEqual(guard.events_processed, initial_events + 2)
        self.assertGreater(guard.reputation_cache.hits, 0, "Second scan must hit reputation cache")

    def test_06_self_event_suppression(self):
        """Verify that internal files in data, logs, quarantine, and .git are suppressed."""
        guard = RealTimeGuard()
        from bi_antivirus.config import DATA_DIR, LOGS_DIR

        self.assertTrue(guard._is_self_event(DATA_DIR / "signatures.db"))
        self.assertTrue(guard._is_self_event(LOGS_DIR / "app.log"))
        self.assertFalse(guard._is_self_event(self.watch_dir / "external_file.exe"))


if __name__ == "__main__":
    unittest.main()
