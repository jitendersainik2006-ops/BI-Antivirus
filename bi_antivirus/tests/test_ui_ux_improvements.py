"""
BI Antivirus - UI/UX Improvement Verification Test Suite
Validates the refined 7-section navigation architecture, beginner-friendly screens,
scan progress controls, quarantine empty states, and technical protections.
"""

import os
import sys
import time
import unittest
from pathlib import Path

# Ensure root path is in sys.path
PROJECT_DIR = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

import tkinter as tk
from bi_antivirus.core.engine import AntivirusEngine
from bi_antivirus.ui.dashboard import AntivirusDashboard
from bi_antivirus.ui.views import (
    OverviewView,
    ScanView,
    QuarantineView,
    HistoryView,
    ProtectionView,
    SettingsView,
    AboutView,
)


class TestUIUXImprovements(unittest.TestCase):
    """Automated test suite verifying user-friendly UI/UX improvements."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.root = tk.Tk()
            cls.root.withdraw()
            cls.tk_available = True
        except Exception:
            cls.tk_available = False

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "tk_available", False) and hasattr(cls, "root"):
            try:
                cls.root.destroy()
            except Exception:
                pass

    def setUp(self):
        if not self.tk_available:
            self.skipTest("Tkinter display not available in headless test runner")
        self.engine = AntivirusEngine()
        self.engine.initialize()

    def test_01_dashboard_navigation_structure(self):
        """Verify AntivirusDashboard exposes exactly the 7 clean top-level navigation sections."""
        app = AntivirusDashboard(engine=self.engine)
        app.withdraw()

        expected_nav = ["dashboard", "scan", "quarantine", "history", "protection", "settings", "about"]
        self.assertEqual(list(app.nav_buttons.keys()), expected_nav)

        # Verify all views exist and are registered
        for k in expected_nav:
            self.assertIn(k, app.views)

        app.destroy()

    def test_02_dashboard_view_swapping(self):
        """Verify seamless view swapping across all primary and embedded views."""
        app = AntivirusDashboard(engine=self.engine)
        app.withdraw()

        test_views = ["dashboard", "scan", "quarantine", "history", "protection", "settings", "about", "firewall", "edr", "reports"]
        for view_key in test_views:
            app.show_view(view_key)
            self.assertEqual(app.current_view_key, view_key)
            active_frame = app.views[view_key]
            self.assertTrue(active_frame.winfo_ismapped() or active_frame.winfo_exists())

        app.destroy()

    def test_03_overview_view_ux_components(self):
        """Verify OverviewView displays hero banner, quick scan button, stat cards, and navigation shortcuts."""
        view = OverviewView(
            self.root,
            engine=self.engine,
            on_start_quick_scan=lambda: None,
            on_start_full_scan=lambda: None,
            on_start_custom_scan=lambda p: None,
            on_navigate=lambda t: None,
        )

        # Hero Banner
        self.assertTrue(hasattr(view, "shield"))
        self.assertTrue(hasattr(view, "status_title"))
        self.assertTrue(hasattr(view, "status_desc"))
        self.assertTrue(hasattr(view, "btn_hero_quick_scan"))
        self.assertTrue(bool(view.btn_hero_quick_scan.cget("command")))

        # Metric Stat Cards
        self.assertTrue(hasattr(view, "card_signatures"))
        self.assertTrue(hasattr(view, "card_scanned"))
        self.assertTrue(hasattr(view, "card_threats"))
        self.assertTrue(hasattr(view, "card_vault"))

        # Quick Navigation Shortcuts
        self.assertTrue(hasattr(view, "btn_nav_quarantine"))
        self.assertTrue(hasattr(view, "btn_nav_protection"))
        self.assertTrue(hasattr(view, "btn_nav_history"))
        self.assertTrue(hasattr(view, "btn_nav_settings"))

        # Backward-compatible diagnostics buttons
        self.assertTrue(hasattr(view, "btn_system_diag"))
        self.assertTrue(hasattr(view, "btn_priv_details"))

        # Refresh data execution
        view.refresh_data()
        self.assertIn("YOU ARE PROTECTED", view.status_title.cget("text"))

    def test_04_scan_view_launchers_and_progress(self):
        """Verify ScanView provides direct scan launchers, progress updates, and completion summaries."""
        view = ScanView(
            self.root,
            engine=self.engine,
            on_start_quick_scan=lambda: None,
            on_start_full_scan=lambda: None,
            on_start_custom_scan=lambda p: None,
        )

        # Launch buttons
        self.assertTrue(hasattr(view, "btn_run_quick"))
        self.assertTrue(hasattr(view, "btn_run_full"))
        self.assertTrue(hasattr(view, "btn_run_custom"))
        self.assertTrue(hasattr(view, "btn_cancel"))
        self.assertTrue(hasattr(view, "btn_quarantine"))

        # Progress reporting
        progress_data_running = {
            "is_scanning": True,
            "scan_type": "Quick",
            "files_scanned": 150,
            "threats_count": 0,
            "current_file": "C:\\Windows\\System32\\test.dll",
            "elapsed_seconds": 2.5,
            "scan_rate_fps": 60.0,
        }
        view.update_progress(progress_data_running)
        self.assertIn("150", view.metric_scanned.cget("text"))
        self.assertTrue(view.current_file_lbl.cget("text").startswith("Scanning: "))

        # Completion reporting
        progress_data_complete = {
            "is_scanning": False,
            "scan_type": "Quick",
            "files_scanned": 200,
            "threats_count": 0,
            "current_file": "",
            "elapsed_seconds": 3.2,
            "scan_rate_fps": 62.5,
        }
        view.update_progress(progress_data_complete)
        self.assertIn("Scan complete", view.current_file_lbl.cget("text"))
        self.assertIn("No Threats Found", view.summary_title.cget("text"))

    def test_05_quarantine_view_empty_state_and_actions(self):
        """Verify QuarantineView displays encrypted status, empty states, and confirmed actions."""
        view = QuarantineView(self.root, engine=self.engine)

        self.assertTrue(hasattr(view, "vault_status_badge"))
        self.assertTrue(hasattr(view, "empty_card"))
        self.assertTrue(hasattr(view, "btn_restore"))
        self.assertTrue(hasattr(view, "btn_restore_to"))
        self.assertTrue(hasattr(view, "btn_purge"))
        self.assertTrue(hasattr(view, "btn_verify"))
        self.assertTrue(hasattr(view, "btn_refresh"))

        # Refresh vault status
        view.refresh_data()
        self.assertTrue("ITEM" in view.vault_status_badge.cget("text"))

        # Verify underlying integrity check
        audit = self.engine.quarantine_mgr.verify_vault_integrity()
        self.assertTrue(audit.get("all_healthy", False))

    def test_06_history_view_structure(self):
        """Verify HistoryView renders audit table, empty states, and refresh controls."""
        view = HistoryView(self.root, engine=self.engine)

        self.assertTrue(hasattr(view, "tree"))
        self.assertTrue(hasattr(view, "empty_card"))
        self.assertTrue(hasattr(view, "btn_refresh"))

        view.refresh_data()
        # Should populate or show empty state cleanly
        self.assertTrue(view.tree.winfo_exists())

    def test_07_protection_view_notebook_tabs(self):
        """Verify ProtectionView organizes defenses into Real-Time, Firewall, EDR, and Reports tabs."""
        view = ProtectionView(self.root, engine=self.engine)

        self.assertTrue(hasattr(view, "notebook"))
        tab_names = [view.notebook.tab(i, "text") for i in range(view.notebook.index("end"))]
        self.assertEqual(len(tab_names), 4)

        # Tab 1 widgets
        self.assertTrue(hasattr(view, "rt_status_lbl"))
        self.assertTrue(hasattr(view, "btn_toggle_rt"))
        self.assertTrue(hasattr(view, "folders_listbox"))
        self.assertTrue(hasattr(view, "url_entry"))

        view.refresh_data()
        self.assertIn("ACTIVE", view.rt_status_lbl.cget("text"))

    def test_08_settings_view_notebook_tabs(self):
        """Verify SettingsView organizes options into General, Exclusions, Updates, and Advanced tabs."""
        view = SettingsView(self.root, engine=self.engine, on_navigate=lambda t: None)

        self.assertTrue(hasattr(view, "notebook"))
        tab_names = [view.notebook.tab(i, "text") for i in range(view.notebook.index("end"))]
        self.assertEqual(len(tab_names), 4)

        # Tab 1: General
        self.assertTrue(hasattr(view, "var_heuristics"))
        self.assertTrue(hasattr(view, "var_auto_q"))

        # Tab 2: Exclusions
        self.assertTrue(hasattr(view, "excl_listbox"))

        # Tab 3: Updates
        self.assertTrue(hasattr(view, "upd_info_lbl"))
        self.assertTrue(hasattr(view, "btn_chk_upd"))

        # Tab 4: Advanced
        self.assertTrue(hasattr(view, "btn_chk_db"))
        self.assertTrue(hasattr(view, "btn_backup_db"))
        self.assertTrue(hasattr(view, "btn_test_siem"))

        view.refresh_data()

    def test_09_about_view_presentation(self):
        """Verify AboutView presents engine version, security architecture, and system health."""
        view = AboutView(self.root, engine=self.engine)

        self.assertTrue(hasattr(view, "btn_check_health"))
        self.assertTrue(hasattr(view, "btn_quick_tips"))
        self.assertTrue(bool(view.btn_check_health.cget("command")))
        self.assertTrue(bool(view.btn_quick_tips.cget("command")))


if __name__ == "__main__":
    unittest.main()
