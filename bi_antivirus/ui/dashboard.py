"""
BI Antivirus - Desktop Dashboard Main Window
Bitdefender-inspired modern cyber dark control center with streamlined 7-section
navigation, real-time telemetry updates, and seamless view swapping.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from typing import Dict, Any, Optional

from bi_antivirus.config import (
    THEME,
    APP_NAME,
    APP_SUBTITLE,
    APP_VERSION,
    ENGINE_VERSION,
    PROJECT_ROOT,
)
from bi_antivirus.core.engine import AntivirusEngine
from bi_antivirus.core.privilege_manager import is_user_admin
from bi_antivirus.ui.theme import apply_theme
from bi_antivirus.ui.views.overview_view import OverviewView
from bi_antivirus.ui.views.scan_view import ScanView
from bi_antivirus.ui.views.quarantine_view import QuarantineView
from bi_antivirus.ui.views.history_view import HistoryView
from bi_antivirus.ui.views.protection_view import ProtectionView
from bi_antivirus.ui.views.firewall_view import FirewallView
from bi_antivirus.ui.views.automation_view import AutomationView
from bi_antivirus.ui.views.settings_view import SettingsView
from bi_antivirus.ui.views.reports_view import ReportsView
from bi_antivirus.ui.views.edr_view import EDRView
from bi_antivirus.ui.views.patch_view import PatchView
from bi_antivirus.ui.views.pe_view import PEClassifierView
from bi_antivirus.ui.views.fleet_view import FleetView
from bi_antivirus.ui.views.about_view import AboutView


class AntivirusDashboard(tk.Tk):
    """Primary application window and navigation controller."""

    def __init__(self, engine: Optional[AntivirusEngine] = None):
        super().__init__()
        self.engine = engine or AntivirusEngine()
        self.engine.initialize()

        # Window Setup
        self.title(f"{APP_NAME} - {APP_SUBTITLE} [{APP_VERSION}]")
        self.geometry("1100x740")
        self.minsize(980, 650)
        self.configure(bg=THEME["bg_darkest"])

        # Official Black Intel Application & Window Icon
        res_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "resources")
        ico_path = os.path.join(res_dir, "bi_antivirus.ico")
        if os.path.exists(ico_path):
            try:
                self.iconbitmap(default=ico_path)
            except Exception:
                pass

        apply_theme(self)

        self.nav_buttons: Dict[str, ttk.Button] = {}
        self.current_view_key = "dashboard"

        self._build_layout()
        self._setup_engine_callbacks()

        # Initial view
        self.show_view("dashboard")

        # Periodic telemetry refresh
        self._schedule_periodic_refresh()

        # Safe shutdown on close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_layout(self) -> None:
        # Container
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # 1. Left Sidebar
        self.sidebar = tk.Frame(self, bg=THEME["bg_dark"], width=230)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.pack_propagate(False)

        # Sidebar Branding Header with Official Black Intel Eagle Emblem
        brand_frame = tk.Frame(self.sidebar, bg=THEME["bg_dark"], padx=16, pady=16)
        brand_frame.pack(fill="x")

        res_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "resources")
        emblem_64_path = os.path.join(res_dir, "black_intel_emblem_64.png")

        self._brand_emblem_img = None
        if os.path.exists(emblem_64_path):
            try:
                self._brand_emblem_img = tk.PhotoImage(file=emblem_64_path)
                emblem_lbl = tk.Label(
                    brand_frame,
                    image=self._brand_emblem_img,
                    bg=THEME["bg_dark"],
                )
                emblem_lbl.pack(anchor="w", pady=(0, 6))
            except Exception:
                pass

        logo_lbl = tk.Label(
            brand_frame,
            text="BI ANTIVIRUS",
            bg=THEME["bg_dark"],
            fg=THEME["accent_primary"],
            font=(THEME["font_family"], 13, "bold"),
            anchor="w",
        )
        logo_lbl.pack(fill="x")

        sub_lbl = tk.Label(
            brand_frame,
            text="BLACK INTEL CYBER DEFENSE",
            bg=THEME["bg_dark"],
            fg=THEME["text_muted"],
            font=(THEME["font_family"], 7, "bold"),
            anchor="w",
        )
        sub_lbl.pack(fill="x", pady=(2, 0))

        # Divider
        div = tk.Frame(self.sidebar, bg=THEME["border"], height=1)
        div.pack(fill="x", padx=14, pady=(0, 14))

        # Intuitive 7-Section Navigation (Beginner-friendly & streamlined)
        nav_items = [
            ("dashboard", "🛡️  Dashboard"),
            ("scan", "🔍  Scan"),
            ("quarantine", "📦  Quarantine Vault"),
            ("history", "📜  Threat History"),
            ("protection", "🌐  Protection"),
            ("settings", "⚙️  Settings"),
            ("about", "ℹ️  About"),
        ]

        for key, label in nav_items:
            btn = ttk.Button(
                self.sidebar,
                text=label,
                style="Nav.TButton",
                command=lambda k=key: self.show_view(k),
            )
            btn.pack(fill="x", padx=10, pady=3)
            self.nav_buttons[key] = btn

        # Sidebar Bottom Footer
        footer_frame = tk.Frame(self.sidebar, bg=THEME["bg_dark"], padx=16, pady=16)
        footer_frame.pack(side="bottom", fill="x")

        self.footer_status = tk.Label(
            footer_frame,
            text="● PROTECTED",
            bg=THEME["bg_dark"],
            fg=THEME["status_safe"],
            font=(THEME["font_family"], 9, "bold"),
            anchor="w",
        )
        self.footer_status.pack(fill="x")

        is_adm = is_user_admin()
        self.footer_mode = tk.Label(
            footer_frame,
            text="🛡️ ADMIN: FULL" if is_adm else "⚠️ USER: AUDIT ONLY",
            bg=THEME["bg_dark"],
            fg=THEME["status_safe"] if is_adm else THEME["status_warning"],
            font=(THEME["font_family"], 8, "bold"),
            anchor="w",
        )
        self.footer_mode.pack(fill="x", pady=(2, 0))

        footer_meta = tk.Label(
            footer_frame,
            text=f"Engine {ENGINE_VERSION}\nStorage: {PROJECT_ROOT}",
            bg=THEME["bg_dark"],
            fg=THEME["text_muted"],
            font=(THEME["font_mono"], 7),
            anchor="w",
            justify="left",
        )
        footer_meta.pack(fill="x", pady=(4, 0))

        # 2. Main Content Area
        self.content_area = tk.Frame(self, bg=THEME["bg_darkest"])
        self.content_area.grid(row=0, column=1, sticky="nsew")

        # Instantiate View Frames (Preserving 100% of existing views for full compatibility)
        self.views = {
            "dashboard": OverviewView(
                self.content_area,
                engine=self.engine,
                on_start_quick_scan=self.launch_quick_scan,
                on_start_full_scan=self.launch_full_scan,
                on_start_custom_scan=self.launch_custom_scan,
                on_navigate=self.show_view,
            ),
            "scan": ScanView(
                self.content_area,
                engine=self.engine,
                on_start_quick_scan=self.launch_quick_scan,
                on_start_full_scan=self.launch_full_scan,
                on_start_custom_scan=self.launch_custom_scan,
                on_navigate=self.show_view,
            ),
            "quarantine": QuarantineView(self.content_area, engine=self.engine),
            "history": HistoryView(self.content_area, engine=self.engine),
            "protection": ProtectionView(self.content_area, engine=self.engine),
            "firewall": FirewallView(self.content_area, engine=self.engine),
            "automation": AutomationView(self.content_area, engine=self.engine),
            "settings": SettingsView(self.content_area, engine=self.engine, on_navigate=self.show_view),
            "reports": ReportsView(self.content_area, engine=self.engine),
            "edr": EDRView(self.content_area, engine=self.engine),
            "patch": PatchView(self.content_area, engine=self.engine),
            "pe_inspect": PEClassifierView(self.content_area, engine=self.engine),
            "fleet": FleetView(self.content_area, engine=self.engine),
            "about": AboutView(self.content_area, engine=self.engine),
        }

    def _setup_engine_callbacks(self) -> None:
        """Connect engine status events to dashboard widgets."""
        def _on_status_change(status: str):
            self.after(0, lambda: self._update_status_badge(status))

        def _on_threat_found(threat: Dict[str, Any]):
            self.after(0, lambda: self._handle_threat_found_alert(threat))

        self.engine.on_status_changed = _on_status_change
        self.engine.on_threat_found = _on_threat_found

    def _update_status_badge(self, status: str) -> None:
        if status == "PROTECTED":
            self.footer_status.config(text="● PROTECTED", fg=THEME["status_safe"])
        elif status == "SCANNING":
            self.footer_status.config(text="● SCANNING...", fg=THEME["status_warning"])
        elif status == "THREAT_DETECTED":
            self.footer_status.config(text="● THREAT FOUND", fg=THEME["status_threat"])
        else:
            self.footer_status.config(text="● WARNING", fg=THEME["status_warning"])

    def _handle_threat_found_alert(self, threat: Dict[str, Any]) -> None:
        self._update_status_badge("THREAT_DETECTED")
        # Refresh current view
        if hasattr(self.views.get(self.current_view_key), "refresh_data"):
            self.views[self.current_view_key].refresh_data()

    def show_view(self, view_key: str) -> None:
        """Switch active view pane in main container."""
        if view_key not in self.views:
            return

        # Hide currently visible views
        for v in self.views.values():
            v.pack_forget()

        # Determine which sidebar nav button to highlight
        parent_map = {
            "firewall": "protection",
            "edr": "protection",
            "reports": "protection",
            "automation": "settings",
            "patch": "settings",
            "pe_inspect": "settings",
            "fleet": "settings",
        }
        active_nav_key = parent_map.get(view_key, view_key)

        # Update Nav Button styling
        for k, btn in self.nav_buttons.items():
            if k == active_nav_key:
                btn.configure(style="NavActive.TButton")
            else:
                btn.configure(style="Nav.TButton")

        # Show target view
        target_view = self.views[view_key]
        target_view.pack(fill="both", expand=True)
        self.current_view_key = view_key

        # Trigger data refresh on the active view
        if hasattr(target_view, "refresh_data"):
            target_view.refresh_data()

    def launch_quick_scan(self) -> None:
        """Trigger Quick Scan and switch to Scan Center view."""
        self.show_view("scan")
        scan_view: ScanView = self.views["scan"]

        def _progress_cb(p):
            self.after(0, lambda: scan_view.update_progress(p))

        self.engine.start_quick_scan(progress_cb=_progress_cb)

    def launch_full_scan(self) -> None:
        """Trigger Full Scan and switch to Scan Center view."""
        self.show_view("scan")
        scan_view: ScanView = self.views["scan"]

        def _progress_cb(p):
            self.after(0, lambda: scan_view.update_progress(p))

        self.engine.start_full_scan(progress_cb=_progress_cb)

    def launch_custom_scan(self, path: Path) -> None:
        """Trigger Custom Folder Scan and switch to Scan Center view."""
        self.show_view("scan")
        scan_view: ScanView = self.views["scan"]

        def _progress_cb(p):
            self.after(0, lambda: scan_view.update_progress(p))

        self.engine.start_custom_scan(path, progress_cb=_progress_cb)

    def _schedule_periodic_refresh(self) -> None:
        """Periodically refresh telemetry every 5 seconds."""
        try:
            if self.current_view_key == "dashboard":
                self.views["dashboard"].refresh_data()
        except Exception:
            pass
        self.after(5000, self._schedule_periodic_refresh)

    def check_first_run(self, auto_prompt: bool = True) -> None:
        """Check if first-run setup has occurred; launch wizard if needed."""
        try:
            from bi_antivirus.config import load_settings
            settings = load_settings()
            if not settings.get("first_run_completed", False):
                if auto_prompt:
                    self.after(300, self.open_first_run_wizard)
        except Exception:
            pass

    def open_first_run_wizard(self) -> None:
        """Open the modal First-Run Setup Wizard."""
        try:
            from bi_antivirus.ui.first_run_wizard import FirstRunWizard
            FirstRunWizard(self, on_complete=self._on_wizard_complete)
        except Exception as e:
            print(f"[!] Unable to launch first run wizard: {e}")

    def _on_wizard_complete(self, run_quick_scan: bool) -> None:
        """Callback when the user completes first-run setup."""
        if run_quick_scan:
            self.show_view("scan")
            if "scan" in self.views and hasattr(self.views["scan"], "_on_start_quick_scan"):
                self.after(400, self.views["scan"]._on_start_quick_scan)

    def _on_close(self) -> None:
        """Handle application close event cleanly."""
        try:
            self.engine.shutdown()
        except Exception:
            pass
        self.destroy()


def run_dashboard(show_splash: bool = False):
    """Launch the BI Antivirus desktop graphical dashboard."""
    app = AntivirusDashboard()
    if show_splash:
        try:
            from bi_antivirus.ui.splash import SplashScreen
            app.withdraw()

            def _on_splash_done():
                app.deiconify()
                app.lift()
                app.focus_force()
                app.check_first_run(auto_prompt=True)

            SplashScreen(app, on_complete=_on_splash_done, duration_ms=1200)
        except Exception:
            app.deiconify()
            app.check_first_run(auto_prompt=True)
    else:
        app.check_first_run(auto_prompt=True)
    app.mainloop()


if __name__ == "__main__":
    run_dashboard()
