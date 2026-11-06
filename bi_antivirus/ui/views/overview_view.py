"""
BI Antivirus - Overview View (Dashboard Home)
Displays main protection status shield, telemetry metrics, and scan launch cards.
"""

import tkinter as tk
from tkinter import ttk, filedialog
from pathlib import Path
from typing import Callable, Optional

from bi_antivirus.config import THEME, APP_NAME, APP_SUBTITLE
from bi_antivirus.ui.widgets.cards import StatusShield, StatCard, ActionCard


class OverviewView(tk.Frame):
    """Primary dashboard view showing protection health, quick metrics, and scan launch cards."""

    def __init__(
        self,
        parent,
        engine,
        on_start_quick_scan: Callable[[], None],
        on_start_full_scan: Callable[[], None],
        on_start_custom_scan: Callable[[Path], None],
        **kwargs,
    ):
        super().__init__(parent, bg=THEME["bg_darkest"], **kwargs)
        self.engine = engine
        self.on_start_quick_scan = on_start_quick_scan
        self.on_start_full_scan = on_start_full_scan
        self.on_start_custom_scan = on_start_custom_scan

        self._build_ui()

    def _build_ui(self) -> None:
        # 1. Main Protection Hero Banner
        hero_frame = tk.Frame(self, bg=THEME["bg_panel"], padx=20, pady=18)
        hero_frame.pack(fill="x", padx=20, pady=(20, 15))
        hero_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        # Shield Widget
        self.shield = StatusShield(hero_frame, size=90, status="PROTECTED")
        self.shield.pack(side="left", padx=(0, 20))

        # Hero Text Info
        text_frame = tk.Frame(hero_frame, bg=THEME["bg_panel"])
        text_frame.pack(side="left", fill="both", expand=True)

        self.status_title = tk.Label(
            text_frame,
            text="YOU ARE PROTECTED",
            bg=THEME["bg_panel"],
            fg=THEME["status_safe"],
            font=(THEME["font_family"], 16, "bold"),
            anchor="w",
        )
        self.status_title.pack(fill="x")

        self.status_desc = tk.Label(
            text_frame,
            text="Black Intel real-time defenses, behavioral heuristics, and malware signatures are active.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10),
            anchor="w",
        )
        self.status_desc.pack(fill="x", pady=(2, 6))

        self.status_meta = tk.Label(
            text_frame,
            text="Definitions: Up to Date | Real-Time Guard: Active | Secure Vault: 0 Isolated",
            bg=THEME["bg_panel"],
            fg=THEME["text_muted"],
            font=(THEME["font_family"], 9),
            anchor="w",
        )
        self.status_meta.pack(fill="x")

        # 1.5 Active Cyber Defense Sentinels Telemetry Bar
        sentinels_bar = tk.Frame(self, bg=THEME["bg_panel"], padx=14, pady=8)
        sentinels_bar.pack(fill="x", padx=20, pady=(0, 15))
        sentinels_bar.configure(highlightbackground=THEME["border"], highlightthickness=1)

        self.sentinel_labels = {}
        sentinel_configs = [
            ("behavioral", "⚡ Behavioral: ACTIVE"),
            ("ransomware", "🛡️ Ransomware Shield: ACTIVE"),
            ("usb", "🔌 USB Sentinel: ACTIVE"),
            ("authenticode", "🔏 WinTrust Authenticode: ACTIVE"),
            ("posture", "🎯 Baseline Audit: 5/5 CONTROLS PASSED"),
        ]

        for key, text in sentinel_configs:
            lbl = tk.Label(
                sentinels_bar,
                text=text,
                bg=THEME["bg_panel"],
                fg=THEME["accent_cyan"],
                font=(THEME["font_family"], 8, "bold"),
            )
            lbl.pack(side="left", padx=(0, 14))
            self.sentinel_labels[key] = lbl

        # 2. Metric Stat Cards Grid
        stats_grid = tk.Frame(self, bg=THEME["bg_darkest"])
        stats_grid.pack(fill="x", padx=20, pady=(0, 15))

        stats_grid.columnconfigure(0, weight=1)
        stats_grid.columnconfigure(1, weight=1)
        stats_grid.columnconfigure(2, weight=1)
        stats_grid.columnconfigure(3, weight=1)

        self.card_signatures = StatCard(
            stats_grid,
            title="Signatures Active",
            value="Loading...",
            subtext="SHA-256 & Pattern Rules",
            accent=THEME["accent_cyan"],
        )
        self.card_signatures.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        self.card_scanned = StatCard(
            stats_grid,
            title="Files Scanned",
            value="0",
            subtext="Lifetime Inspected",
            accent=THEME["accent_primary"],
        )
        self.card_scanned.grid(row=0, column=1, sticky="nsew", padx=5)

        self.card_threats = StatCard(
            stats_grid,
            title="Threats Blocked",
            value="0",
            subtext="Neutralized & Logged",
            accent=THEME["status_threat"],
        )
        self.card_threats.grid(row=0, column=2, sticky="nsew", padx=5)

        self.card_vault = StatCard(
            stats_grid,
            title="Quarantine Vault",
            value="0",
            subtext="Reversibly Isolated",
            accent=THEME["status_warning"],
        )
        self.card_vault.grid(row=0, column=3, sticky="nsew", padx=(10, 0))

        # 3. Action Cards Grid
        section_lbl = tk.Label(
            self,
            text="ON-DEMAND SCANNING",
            bg=THEME["bg_darkest"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10, "bold"),
            anchor="w",
        )
        section_lbl.pack(fill="x", padx=20, pady=(5, 8))

        actions_grid = tk.Frame(self, bg=THEME["bg_darkest"])
        actions_grid.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        actions_grid.columnconfigure(0, weight=1)
        actions_grid.columnconfigure(1, weight=1)
        actions_grid.columnconfigure(2, weight=1)

        card_quick = ActionCard(
            actions_grid,
            title="Quick Scan",
            description="Inspects active processes, startup programs, and memory temp directories in seconds.",
            button_text="Run Quick Scan",
            on_click=self.on_start_quick_scan,
            accent=THEME["accent_primary"],
        )
        card_quick.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        card_full = ActionCard(
            actions_grid,
            title="Full System Scan",
            description="Deep multi-threaded inspection traversing drives, profiles, and archives on disk.",
            button_text="Run Full Scan",
            on_click=self.on_start_full_scan,
            accent=THEME["accent_cyan"],
        )
        card_full.grid(row=0, column=1, sticky="nsew", padx=5)

        card_custom = ActionCard(
            actions_grid,
            title="Custom Scan",
            description="Target a specific folder, project directory, flash drive, or single file for inspection.",
            button_text="Select & Scan...",
            on_click=self._prompt_custom_scan,
            accent=THEME["status_warning"],
        )
        card_custom.grid(row=0, column=2, sticky="nsew", padx=(10, 0))

    def _prompt_custom_scan(self) -> None:
        """Open folder dialog to select custom scan target."""
        folder = filedialog.askdirectory(title="Select Folder to Scan with BI Antivirus")
        if folder:
            self.on_start_custom_scan(Path(folder))

    def refresh_data(self) -> None:
        """Update metrics and shield state."""
        summary = self.engine.get_dashboard_summary()
        status = summary["status"]

        if status == "PROTECTED":
            self.status_title.config(text="YOU ARE PROTECTED", fg=THEME["status_safe"])
            self.shield.set_status("PROTECTED")
        elif status == "THREAT_DETECTED":
            self.status_title.config(text="ACTION REQUIRED - THREAT DETECTED", fg=THEME["status_threat"])
            self.shield.set_status("THREAT_DETECTED")
        elif status == "SCANNING":
            self.status_title.config(text="SCANNING SYSTEM IN PROGRESS", fg=THEME["status_warning"])
            self.shield.set_status("SCANNING")
        else:
            self.status_title.config(text="PROTECTION WARNING", fg=THEME["status_warning"])
            self.shield.set_status("WARNING")

        self.status_meta.config(
            text=f"Definitions: {summary['definition_version']} | Last Scan: {summary['last_scan_time']} | Vault: {summary['quarantined_items_count']} Items"
        )

        self.card_signatures.update_value(str(summary["total_signatures"]))
        self.card_scanned.update_value(f"{summary['total_files_scanned']:,}")
        self.card_threats.update_value(str(summary["total_threats_found"]))
        self.card_vault.update_value(str(summary["quarantined_items_count"]))

        # Update Sentinels telemetry
        if hasattr(self, "sentinel_labels"):
            bh_state = "ACTIVE" if summary.get("behavioral_active") else "STANDBY"
            self.sentinel_labels["behavioral"].config(
                text=f"⚡ Behavioral: {bh_state}",
                fg=THEME["status_safe"] if bh_state == "ACTIVE" else THEME["text_muted"],
            )
            rn_state = "ACTIVE" if summary.get("ransomware_shield_active") else "STANDBY"
            canaries = summary.get("canaries_deployed", 0)
            self.sentinel_labels["ransomware"].config(
                text=f"🛡️ Ransomware: {rn_state} ({canaries} Canaries)",
                fg=THEME["status_safe"] if rn_state == "ACTIVE" else THEME["text_muted"],
            )
            usb_state = "ACTIVE" if summary.get("usb_sentinel_active") else "STANDBY"
            self.sentinel_labels["usb"].config(
                text=f"🔌 USB Sentinel: {usb_state}",
                fg=THEME["status_safe"] if usb_state == "ACTIVE" else THEME["text_muted"],
            )

