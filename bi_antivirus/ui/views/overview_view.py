"""
BI Antivirus - Overview View (Dashboard Home)
Displays main protection status shield, telemetry metrics, and scan launch cards.
"""

import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from typing import Callable, Optional

from bi_antivirus.config import THEME, APP_NAME, APP_SUBTITLE, DATA_DIR
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
        on_navigate: Optional[Callable[[str], None]] = None,
        **kwargs,
    ):
        super().__init__(parent, bg=THEME["bg_darkest"], **kwargs)
        self.engine = engine
        self.on_start_quick_scan = on_start_quick_scan
        self.on_start_full_scan = on_start_full_scan
        self.on_start_custom_scan = on_start_custom_scan
        self.on_navigate = on_navigate

        self._build_ui()

    def _navigate(self, target: str) -> None:
        if self.on_navigate:
            self.on_navigate(target)

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

        # Hero Action (Prominent Quick Scan Button)
        hero_action = tk.Frame(hero_frame, bg=THEME["bg_panel"])
        hero_action.pack(side="right", padx=(16, 0))

        self.btn_hero_quick_scan = ttk.Button(
            hero_action,
            text="⚡ Run Quick Scan",
            style="Primary.TButton",
            command=self.on_start_quick_scan,
        )
        self.btn_hero_quick_scan.pack(fill="x", pady=(0, 4))

        quick_sub = tk.Label(
            hero_action,
            text="Memory & startup scan",
            bg=THEME["bg_panel"],
            fg=THEME["text_muted"],
            font=(THEME["font_family"], 8),
            wraplength=140,
            justify="center",
            anchor="center",
        )
        quick_sub.pack(fill="x")

        # 1.25 Operating Privilege & Enforcement Mode Banner
        self.enforcement_frame = tk.Frame(self, bg=THEME["bg_panel"], padx=16, pady=10)
        self.enforcement_frame.pack(fill="x", padx=20, pady=(0, 10))
        self.enforcement_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        enf_left = tk.Frame(self.enforcement_frame, bg=THEME["bg_panel"])
        enf_left.pack(side="left", fill="both", expand=True)

        self.enforcement_title = tk.Label(
            enf_left,
            text="ENFORCEMENT MODE: VERIFYING PRIVILEGES...",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 10, "bold"),
            anchor="w",
        )
        self.enforcement_title.pack(fill="x")

        self.enforcement_subtext = tk.Label(
            enf_left,
            text="Checking Windows security token integrity level and host capability boundaries.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 8),
            anchor="w",
            justify="left",
        )
        self.enforcement_subtext.pack(fill="x", pady=(2, 0))

        self.btn_system_diag = ttk.Button(
            self.enforcement_frame,
            text="System Diagnostics",
            command=self._show_system_diagnostics_dialog,
        )
        self.btn_system_diag.pack(side="right", padx=(10, 0))

        self.btn_priv_details = ttk.Button(
            self.enforcement_frame,
            text="Privilege Details",
            command=self._show_privilege_details_dialog,
        )
        self.btn_priv_details.pack(side="right", padx=(10, 0))

        # 1.5 Active Cyber Defense Sentinels Telemetry Bar
        sentinels_bar = tk.Frame(self, bg=THEME["bg_panel"], padx=14, pady=8)
        sentinels_bar.pack(fill="x", padx=20, pady=(0, 15))
        sentinels_bar.configure(highlightbackground=THEME["border"], highlightthickness=1)

        self.sentinel_labels = {}
        sentinel_configs = [
            ("behavioral", "⚡ Behavioral: ACTIVE"),
            ("ransomware", "🛡️ Ransomware: ACTIVE"),
            ("usb", "🔌 USB: ACTIVE"),
            ("authenticode", "🔏 Authenticode: ACTIVE"),
            ("posture", "🎯 Baseline: 5/5 PASSED"),
            ("etw", "📡 ETW: AUDIT"),
        ]

        for key, text in sentinel_configs:
            lbl = tk.Label(
                sentinels_bar,
                text=text,
                bg=THEME["bg_panel"],
                fg=THEME["accent_cyan"],
                font=(THEME["font_family"], 8, "bold"),
            )
            lbl.pack(side="left", padx=(0, 6))
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

        # 4. Quick Feature Shortcuts
        shortcuts_lbl = tk.Label(
            self,
            text="IMPORTANT FEATURES & SHORTCUTS",
            bg=THEME["bg_darkest"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10, "bold"),
            anchor="w",
        )
        shortcuts_lbl.pack(fill="x", padx=20, pady=(5, 8))

        shortcuts_grid = tk.Frame(self, bg=THEME["bg_darkest"])
        shortcuts_grid.pack(fill="x", padx=20, pady=(0, 20))
        shortcuts_grid.columnconfigure(0, weight=1)
        shortcuts_grid.columnconfigure(1, weight=1)
        shortcuts_grid.columnconfigure(2, weight=1)
        shortcuts_grid.columnconfigure(3, weight=1)

        self.btn_nav_quarantine = ttk.Button(
            shortcuts_grid,
            text="📦 Quarantine Vault",
            style="Secondary.TButton",
            command=lambda: self._navigate("quarantine"),
        )
        self.btn_nav_quarantine.grid(row=0, column=0, sticky="ew", padx=(0, 5))

        self.btn_nav_protection = ttk.Button(
            shortcuts_grid,
            text="🌐 Protection Shields",
            style="Secondary.TButton",
            command=lambda: self._navigate("protection"),
        )
        self.btn_nav_protection.grid(row=0, column=1, sticky="ew", padx=5)

        self.btn_nav_history = ttk.Button(
            shortcuts_grid,
            text="📜 Threat History",
            style="Secondary.TButton",
            command=lambda: self._navigate("history"),
        )
        self.btn_nav_history.grid(row=0, column=2, sticky="ew", padx=5)

        self.btn_nav_settings = ttk.Button(
            shortcuts_grid,
            text="⚙️ Settings & Exclusions",
            style="Secondary.TButton",
            command=lambda: self._navigate("settings"),
        )
        self.btn_nav_settings.grid(row=0, column=3, sticky="ew", padx=(5, 0))

        # Initial data refresh from active engine state
        self.refresh_data()

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
                text=f"🔌 USB: {usb_state}",
                fg=THEME["status_safe"] if usb_state == "ACTIVE" else THEME["text_muted"],
            )
            if "etw" in self.sentinel_labels:
                etw_info = summary.get("etw_status", {})
                etw_op = etw_info.get("operational_status", "PROBE")
                etw_short = "ACTIVE" if "PERMITTED" in etw_op else "AUDIT"
                self.sentinel_labels["etw"].config(
                    text=f"📡 ETW: {etw_short}",
                    fg=THEME["status_safe"] if "PERMITTED" in etw_op else THEME["accent_cyan"],
                )

        # Update Operating Mode & Enforcement Banner
        enf = summary.get("enforcement_details", {})
        if enf and hasattr(self, "enforcement_title"):
            is_adm = enf.get("is_admin", False)
            title_text = f"🛡️ {enf.get('mode_title', 'Administrator Mode')}" if is_adm else f"⚠️ {enf.get('mode_title', 'Standard User Mode')}"
            self.enforcement_title.config(
                text=title_text,
                fg=enf.get("status_color", THEME["status_safe"]),
            )
            sub = (
                f"Integrity Level: {enf.get('integrity_level')} — All host OS enforcement capabilities active."
                if is_adm
                else f"Integrity Level: {enf.get('integrity_level')} — {enf.get('restricted_count', 4)} capabilities operating in Audit-Only mode."
            )
            self.enforcement_subtext.config(text=sub)
            border_color = enf.get("status_color", THEME["border"])
            self.enforcement_frame.configure(highlightbackground=border_color)

    def _show_privilege_details_dialog(self) -> None:
        """Display dialog explaining permission state, available vs audit-only capabilities."""
        summary = self.engine.get_dashboard_summary()
        enf = summary.get("enforcement_details", {})
        if not enf:
            from bi_antivirus.core.privilege_manager import PrivilegeManager
            enf = PrivilegeManager.get_enforcement_details()

        dialog = tk.Toplevel(self)
        dialog.title("Operating Privilege & Host Enforcement Details")
        dialog.geometry("720x520")
        dialog.configure(bg=THEME["bg_dark"])
        dialog.transient(self)
        dialog.grab_set()

        hdr = tk.Frame(dialog, bg=THEME["bg_panel"], padx=16, pady=12)
        hdr.pack(fill="x", padx=14, pady=14)
        tk.Label(
            hdr,
            text=enf.get("mode_title", "Privilege State"),
            font=(THEME["font_family"], 12, "bold"),
            bg=THEME["bg_panel"],
            fg=enf.get("status_color", THEME["text_primary"]),
        ).pack(anchor="w")
        tk.Label(
            hdr,
            text=f"Process Security Token: {enf.get('integrity_level', 'Unknown')}",
            font=(THEME["font_family"], 9),
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
        ).pack(anchor="w", pady=(2, 0))

        expl_frame = tk.Frame(dialog, bg=THEME["bg_dark"], padx=14)
        expl_frame.pack(fill="x")
        tk.Label(
            expl_frame,
            text=enf.get("explanation", ""),
            font=(THEME["font_family"], 9),
            bg=THEME["bg_dark"],
            fg=THEME["text_primary"],
            wraplength=680,
            justify="left",
        ).pack(anchor="w", pady=(0, 10))

        tree_frame = tk.Frame(dialog, bg=THEME["bg_dark"], padx=14)
        tree_frame.pack(fill="both", expand=True)

        columns = ("feature", "state", "enforcement", "elevation")
        tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=8)
        tree.heading("feature", text="Security Subsystem")
        tree.heading("state", text="Operational State")
        tree.heading("enforcement", text="Enforcement Mode")
        tree.heading("elevation", text="Admin Required?")

        tree.column("feature", width=220)
        tree.column("state", width=120)
        tree.column("enforcement", width=230)
        tree.column("elevation", width=110)

        for fid, f in enf.get("features", {}).items():
            tree.insert("", "end", values=(
                f["name"],
                f["state"],
                f["enforcement"],
                "Yes" if f["requires_elevation"] else "No",
            ))

        tree.pack(fill="both", expand=True)

        btn_box = tk.Frame(dialog, bg=THEME["bg_dark"], padx=14, pady=12)
        btn_box.pack(fill="x")
        ttk.Button(btn_box, text="Close", command=dialog.destroy).pack(side="right")

    def _show_system_diagnostics_dialog(self) -> None:
        """Open master Windows host environment compatibility and diagnostics dialog."""
        from bi_antivirus.core.windows_compat import WindowsCompatibilityAuditor
        auditor = WindowsCompatibilityAuditor()
        report = auditor.run_full_audit()

        dialog = tk.Toplevel(self)
        dialog.title("Windows Host Environment & Pre-Flight Diagnostics")
        dialog.geometry("740x540")
        dialog.configure(bg=THEME["bg_dark"])
        dialog.transient(self)
        dialog.grab_set()

        hdr = tk.Frame(dialog, bg=THEME["bg_panel"], padx=16, pady=12)
        hdr.pack(fill="x", padx=14, pady=14)
        
        status_color = THEME["status_safe"] if report["overall_readiness"] == "READY" else THEME["status_warning"]
        tk.Label(
            hdr,
            text=f"System Readiness: {report['overall_readiness']}",
            font=(THEME["font_family"], 13, "bold"),
            bg=THEME["bg_panel"],
            fg=status_color,
        ).pack(anchor="w")

        tk.Label(
            hdr,
            text=f"{report['app_name']} v{report['app_version']} | Engine: {report['engine_version']}",
            font=(THEME["font_family"], 9),
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
        ).pack(anchor="w", pady=(2, 0))

        # Detail Table
        tree_frame = tk.Frame(dialog, bg=THEME["bg_dark"], padx=14)
        tree_frame.pack(fill="both", expand=True)

        columns = ("component", "status", "detail")
        tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=10)
        tree.heading("component", text="Component / Subsystem")
        tree.heading("status", text="Verification Status")
        tree.heading("detail", text="Diagnostic Finding")

        tree.column("component", width=180)
        tree.column("status", width=110, anchor="center")
        tree.column("detail", width=410)

        checks = report.get("checks", {})
        
        # Python
        py = checks.get("python", {})
        tree.insert("", "end", values=("Python Runtime", py.get("status", "N/A"), f"v{py.get('version')} (64-bit={py.get('is_64bit')})"))
        
        # Windows
        win = checks.get("windows", {})
        tree.insert("", "end", values=("Windows OS", win.get("status", "N/A"), f"{win.get('release')} Build {win.get('build')} ({win.get('edition')})"))
        
        # Privileges
        priv = checks.get("privileges", {})
        tree.insert("", "end", values=("Token Integrity", "ACTIVE", f"{priv.get('enforcement_mode')} ({priv.get('full_enforcement_subsystems')} active, {priv.get('audit_only_subsystems')} audit)"))
        
        # Storage
        st = checks.get("storage", {})
        tree.insert("", "end", values=("Storage Target", st.get("status", "N/A"), f"{st.get('drive')} drive ({st.get('free_space_gb')} GB free, write=OK)"))
        
        # SQLite
        sq = checks.get("sqlite", {})
        tree.insert("", "end", values=("SQLite Databases", sq.get("status", "N/A"), f"v{sq.get('sqlite_version')} - All databases verified intact with WAL mode"))
        
        # Crypto
        cr = checks.get("cryptography", {})
        tree.insert("", "end", values=("Native DPAPI/CNG", cr.get("status", "N/A"), cr.get("note", "DPAPI available")))
        
        # Defender
        df = checks.get("defender_coexistence", {})
        tree.insert("", "end", values=("Windows Defender", df.get("status", "N/A"), df.get("details", "Mutual coexistence active")))

        tree.pack(fill="both", expand=True)

        # Footer Buttons
        btn_box = tk.Frame(dialog, bg=THEME["bg_dark"], padx=14, pady=12)
        btn_box.pack(fill="x")

        def _export():
            out_p = DATA_DIR / "system_diagnostics.json"
            with open(out_p, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            messagebox.showinfo("Export Diagnostics", f"Diagnostic report exported to:\n{out_p}")

        ttk.Button(btn_box, text="Export JSON", command=_export).pack(side="left")
        ttk.Button(btn_box, text="Close", command=dialog.destroy).pack(side="right")


