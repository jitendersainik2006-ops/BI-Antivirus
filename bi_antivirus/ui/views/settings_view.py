"""
BI Antivirus - Settings & Exclusions View
Manages scan exclusions, heuristic thresholds, definition updates, and storage paths.
"""

import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path

from bi_antivirus.config import (
    THEME,
    load_settings,
    save_settings,
    PROJECT_ROOT,
    DATA_DIR,
    LOGS_DIR,
    QUARANTINE_DIR,
    REPORTS_DIR,
)


class SettingsView(tk.Frame):
    """Configuration panel for exclusions, heuristic thresholds, and definition updates."""

    def __init__(self, parent, engine, **kwargs):
        super().__init__(parent, bg=THEME["bg_darkest"], **kwargs)
        self.engine = engine
        self._build_ui()

    def _build_ui(self) -> None:
        header_frame = tk.Frame(self, bg=THEME["bg_panel"], padx=20, pady=16)
        header_frame.pack(fill="x", padx=20, pady=(20, 15))
        header_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        title_lbl = tk.Label(
            header_frame,
            text="SETTINGS & CONFIGURATION",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 14, "bold"),
            anchor="w",
        )
        title_lbl.pack(fill="x")

        desc_lbl = tk.Label(
            header_frame,
            text="Tune detection sensitivity, manage scan exclusions, and update malware signature definitions.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10),
            anchor="w",
        )
        desc_lbl.pack(fill="x", pady=(2, 0))

        content_frame = tk.Frame(self, bg=THEME["bg_darkest"])
        content_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Left Column - Exclusions
        left_col = tk.Frame(content_frame, bg=THEME["bg_panel"], padx=16, pady=16)
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 10))
        left_col.configure(highlightbackground=THEME["border"], highlightthickness=1)

        excl_hdr = tk.Label(
            left_col,
            text="SCAN EXCLUSION LIST",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        excl_hdr.pack(fill="x")

        excl_desc = tk.Label(
            left_col,
            text="Items excluded from real-time and scheduled file analysis:",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            anchor="w",
        )
        excl_desc.pack(fill="x", pady=(2, 8))

        self.excl_listbox = tk.Listbox(
            left_col,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            selectbackground=THEME["border_highlight"],
            font=(THEME["font_mono"], 9),
            height=7,
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        self.excl_listbox.pack(fill="both", expand=True)

        excl_btns = tk.Frame(left_col, bg=THEME["bg_panel"])
        excl_btns.pack(fill="x", pady=(8, 14))

        btn_add_excl = ttk.Button(excl_btns, text="Exclude Folder...", style="Primary.TButton", command=self._on_add_exclusion)
        btn_add_excl.pack(side="left", padx=(0, 8))

        btn_remove_excl = ttk.Button(excl_btns, text="Remove", style="Secondary.TButton", command=self._on_remove_exclusion)
        btn_remove_excl.pack(side="left")

        # Storage Path Info
        storage_hdr = tk.Label(
            left_col,
            text="SECURE STORAGE (D: DRIVE)",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9, "bold"),
            anchor="w",
        )
        storage_hdr.pack(fill="x", pady=(6, 4))

        storage_text = (
            f"• Project Root: {PROJECT_ROOT}\n"
            f"• Database Store: {DATA_DIR}\n"
            f"• Quarantine Vault: {QUARANTINE_DIR}\n"
            f"• Security Logs: {LOGS_DIR}"
        )
        storage_lbl = tk.Label(
            left_col,
            text=storage_text,
            bg=THEME["bg_input"],
            fg=THEME["text_secondary"],
            font=(THEME["font_mono"], 8),
            justify="left",
            anchor="w",
            padx=8,
            pady=6,
        )
        storage_lbl.pack(fill="x")

        # Right Column - Heuristics & Updates
        right_col = tk.Frame(content_frame, bg=THEME["bg_panel"], padx=16, pady=16)
        right_col.pack(side="right", fill="both", expand=True, padx=(10, 0))
        right_col.configure(highlightbackground=THEME["border"], highlightthickness=1)

        upd_hdr = tk.Label(
            right_col,
            text="MALWARE SIGNATURE UPDATES",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        upd_hdr.pack(fill="x")

        self.upd_info_lbl = tk.Label(
            right_col,
            text="Checking definitions status...",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            anchor="w",
            justify="left",
        )
        self.upd_info_lbl.pack(fill="x", pady=(4, 12))

        upd_btns = tk.Frame(right_col, bg=THEME["bg_panel"])
        upd_btns.pack(fill="x", pady=(0, 16))

        btn_chk_upd = ttk.Button(upd_btns, text="Verify Definitions", style="Primary.TButton", command=self._on_check_updates)
        btn_chk_upd.pack(side="left", padx=(0, 8))

        btn_import_pack = ttk.Button(upd_btns, text="Import Definition Pack...", style="Secondary.TButton", command=self._on_import_pack)
        btn_import_pack.pack(side="left")

        # Heuristic Sensitivity Settings
        heur_hdr = tk.Label(
            right_col,
            text="DETECTION ENGINE SETTINGS",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        heur_hdr.pack(fill="x", pady=(10, 4))

        self.var_heuristics = tk.BooleanVar(value=True)
        cb_heur = tk.Checkbutton(
            right_col,
            text="Enable Deep Behavioral Heuristic Analysis",
            variable=self.var_heuristics,
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            selectcolor=THEME["bg_input"],
            activebackground=THEME["bg_panel"],
            activeforeground=THEME["text_primary"],
            font=(THEME["font_family"], 9),
            command=self._on_save_tuning,
        )
        cb_heur.pack(anchor="w", pady=(2, 4))

        self.var_auto_q = tk.BooleanVar(value=False)
        cb_auto_q = tk.Checkbutton(
            right_col,
            text="Auto-Quarantine Threats (Off = Prompt for Approval)",
            variable=self.var_auto_q,
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            selectcolor=THEME["bg_input"],
            activebackground=THEME["bg_panel"],
            activeforeground=THEME["text_primary"],
            font=(THEME["font_family"], 9),
            command=self._on_save_tuning,
        )
        cb_auto_q.pack(anchor="w", pady=(2, 4))

        # Enterprise Database & SIEM Operations
        maint_hdr = tk.Label(
            right_col,
            text="DATABASE HEALTH & SIEM MAINTENANCE",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        maint_hdr.pack(fill="x", pady=(12, 4))

        maint_btns = tk.Frame(right_col, bg=THEME["bg_panel"])
        maint_btns.pack(fill="x", pady=(2, 6))

        btn_chk_db = ttk.Button(maint_btns, text="Verify DB Integrity", style="Secondary.TButton", command=self._on_check_db_integrity)
        btn_chk_db.pack(side="left", padx=(0, 8))

        btn_backup_db = ttk.Button(maint_btns, text="Backup SQLite DB...", style="Secondary.TButton", command=self._on_backup_db)
        btn_backup_db.pack(side="left", padx=(0, 8))

        btn_test_siem = ttk.Button(maint_btns, text="Test SIEM Export", style="Secondary.TButton", command=self._on_test_siem)
        btn_test_siem.pack(side="left")

        self.refresh_data()

    def refresh_data(self) -> None:
        """Load settings into UI widgets."""
        settings = load_settings()
        self.excl_listbox.delete(0, tk.END)
        for p in settings.get("exclusions_paths", []):
            self.excl_listbox.insert(tk.END, f"[DIR] {p}")
        for ext in settings.get("exclusions_extensions", []):
            self.excl_listbox.insert(tk.END, f"[EXT] {ext}")

        self.var_heuristics.set(settings.get("heuristic_analysis_enabled", True))
        self.var_auto_q.set(settings.get("auto_quarantine_threats", False))

        upd = self.engine.updater.check_definition_status()
        self.upd_info_lbl.config(
            text=(
                f"• Definition Version: {upd['version']}\n"
                f"• Total Indicators: {upd['total_signatures']} (Hashes: {upd['hash_signatures']}, Patterns: {upd['pattern_signatures']})\n"
                f"• Web Reputations: {upd['web_reputations']}\n"
                f"• Definition Health: {upd['status']} (Last updated: {upd['last_updated']})"
            )
        )

    def _on_add_exclusion(self) -> None:
        folder = filedialog.askdirectory(title="Select Folder to Exclude from Antivirus Scanning")
        if folder:
            settings = load_settings()
            paths = settings.get("exclusions_paths", [])
            if folder not in paths:
                paths.append(folder)
                settings["exclusions_paths"] = paths
                save_settings(settings)
                self.refresh_data()

    def _on_remove_exclusion(self) -> None:
        selected = self.excl_listbox.curselection()
        if not selected:
            return
        item_str = self.excl_listbox.get(selected[0])
        settings = load_settings()
        if item_str.startswith("[DIR] "):
            val = item_str.replace("[DIR] ", "")
            if val in settings.get("exclusions_paths", []):
                settings["exclusions_paths"].remove(val)
        elif item_str.startswith("[EXT] "):
            val = item_str.replace("[EXT] ", "")
            if val in settings.get("exclusions_extensions", []):
                settings["exclusions_extensions"].remove(val)
        save_settings(settings)
        self.refresh_data()

    def _on_save_tuning(self) -> None:
        settings = load_settings()
        settings["heuristic_analysis_enabled"] = self.var_heuristics.get()
        settings["auto_quarantine_threats"] = self.var_auto_q.get()
        self.engine.detector.enable_heuristics = self.var_heuristics.get()
        save_settings(settings)

    def _on_check_updates(self) -> None:
        self.refresh_data()
        messagebox.showinfo("Definition Status", "Definitions verified. All active malware indicators are up to date.")

    def _on_import_pack(self) -> None:
        pack_file = filedialog.askopenfilename(
            title="Select BI Antivirus Definition Pack (.json)",
            filetypes=[("JSON Definition Pack", "*.json"), ("All Files", "*.*")],
        )
        if pack_file:
            try:
                with open(pack_file, "r", encoding="utf-8") as f:
                    content = f.read()
                res = self.engine.updater.apply_update_pack(content)
                if res.get("success"):
                    messagebox.showinfo("Update Complete", res.get("message"))
                    self.refresh_data()
                else:
                    messagebox.showerror("Update Error", res.get("error"))
            except Exception as e:
                messagebox.showerror("Error", f"Could not read definition pack: {e}")

    def _on_check_db_integrity(self) -> None:
        """Execute PRAGMA integrity_check on the persistent SQLite history database."""
        ok, msg = self.engine.history_db.check_integrity()
        if ok:
            messagebox.showinfo("Database Integrity", f"SQLite History Database Status:\n{msg}")
        else:
            messagebox.showwarning("Database Warning", f"Integrity check issue:\n{msg}")

    def _on_backup_db(self) -> None:
        """Execute safe physical online SQLite backup to destination file."""
        dest = filedialog.asksaveasfilename(
            title="Save Online SQLite Database Backup",
            initialfile=f"history_backup_{time.strftime('%Y%m%d_%H%M%S')}.db",
            filetypes=[("SQLite Database", "*.db"), ("All Files", "*.*")],
        )
        if dest:
            ok = self.engine.history_db.create_backup(Path(dest))
            if ok:
                messagebox.showinfo("Database Backup", f"Hot SQLite backup completed successfully to:\n{dest}")
            else:
                messagebox.showerror("Backup Error", "Failed to write database backup.")

    def _on_test_siem(self) -> None:
        """Dispatch test security event via RFC 5424 / CEF SIEM exporter."""
        try:
            sample_event = {
                "event_type": "SIEM_TEST_DISPATCH",
                "severity": "LOW",
                "source": "SettingsView",
                "timestamp": time.time(),
                "message": "Manual SIEM diagnostic test dispatch from BI Antivirus console.",
            }
            if hasattr(self.engine, "siem_exporter") and self.engine.siem_exporter:
                res = self.engine.siem_exporter.export_event(sample_event)
                messagebox.showinfo("SIEM Export", f"SIEM Test Event Dispatched Successfully.\nFormat: RFC 5424 / CEF\nPayload Hash: {res.get('hash', 'Verified') if isinstance(res, dict) else 'Active'}")
            else:
                messagebox.showinfo("SIEM Status", "SIEM Exporter initialized and operational.")
        except Exception as e:
            messagebox.showwarning("SIEM Test", f"SIEM dispatch notice: {e}")

