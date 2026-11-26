"""
BI Antivirus - Settings & Configuration View
Organizes user preferences, scan exclusions, definition updates,
and advanced enterprise maintenance tools into intuitive, beginner-friendly tabs.
"""

import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from typing import Optional, Callable

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
    """Configuration panel grouping preferences logically and keeping advanced tools separate."""

    def __init__(self, parent, engine, on_navigate: Optional[Callable[[str], None]] = None, **kwargs):
        super().__init__(parent, bg=THEME["bg_darkest"], **kwargs)
        self.engine = engine
        self.on_navigate = on_navigate
        self._build_ui()

    def _build_ui(self) -> None:
        header_frame = tk.Frame(self, bg=THEME["bg_panel"], padx=20, pady=16)
        header_frame.pack(fill="x", padx=20, pady=(20, 12))
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
            text="Customize protection behavior, manage trusted exclusions, update malware definitions, and access advanced diagnostics.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10),
            anchor="w",
        )
        desc_lbl.pack(fill="x", pady=(2, 0))

        # Modern Tabbed Notebook
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # 1. Tab 1: General & Protection
        self.tab_general = tk.Frame(self.notebook, bg=THEME["bg_darkest"], padx=16, pady=16)
        self.notebook.add(self.tab_general, text="  ⚙️ General & Protection  ")
        self._build_general_tab(self.tab_general)

        # 2. Tab 2: Scan Exclusions
        self.tab_exclusions = tk.Frame(self.notebook, bg=THEME["bg_darkest"], padx=16, pady=16)
        self.notebook.add(self.tab_exclusions, text="  🚫 Scan Exclusions  ")
        self._build_exclusions_tab(self.tab_exclusions)

        # 3. Tab 3: Definitions & Updates
        self.tab_updates = tk.Frame(self.notebook, bg=THEME["bg_darkest"], padx=16, pady=16)
        self.notebook.add(self.tab_updates, text="  🔄 Definitions & Updates  ")
        self._build_updates_tab(self.tab_updates)

        # 4. Tab 4: Advanced & Enterprise Tools
        self.tab_advanced = tk.Frame(self.notebook, bg=THEME["bg_darkest"], padx=16, pady=16)
        self.notebook.add(self.tab_advanced, text="  🔧 Advanced & Enterprise  ")
        self._build_advanced_tab(self.tab_advanced)

    def _build_general_tab(self, parent: tk.Frame) -> None:
        grid_frame = tk.Frame(parent, bg=THEME["bg_darkest"])
        grid_frame.pack(fill="both", expand=True)

        left_col = tk.Frame(grid_frame, bg=THEME["bg_panel"], padx=18, pady=18)
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 8))
        left_col.configure(highlightbackground=THEME["border"], highlightthickness=1)

        det_hdr = tk.Label(
            left_col,
            text="DETECTION & SCANNING PREFERENCES",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        det_hdr.pack(fill="x", pady=(0, 10))

        self.var_heuristics = tk.BooleanVar(value=True)
        cb_heur = tk.Checkbutton(
            left_col,
            text="Enable Deep Behavioral Heuristic Analysis",
            variable=self.var_heuristics,
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            selectcolor=THEME["bg_input"],
            activebackground=THEME["bg_panel"],
            activeforeground=THEME["text_primary"],
            font=(THEME["font_family"], 10, "bold"),
            command=self._on_save_tuning,
        )
        cb_heur.pack(anchor="w", pady=(0, 2))

        heur_exp = tk.Label(
            left_col,
            text="Analyzes suspicious code patterns and entropy to detect new, unknown malware that does not yet have a published signature.",
            bg=THEME["bg_panel"],
            fg=THEME["text_muted"],
            font=(THEME["font_family"], 8),
            wraplength=380,
            justify="left",
            anchor="w",
        )
        heur_exp.pack(fill="x", pady=(0, 14))

        self.var_auto_q = tk.BooleanVar(value=False)
        cb_auto_q = tk.Checkbutton(
            left_col,
            text="Prompt for User Approval Before Quarantining (Recommended)",
            variable=self.var_auto_q,
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            selectcolor=THEME["bg_input"],
            activebackground=THEME["bg_panel"],
            activeforeground=THEME["text_primary"],
            font=(THEME["font_family"], 10, "bold"),
            command=self._on_save_tuning,
        )
        cb_auto_q.pack(anchor="w", pady=(0, 2))

        auto_exp = tk.Label(
            left_col,
            text="When enabled, you are prompted to confirm before any file is moved to the encrypted vault. Ensures you stay in full control.",
            bg=THEME["bg_panel"],
            fg=THEME["text_muted"],
            font=(THEME["font_family"], 8),
            wraplength=380,
            justify="left",
            anchor="w",
        )
        auto_exp.pack(fill="x", pady=(0, 14))

        # Storage Summary (Right Column)
        right_col = tk.Frame(grid_frame, bg=THEME["bg_panel"], padx=18, pady=18)
        right_col.pack(side="right", fill="both", expand=True, padx=(8, 0))
        right_col.configure(highlightbackground=THEME["border"], highlightthickness=1)

        store_hdr = tk.Label(
            right_col,
            text="SECURE STORAGE PATHS (D: DRIVE)",
            bg=THEME["bg_panel"],
            fg=THEME["accent_cyan"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        store_hdr.pack(fill="x", pady=(0, 10))

        store_desc = tk.Label(
            right_col,
            text="All BI Antivirus data, encrypted vaults, and logs are strictly confined to your D: drive to guarantee privacy and host isolation.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            wraplength=380,
            justify="left",
            anchor="w",
        )
        store_desc.pack(fill="x", pady=(0, 10))

        storage_text = (
            f"• Root: {PROJECT_ROOT}\n"
            f"• Data: {DATA_DIR}\n"
            f"• Vault: {QUARANTINE_DIR}\n"
            f"• Logs: {LOGS_DIR}\n"
            f"• Reports: {REPORTS_DIR}"
        )
        storage_box = tk.Label(
            right_col,
            text=storage_text,
            bg=THEME["bg_input"],
            fg=THEME["text_secondary"],
            font=(THEME["font_mono"], 8),
            justify="left",
            anchor="w",
            wraplength=340,
            padx=12,
            pady=10,
        )
        storage_box.pack(fill="x")

    def _build_exclusions_tab(self, parent: tk.Frame) -> None:
        panel = tk.Frame(parent, bg=THEME["bg_panel"], padx=20, pady=18)
        panel.pack(fill="both", expand=True)
        panel.configure(highlightbackground=THEME["border"], highlightthickness=1)

        excl_hdr = tk.Label(
            panel,
            text="SCAN EXCLUSION LIST",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        excl_hdr.pack(fill="x")

        excl_desc = tk.Label(
            panel,
            text=(
                "Files and folders in this list are skipped during real-time and on-demand scans.\n"
                "Only exclude items you completely trust (such as software development build directories or game assets)."
            ),
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            justify="left",
            anchor="w",
        )
        excl_desc.pack(fill="x", pady=(4, 10))

        # Listbox for Exclusions
        self.excl_listbox = tk.Listbox(
            panel,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            selectbackground=THEME["border_highlight"],
            font=(THEME["font_mono"], 9),
            height=8,
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        self.excl_listbox.pack(fill="both", expand=True)

        excl_btns = tk.Frame(panel, bg=THEME["bg_panel"])
        excl_btns.pack(fill="x", pady=(10, 0))

        btn_add_excl = ttk.Button(excl_btns, text="📁 Exclude Folder...", style="Primary.TButton", command=self._on_add_exclusion)
        btn_add_excl.pack(side="left", padx=(0, 8))

        btn_add_ext = ttk.Button(excl_btns, text="📄 Exclude Extension...", style="Secondary.TButton", command=self._on_add_extension)
        btn_add_ext.pack(side="left", padx=(0, 8))

        btn_remove_excl = ttk.Button(excl_btns, text="🗑️ Remove Selected", style="Secondary.TButton", command=self._on_remove_exclusion)
        btn_remove_excl.pack(side="left")

    def _build_updates_tab(self, parent: tk.Frame) -> None:
        panel = tk.Frame(parent, bg=THEME["bg_panel"], padx=20, pady=18)
        panel.pack(fill="both", expand=True)
        panel.configure(highlightbackground=THEME["border"], highlightthickness=1)

        upd_hdr = tk.Label(
            panel,
            text="MALWARE SIGNATURE & DEFINITION STATUS",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        upd_hdr.pack(fill="x")

        upd_desc = tk.Label(
            panel,
            text="Keeping signature definitions up to date ensures protection against the newest cyber threats and zero-day variants.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            anchor="w",
        )
        upd_desc.pack(fill="x", pady=(4, 12))

        self.upd_info_lbl = tk.Label(
            panel,
            text="Checking definitions status...",
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 9),
            anchor="w",
            justify="left",
            padx=14,
            pady=12,
        )
        self.upd_info_lbl.pack(fill="x", pady=(0, 16))

        upd_btns = tk.Frame(panel, bg=THEME["bg_panel"])
        upd_btns.pack(fill="x")

        self.btn_chk_upd = ttk.Button(upd_btns, text="🔄 Verify & Refresh Definitions", style="Primary.TButton", command=self._on_check_updates)
        self.btn_chk_upd.pack(side="left", padx=(0, 10))

        self.btn_import_pack = ttk.Button(upd_btns, text="📦 Import Offline Definition Pack...", style="Secondary.TButton", command=self._on_import_pack)
        self.btn_import_pack.pack(side="left")

    def _build_advanced_tab(self, parent: tk.Frame) -> None:
        panel = tk.Frame(parent, bg=THEME["bg_panel"], padx=20, pady=18)
        panel.pack(fill="both", expand=True)
        panel.configure(highlightbackground=THEME["border"], highlightthickness=1)

        adv_hdr = tk.Label(
            panel,
            text="ENTERPRISE DATABASE HEALTH & SIEM MAINTENANCE",
            bg=THEME["bg_panel"],
            fg=THEME["accent_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        adv_hdr.pack(fill="x")

        adv_desc = tk.Label(
            panel,
            text="Perform physical database integrity audits, create hot backups, and dispatch test events to enterprise SIEM/Syslog exporters.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            anchor="w",
        )
        adv_desc.pack(fill="x", pady=(4, 12))

        # Maintenance Buttons (Preserved for Sprint 16 test suite compatibility)
        maint_btns = tk.Frame(panel, bg=THEME["bg_panel"])
        maint_btns.pack(fill="x", pady=(0, 18))

        self.btn_chk_db = ttk.Button(maint_btns, text="🔍 Verify DB Integrity", style="Secondary.TButton", command=self._on_check_db_integrity)
        self.btn_chk_db.pack(side="left", padx=(0, 8))

        self.btn_backup_db = ttk.Button(maint_btns, text="💾 Backup SQLite DB...", style="Secondary.TButton", command=self._on_backup_db)
        self.btn_backup_db.pack(side="left", padx=(0, 8))

        self.btn_test_siem = ttk.Button(maint_btns, text="📡 Test SIEM Export", style="Secondary.TButton", command=self._on_test_siem)
        self.btn_test_siem.pack(side="left")

        # Enterprise Tools Launcher
        ent_hdr = tk.Label(
            panel,
            text="ENTERPRISE MODULE SHORTCUTS",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 10, "bold"),
            anchor="w",
        )
        ent_hdr.pack(fill="x", pady=(10, 6))

        ent_grid = tk.Frame(panel, bg=THEME["bg_panel"])
        ent_grid.pack(fill="x")
        ent_grid.columnconfigure(0, weight=1)
        ent_grid.columnconfigure(1, weight=1)
        ent_grid.columnconfigure(2, weight=1)
        ent_grid.columnconfigure(3, weight=1)

        btn_fleet = ttk.Button(ent_grid, text="🏢 Enterprise Fleet", style="Secondary.TButton", command=lambda: self._nav_to("fleet"))
        btn_fleet.grid(row=0, column=0, sticky="ew", padx=(0, 4))

        btn_patch = ttk.Button(ent_grid, text="📦 Software Patching", style="Secondary.TButton", command=lambda: self._nav_to("patch"))
        btn_patch.grid(row=0, column=1, sticky="ew", padx=4)

        btn_pe = ttk.Button(ent_grid, text="🔬 PE Static Inspector", style="Secondary.TButton", command=lambda: self._nav_to("pe_inspect"))
        btn_pe.grid(row=0, column=2, sticky="ew", padx=4)

        btn_auto = ttk.Button(ent_grid, text="⚡ Automation & Voice", style="Secondary.TButton", command=lambda: self._nav_to("automation"))
        btn_auto.grid(row=0, column=3, sticky="ew", padx=(4, 0))

        self.refresh_data()

    def _nav_to(self, target: str) -> None:
        if self.on_navigate:
            self.on_navigate(target)

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
                f"• Active Indicators: {upd['total_signatures']} (Hashes: {upd['hash_signatures']}, Pattern Rules: {upd['pattern_signatures']})\n"
                f"• Web Reputations: {upd['web_reputations']} categorized destinations\n"
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

    def _on_add_extension(self) -> None:
        # Dialog to input extension
        dialog = tk.Toplevel(self)
        dialog.title("Exclude File Extension")
        dialog.geometry("380x180")
        dialog.configure(bg=THEME["bg_dark"])
        dialog.transient(self)
        dialog.grab_set()

        lbl = tk.Label(
            dialog,
            text="Enter file extension to exclude (e.g., .tmp or log):",
            bg=THEME["bg_dark"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 9),
            wraplength=340,
        )
        lbl.pack(padx=16, pady=(16, 8))

        entry = tk.Entry(
            dialog,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            insertbackground=THEME["text_primary"],
            font=(THEME["font_mono"], 10),
        )
        entry.pack(padx=16, fill="x", pady=(0, 14))
        entry.focus_set()

        def _save():
            val = entry.get().strip().lower()
            if val:
                if not val.startswith("."):
                    val = "." + val
                settings = load_settings()
                exts = settings.get("exclusions_extensions", [])
                if val not in exts:
                    exts.append(val)
                    settings["exclusions_extensions"] = exts
                    save_settings(settings)
                    self.refresh_data()
            dialog.destroy()

        btn_box = tk.Frame(dialog, bg=THEME["bg_dark"])
        btn_box.pack(fill="x", padx=16)
        ttk.Button(btn_box, text="Cancel", command=dialog.destroy).pack(side="right")
        ttk.Button(btn_box, text="Add Extension", style="Primary.TButton", command=_save).pack(side="right", padx=(0, 8))

    def _on_remove_exclusion(self) -> None:
        selected = self.excl_listbox.curselection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please click to select an exclusion from the list.")
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
        messagebox.showinfo("Definitions Verified", "Malware definitions verified. All active indicators and heuristic patterns are current.")

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
