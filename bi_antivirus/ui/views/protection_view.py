"""
BI Antivirus - Real-Time & Web Protection View
Controls background filesystem guard, monitored directory locations,
and provides on-demand URL and domain reputation checking.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path

from bi_antivirus.config import THEME, load_settings, save_settings


class ProtectionView(tk.Frame):
    """Real-Time sentinel controls and interactive web reputation shield."""

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
            text="REAL-TIME & WEB PROTECTION",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 14, "bold"),
            anchor="w",
        )
        title_lbl.pack(fill="x")

        desc_lbl = tk.Label(
            header_frame,
            text="Continuous background filesystem monitoring and web destination reputation filtering.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10),
            anchor="w",
        )
        desc_lbl.pack(fill="x", pady=(2, 0))

        content_frame = tk.Frame(self, bg=THEME["bg_darkest"])
        content_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # 1. Left Panel - Real-Time Sentinel & Folders
        left_col = tk.Frame(content_frame, bg=THEME["bg_panel"], padx=16, pady=16)
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 10))
        left_col.configure(highlightbackground=THEME["border"], highlightthickness=1)

        rt_hdr = tk.Label(
            left_col,
            text="REAL-TIME FILE GUARD",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        rt_hdr.pack(fill="x")

        self.rt_status_lbl = tk.Label(
            left_col,
            text="Status: ACTIVE (Monitoring Downloads, Desktop, Temp)",
            bg=THEME["bg_panel"],
            fg=THEME["status_safe"],
            font=(THEME["font_family"], 9, "bold"),
            anchor="w",
        )
        self.rt_status_lbl.pack(fill="x", pady=(4, 12))

        # Toggle Button
        self.btn_toggle_rt = ttk.Button(
            left_col,
            text="Pause Guard",
            style="Secondary.TButton",
            command=self._on_toggle_realtime,
        )
        self.btn_toggle_rt.pack(anchor="w", pady=(0, 15))

        folders_lbl = tk.Label(
            left_col,
            text="MONITORED DIRECTORIES",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9, "bold"),
            anchor="w",
        )
        folders_lbl.pack(fill="x", pady=(0, 6))

        # Listbox for Monitored Folders
        self.folders_listbox = tk.Listbox(
            left_col,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            selectbackground=THEME["border_highlight"],
            font=(THEME["font_mono"], 9),
            height=6,
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        self.folders_listbox.pack(fill="both", expand=True)

        folder_btns = tk.Frame(left_col, bg=THEME["bg_panel"])
        folder_btns.pack(fill="x", pady=(8, 0))

        btn_add = ttk.Button(folder_btns, text="Add Folder...", style="Primary.TButton", command=self._on_add_folder)
        btn_add.pack(side="left", padx=(0, 8))

        btn_remove = ttk.Button(folder_btns, text="Remove", style="Secondary.TButton", command=self._on_remove_folder)
        btn_remove.pack(side="left")

        # Active Defense Sentinels Telemetry Box
        sentinels_frame = tk.Frame(left_col, bg=THEME["bg_input"], padx=12, pady=10)
        sentinels_frame.pack(fill="x", pady=(14, 0))
        sentinels_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        st_title = tk.Label(
            sentinels_frame,
            text="ACTIVE DEFENSE SENTINELS",
            bg=THEME["bg_input"],
            fg=THEME["accent_cyan"],
            font=(THEME["font_family"], 9, "bold"),
            anchor="w",
        )
        st_title.pack(fill="x", pady=(0, 4))

        self.sentinel_rows = {}
        for s_key, s_name in [
            ("behavioral", "Behavioral Process Monitor"),
            ("ransomware", "Ransomware Honeypot Shield"),
            ("usb", "Removable USB Sentinel"),
            ("authenticode", "Authenticode WinTrust Verifier"),
        ]:
            s_row = tk.Label(
                sentinels_frame,
                text=f"● {s_name}: ACTIVE",
                bg=THEME["bg_input"],
                fg=THEME["status_safe"],
                font=(THEME["font_family"], 8),
                anchor="w",
            )
            s_row.pack(fill="x", pady=1)
            self.sentinel_rows[s_key] = s_row

        # 2. Right Panel - Web Protection Tester
        right_col = tk.Frame(content_frame, bg=THEME["bg_panel"], padx=16, pady=16)
        right_col.pack(side="right", fill="both", expand=True, padx=(10, 0))
        right_col.configure(highlightbackground=THEME["border"], highlightthickness=1)

        web_hdr = tk.Label(
            right_col,
            text="WEB & DOMAIN REPUTATION SHIELD",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        web_hdr.pack(fill="x")

        web_desc = tk.Label(
            right_col,
            text="Audit any web link or domain for phishing, credential harvesters, or malware distribution.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            anchor="w",
            wraplength=320,
            justify="left",
        )
        web_desc.pack(fill="x", pady=(4, 14))

        url_lbl = tk.Label(
            right_col,
            text="URL / DOMAIN TO INSPECT:",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9, "bold"),
            anchor="w",
        )
        url_lbl.pack(fill="x", pady=(0, 4))

        self.url_entry = tk.Entry(
            right_col,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            insertbackground=THEME["text_primary"],
            font=(THEME["font_mono"], 10),
            highlightbackground=THEME["border"],
            highlightthickness=1,
            relief="flat",
        )
        self.url_entry.insert(0, "https://phishing-bank-update.test/login")
        self.url_entry.pack(fill="x", ipady=6, pady=(0, 10))

        btn_check = ttk.Button(right_col, text="Check Web Reputation", style="Primary.TButton", command=self._on_check_url)
        btn_check.pack(anchor="w", pady=(0, 15))

        # Result Card Box
        self.web_result_frame = tk.Frame(right_col, bg=THEME["bg_input"], padx=12, pady=12)
        self.web_result_frame.pack(fill="both", expand=True)
        self.web_result_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        self.web_result_title = tk.Label(
            self.web_result_frame,
            text="Ready to inspect URL",
            bg=THEME["bg_input"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10, "bold"),
            anchor="w",
        )
        self.web_result_title.pack(fill="x")

        self.web_result_details = tk.Label(
            self.web_result_frame,
            text="Enter a domain or web address above to query reputation and heuristic risk parameters.",
            bg=THEME["bg_input"],
            fg=THEME["text_muted"],
            font=(THEME["font_family"], 9),
            anchor="w",
            wraplength=300,
            justify="left",
        )
        self.web_result_details.pack(fill="x", pady=(4, 0))

        self.refresh_data()

    def refresh_data(self) -> None:
        """Refresh monitored directories list and real-time guard state."""
        settings = load_settings()
        self.folders_listbox.delete(0, tk.END)
        for folder in settings.get("monitored_directories", []):
            self.folders_listbox.insert(tk.END, folder)

        is_guard_active = self.engine.realtime_guard.is_running
        if is_guard_active:
            self.rt_status_lbl.config(text="Status: ACTIVE (Filesystem Sentinel Guarding)", fg=THEME["status_safe"])
            self.btn_toggle_rt.config(text="Stop Guard")
        else:
            self.rt_status_lbl.config(text="Status: INACTIVE (Guard Paused)", fg=THEME["status_warning"])
            self.btn_toggle_rt.config(text="Start Guard")

        if hasattr(self, "sentinel_rows"):
            b_act = self.engine.behavioral_monitor.is_running
            self.sentinel_rows["behavioral"].config(
                text=f"● Behavioral Process Monitor: {'ACTIVE' if b_act else 'STANDBY'}",
                fg=THEME["status_safe"] if b_act else THEME["text_muted"],
            )
            r_act = self.engine.ransomware_shield.is_running
            c_cnt = len(self.engine.ransomware_shield.canaries)
            self.sentinel_rows["ransomware"].config(
                text=f"● Ransomware Honeypot Shield: {'ACTIVE' if r_act else 'STANDBY'} ({c_cnt} Canaries)",
                fg=THEME["status_safe"] if r_act else THEME["text_muted"],
            )
            u_act = self.engine.usb_sentinel.is_running
            self.sentinel_rows["usb"].config(
                text=f"● Removable USB Sentinel: {'ACTIVE' if u_act else 'STANDBY'}",
                fg=THEME["status_safe"] if u_act else THEME["text_muted"],
            )
            self.sentinel_rows["authenticode"].config(
                text="● Authenticode WinTrust Verifier: ACTIVE (Kernel32/WinTrust)",
                fg=THEME["status_safe"],
            )

    def _on_toggle_realtime(self) -> None:
        if self.engine.realtime_guard.is_running:
            self.engine.realtime_guard.stop()
        else:
            self.engine.realtime_guard.start()
        self.refresh_data()

    def _on_add_folder(self) -> None:
        new_dir = filedialog.askdirectory(title="Select Folder to Monitor in Real-Time")
        if new_dir:
            settings = load_settings()
            dirs = settings.get("monitored_directories", [])
            if new_dir not in dirs:
                dirs.append(new_dir)
                settings["monitored_directories"] = dirs
                save_settings(settings)
                self.engine.realtime_guard.update_monitored_paths()
                self.refresh_data()

    def _on_remove_folder(self) -> None:
        selected = self.folders_listbox.curselection()
        if not selected:
            return
        folder = self.folders_listbox.get(selected[0])
        settings = load_settings()
        dirs = settings.get("monitored_directories", [])
        if folder in dirs:
            dirs.remove(folder)
            settings["monitored_directories"] = dirs
            save_settings(settings)
            self.engine.realtime_guard.update_monitored_paths()
            self.refresh_data()

    def _on_check_url(self) -> None:
        url = self.url_entry.get().strip()
        if not url:
            return

        res = self.engine.web_shield.check_url(url)
        if res.get("is_threat"):
            self.web_result_title.config(text=f"⚠️ BLOCKED: {res.get('threat_name')}", fg=THEME["status_threat"])
            self.web_result_details.config(
                text=f"Severity: {res.get('severity')}\nRisk Score: {res.get('risk_score', 0)}/100\nReason: {res.get('reason')}",
                fg=THEME["text_primary"],
            )
        else:
            self.web_result_title.config(text="✓ CLEAN: Destination Verified", fg=THEME["status_safe"])
            self.web_result_details.config(
                text=f"No threat indicators found in local reputation database.\nRisk Score: {res.get('risk_score', 0)}/100",
                fg=THEME["text_secondary"],
            )
