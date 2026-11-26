"""
BI Antivirus - Scan View
Real-time scanning dashboard with progress bars, live file ticker, telemetry,
quick scan launchers, understandable completion summaries, and threat resolution.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from typing import Dict, Any, Optional, Callable

from bi_antivirus.config import THEME


class ScanView(tk.Frame):
    """Active scan progress monitor, scan launcher, and real-time threat resolution view."""

    def __init__(
        self,
        parent,
        engine,
        on_start_quick_scan: Optional[Callable[[], None]] = None,
        on_start_full_scan: Optional[Callable[[], None]] = None,
        on_start_custom_scan: Optional[Callable[[Path], None]] = None,
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

    def _build_ui(self) -> None:
        # 1. Header & Launch Controls Box
        header_frame = tk.Frame(self, bg=THEME["bg_panel"], padx=20, pady=16)
        header_frame.pack(fill="x", padx=20, pady=(20, 12))
        header_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        # Header Title Row
        title_row = tk.Frame(header_frame, bg=THEME["bg_panel"])
        title_row.pack(fill="x")

        self.scan_title_lbl = tk.Label(
            title_row,
            text="SCAN CENTER",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 14, "bold"),
            anchor="w",
        )
        self.scan_title_lbl.pack(side="left")

        # Scan Launcher Quick Buttons
        launch_btns = tk.Frame(title_row, bg=THEME["bg_panel"])
        launch_btns.pack(side="right")

        self.btn_run_quick = ttk.Button(
            launch_btns,
            text="⚡ Quick Scan",
            style="Primary.TButton",
            command=self._launch_quick,
        )
        self.btn_run_quick.pack(side="left", padx=(0, 6))

        self.btn_run_full = ttk.Button(
            launch_btns,
            text="🛡️ Full Scan",
            style="Secondary.TButton",
            command=self._launch_full,
        )
        self.btn_run_full.pack(side="left", padx=(0, 6))

        self.btn_run_custom = ttk.Button(
            launch_btns,
            text="📁 Custom Scan...",
            style="Secondary.TButton",
            command=self._launch_custom,
        )
        self.btn_run_custom.pack(side="left")

        self.scan_desc_lbl = tk.Label(
            header_frame,
            text="Ready to scan. Select a scan type above or click Quick Scan to begin.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10),
            anchor="w",
        )
        self.scan_desc_lbl.pack(fill="x", pady=(8, 10))

        # Progress bar
        self.progress_bar = ttk.Progressbar(
            header_frame,
            style="Cyber.Horizontal.TProgressbar",
            mode="indeterminate",
        )
        self.progress_bar.pack(fill="x", pady=(0, 10))

        # Current File Ticker
        ticker_frame = tk.Frame(header_frame, bg=THEME["bg_input"], padx=10, pady=6)
        ticker_frame.pack(fill="x")

        self.current_file_lbl = tk.Label(
            ticker_frame,
            text="Current File: Idle",
            bg=THEME["bg_input"],
            fg=THEME["text_muted"],
            font=(THEME["font_mono"], 8),
            anchor="w",
        )
        self.current_file_lbl.pack(fill="x")

        # Telemetry metrics row
        telemetry_row = tk.Frame(header_frame, bg=THEME["bg_panel"])
        telemetry_row.pack(fill="x", pady=(12, 0))

        self.metric_scanned = tk.Label(
            telemetry_row,
            text="Files Scanned: 0",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 9, "bold"),
        )
        self.metric_scanned.pack(side="left", padx=(0, 20))

        self.metric_threats = tk.Label(
            telemetry_row,
            text="Threats Found: 0",
            bg=THEME["bg_panel"],
            fg=THEME["status_safe"],
            font=(THEME["font_family"], 9, "bold"),
        )
        self.metric_threats.pack(side="left", padx=(0, 20))

        self.metric_rate = tk.Label(
            telemetry_row,
            text="Speed: 0.0 f/s",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
        )
        self.metric_rate.pack(side="left", padx=(0, 20))

        self.metric_duration = tk.Label(
            telemetry_row,
            text="Duration: 0.0s",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
        )
        self.metric_duration.pack(side="left")

        # Control Buttons
        self.btn_cancel = ttk.Button(
            telemetry_row,
            text="Stop Scan",
            style="Danger.TButton",
            command=self._on_cancel,
        )
        self.btn_cancel.pack(side="right")

        # 2. Completion Summary Card (Hidden when idle/scanning, shown on finish)
        self.summary_frame = tk.Frame(self, bg=THEME["bg_panel"], padx=16, pady=12)
        self.summary_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        self.summary_icon = tk.Label(
            self.summary_frame,
            text="✓",
            bg=THEME["bg_panel"],
            fg=THEME["status_safe"],
            font=(THEME["font_family"], 18, "bold"),
        )
        self.summary_icon.pack(side="left", padx=(0, 12))

        summary_text_col = tk.Frame(self.summary_frame, bg=THEME["bg_panel"])
        summary_text_col.pack(side="left", fill="both", expand=True)

        self.summary_title = tk.Label(
            summary_text_col,
            text="Scan Finished: No Threats Found!",
            bg=THEME["bg_panel"],
            fg=THEME["status_safe"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        self.summary_title.pack(fill="x")

        self.summary_detail = tk.Label(
            summary_text_col,
            text="All scanned files passed signature and heuristic analysis. Your system is safe.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            anchor="w",
        )
        self.summary_detail.pack(fill="x", pady=(2, 0))

        # 3. Detected Threats Table Section
        threats_section = tk.Frame(self, bg=THEME["bg_darkest"])
        threats_section.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        section_hdr = tk.Label(
            threats_section,
            text="DETECTED THREATS IN ACTIVE SESSION",
            bg=THEME["bg_darkest"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10, "bold"),
            anchor="w",
        )
        section_hdr.pack(fill="x", pady=(5, 6))

        # Table container
        table_frame = tk.Frame(threats_section, bg=THEME["bg_input"])
        table_frame.pack(fill="both", expand=True)

        columns = ("severity", "threat_name", "family", "risk", "file_path")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("severity", text="RISK LEVEL")
        self.tree.heading("threat_name", text="THREAT NAME")
        self.tree.heading("family", text="CATEGORY")
        self.tree.heading("risk", text="SCORE")
        self.tree.heading("file_path", text="FILE LOCATION")

        self.tree.column("severity", width=90, minwidth=75, anchor="center")
        self.tree.column("threat_name", width=190, minwidth=140)
        self.tree.column("family", width=110, minwidth=90)
        self.tree.column("risk", width=65, minwidth=50, anchor="center")
        self.tree.column("file_path", width=300, minwidth=180)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Threat Action Controls & Plain-English Explanations
        action_bar = tk.Frame(threats_section, bg=THEME["bg_darkest"])
        action_bar.pack(fill="x", pady=(10, 0))

        self.btn_quarantine = ttk.Button(
            action_bar,
            text="📦 Quarantine Selected Threat",
            style="Primary.TButton",
            command=self._on_quarantine_selected,
        )
        self.btn_quarantine.pack(side="left", padx=(0, 14))

        self.help_lbl = tk.Label(
            action_bar,
            text="💡 Quarantining safely locks away the threat in an encrypted vault so it cannot harm your PC.",
            bg=THEME["bg_darkest"],
            fg=THEME["text_muted"],
            font=(THEME["font_family"], 9),
            anchor="w",
        )
        self.help_lbl.pack(side="left", fill="x", expand=True)

    def _launch_quick(self) -> None:
        if self.on_start_quick_scan:
            self.on_start_quick_scan()
        else:
            self.engine.start_quick_scan(progress_cb=self.update_progress)

    def _launch_full(self) -> None:
        if self.on_start_full_scan:
            self.on_start_full_scan()
        else:
            self.engine.start_full_scan(progress_cb=self.update_progress)

    def _launch_custom(self) -> None:
        folder = filedialog.askdirectory(title="Select Folder to Scan with BI Antivirus")
        if folder:
            p = Path(folder)
            if self.on_start_custom_scan:
                self.on_start_custom_scan(p)
            else:
                self.engine.start_custom_scan(p, progress_cb=self.update_progress)

    def update_progress(self, p: Dict[str, Any]) -> None:
        """Called by scanner worker callback."""
        is_scanning = p.get("is_scanning", False)
        scan_type = p.get("scan_type", "Standard")
        threats_n = p.get("threats_count", 0)

        if is_scanning:
            self.summary_frame.pack_forget()
            if str(self.progress_bar.cget("mode")) != "indeterminate":
                self.progress_bar.config(mode="indeterminate")
            self.progress_bar.step(3)
            self.scan_desc_lbl.config(text=f"Scanning in progress ({scan_type} Scan)...")
            self.btn_run_quick.state(["disabled"])
            self.btn_run_full.state(["disabled"])
            self.btn_run_custom.state(["disabled"])
        else:
            self.progress_bar.stop()
            self.btn_run_quick.state(["!disabled"])
            self.btn_run_full.state(["!disabled"])
            self.btn_run_custom.state(["!disabled"])

            # Show completion summary
            self.summary_frame.pack(fill="x", padx=20, pady=(0, 10), before=self.tree.master.master)
            if threats_n > 0:
                self.scan_desc_lbl.config(text=f"Scan completed: {threats_n} threat(s) detected. Please review below.")
                self.summary_icon.config(text="⚠️", fg=THEME["status_threat"])
                self.summary_title.config(
                    text=f"Scan Finished: {threats_n} Threat(s) Found!",
                    fg=THEME["status_threat"],
                )
                self.summary_detail.config(
                    text="Select the detected items below and click 'Quarantine Selected Threat' to neutralize them.",
                    fg=THEME["text_primary"],
                )
            else:
                self.scan_desc_lbl.config(text=f"Scan completed: All {p.get('files_scanned', 0):,} files evaluated clean. Zero threats detected.")
                self.summary_icon.config(text="✓", fg=THEME["status_safe"])
                self.summary_title.config(
                    text="Scan Finished: No Threats Found!",
                    fg=THEME["status_safe"],
                )
                self.summary_detail.config(
                    text=f"Evaluated {p.get('files_scanned', 0):,} files in {p.get('elapsed_seconds', 0.0):.1f}s. Your computer is clean and safe.",
                    fg=THEME["text_secondary"],
                )

        file_disp = p.get("current_file", "")
        if len(file_disp) > 80:
            file_disp = "..." + file_disp[-77:]
        if is_scanning:
            self.current_file_lbl.config(text=f"Scanning: {file_disp}")
        else:
            self.current_file_lbl.config(text=f"Status: Scan complete ({p.get('files_scanned', 0):,} files evaluated)")

        self.metric_scanned.config(text=f"Files Scanned: {p.get('files_scanned', 0):,}")
        if threats_n > 0:
            self.metric_threats.config(text=f"Threats Found: {threats_n}", fg=THEME["status_threat"])
        else:
            self.metric_threats.config(text="Threats Found: 0", fg=THEME["status_safe"])

        self.metric_rate.config(text=f"Speed: {p.get('scan_rate_fps', 0.0):.1f} f/s")
        self.metric_duration.config(text=f"Duration: {p.get('elapsed_seconds', 0.0):.1f}s")

        # Refresh threats in table
        current_threats = self.engine.scanner.threats_found
        existing_items = self.tree.get_children()
        if len(existing_items) != len(current_threats):
            self.tree.delete(*existing_items)
            for t in current_threats:
                self.tree.insert(
                    "",
                    "end",
                    values=(
                        t.get("severity", "HIGH"),
                        t.get("threat_name", "Unknown"),
                        t.get("threat_family", "Generic"),
                        f"{t.get('risk_score', 0)}%",
                        t.get("file_path", ""),
                    ),
                )

    def refresh_data(self) -> None:
        """Refresh detected threats from engine scanner session if present."""
        current_threats = getattr(self.engine.scanner, "threats_found", [])
        existing_items = self.tree.get_children()
        if len(existing_items) != len(current_threats):
            self.tree.delete(*existing_items)
            for t in current_threats:
                self.tree.insert(
                    "",
                    "end",
                    values=(
                        t.get("severity", "HIGH"),
                        t.get("threat_name", "Unknown"),
                        t.get("threat_family", "Generic"),
                        f"{t.get('risk_score', 0)}%",
                        t.get("file_path", ""),
                    ),
                )
        if current_threats:
            self.metric_threats.config(text=f"Threats Found: {len(current_threats)}", fg=THEME["status_threat"])
        else:
            self.metric_threats.config(text="Threats Found: 0", fg=THEME["status_safe"])

    def _on_cancel(self) -> None:
        if messagebox.askyesno("Stop Scan", "Are you sure you want to stop the current scan?"):
            self.engine.cancel_scan()
            self.scan_desc_lbl.config(text="Scan cancellation requested.")

    def _on_quarantine_selected(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Quarantine", "Please select a detected threat from the table to quarantine.")
            return

        item = self.tree.item(selected[0])
        values = item.get("values", [])
        if not values:
            return

        file_path_str = values[4]
        threat_name = values[1]

        # Confirmation before action (never auto-delete or silently move)
        confirm = messagebox.askyesno(
            "Confirm Quarantine",
            f"Are you sure you want to quarantine this file?\n\n"
            f"File: {file_path_str}\n"
            f"Threat: {threat_name}\n\n"
            "The file will be encrypted and safely moved to the Quarantine Vault.\n"
            "You can safely restore it at any time if needed.",
        )
        if not confirm:
            return

        # Locate matching threat in engine scanner
        target_threat = None
        for t in self.engine.scanner.threats_found:
            if t.get("file_path") == file_path_str:
                target_threat = t
                break

        if not target_threat:
            target_threat = {
                "file_path": file_path_str,
                "threat_name": values[1],
                "threat_family": values[2],
                "severity": values[0],
            }

        res = self.engine.quarantine_threat(target_threat)
        if res.get("success"):
            messagebox.showinfo(
                "Quarantine Successful",
                f"Threat has been safely isolated in the encrypted vault.\n\nQuarantine ID: {res['quarantine_id']}\nFile: {target_threat['threat_name']}",
            )
            self.tree.delete(selected[0])
        else:
            messagebox.showerror("Quarantine Error", f"Failed isolating threat: {res.get('error')}")
