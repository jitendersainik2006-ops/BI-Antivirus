"""
BI Antivirus - Scan View
Real-time scanning dashboard with progress bars, live file ticker, telemetry,
and detected threats table with immediate quarantine actions.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, Any, Optional

from bi_antivirus.config import THEME


class ScanView(tk.Frame):
    """Active scan progress monitor and real-time threat resolution view."""

    def __init__(self, parent, engine, **kwargs):
        super().__init__(parent, bg=THEME["bg_darkest"], **kwargs)
        self.engine = engine
        self._build_ui()

    def _build_ui(self) -> None:
        # Header Box
        header_frame = tk.Frame(self, bg=THEME["bg_panel"], padx=20, pady=16)
        header_frame.pack(fill="x", padx=20, pady=(20, 15))
        header_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        self.scan_title_lbl = tk.Label(
            header_frame,
            text="SCAN CENTER",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 14, "bold"),
            anchor="w",
        )
        self.scan_title_lbl.pack(fill="x")

        self.scan_desc_lbl = tk.Label(
            header_frame,
            text="Ready to perform high-speed on-demand file analysis.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10),
            anchor="w",
        )
        self.scan_desc_lbl.pack(fill="x", pady=(2, 10))

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

        # 2. Detected Threats Table
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

        self.tree.heading("severity", text="SEVERITY")
        self.tree.heading("threat_name", text="THREAT NAME")
        self.tree.heading("family", text="FAMILY")
        self.tree.heading("risk", text="RISK")
        self.tree.heading("file_path", text="TARGET FILE PATH")

        self.tree.column("severity", width=90, anchor="center")
        self.tree.column("threat_name", width=220)
        self.tree.column("family", width=120)
        self.tree.column("risk", width=70, anchor="center")
        self.tree.column("file_path", width=360)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Threat Action Controls
        action_bar = tk.Frame(threats_section, bg=THEME["bg_darkest"])
        action_bar.pack(fill="x", pady=(10, 0))

        self.btn_quarantine = ttk.Button(
            action_bar,
            text="Quarantine Selected Threat",
            style="Primary.TButton",
            command=self._on_quarantine_selected,
        )
        self.btn_quarantine.pack(side="left", padx=(0, 10))

    def update_progress(self, p: Dict[str, Any]) -> None:
        """Called by scanner worker callback."""
        is_scanning = p.get("is_scanning", False)
        if is_scanning:
            if str(self.progress_bar.cget("mode")) != "indeterminate":
                self.progress_bar.config(mode="indeterminate")
            self.progress_bar.step(3)
            self.scan_desc_lbl.config(text=f"Scanning target hotspots ({p.get('scan_type')} Scan)...")
        else:
            self.progress_bar.stop()
            self.scan_desc_lbl.config(text=f"Scan {p.get('scan_type')} finished. Review any detected threats below.")

        file_disp = p.get("current_file", "")
        if len(file_disp) > 80:
            file_disp = "..." + file_disp[-77:]
        self.current_file_lbl.config(text=f"Scanning: {file_disp}")

        self.metric_scanned.config(text=f"Files Scanned: {p.get('files_scanned', 0):,}")
        threats_count = p.get("threats_count", 0)
        if threats_count > 0:
            self.metric_threats.config(text=f"Threats Found: {threats_count}", fg=THEME["status_threat"])
        else:
            self.metric_threats.config(text="Threats Found: 0", fg=THEME["status_safe"])

        self.metric_rate.config(text=f"Speed: {p.get('scan_rate_fps', 0.0)} f/s")
        self.metric_duration.config(text=f"Duration: {p.get('elapsed_seconds', 0.0)}s")

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

    def _on_cancel(self) -> None:
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
                f"Threat has been safely isolated in the encrypted vault.\nQuarantine ID: {res['quarantine_id']}",
            )
            self.tree.delete(selected[0])
        else:
            messagebox.showerror("Quarantine Error", f"Failed isolating threat: {res.get('error')}")
