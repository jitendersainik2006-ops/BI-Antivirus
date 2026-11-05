"""
BI Antivirus - Threat & Scan History View
Displays audit trail of all historical scans, identified threats, and actions taken.
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, Any

from bi_antivirus.config import THEME


class HistoryView(tk.Frame):
    """Historical audit log of scan sessions and threat detections."""

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
            text="SECURITY AUDIT & THREAT HISTORY",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 14, "bold"),
            anchor="w",
        )
        title_lbl.pack(fill="x")

        desc_lbl = tk.Label(
            header_frame,
            text="Chronological record of scan executions, detected malware signatures, and response actions.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10),
            anchor="w",
        )
        desc_lbl.pack(fill="x", pady=(2, 0))

        # Main Table - Threat Detections
        table_container = tk.Frame(self, bg=THEME["bg_input"])
        table_container.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        columns = ("date", "severity", "threat_name", "family", "action", "file_path")
        self.tree = ttk.Treeview(table_container, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("date", text="DETECTED AT")
        self.tree.heading("severity", text="SEVERITY")
        self.tree.heading("threat_name", text="THREAT NAME")
        self.tree.heading("family", text="FAMILY")
        self.tree.heading("action", text="ACTION")
        self.tree.heading("file_path", text="TARGET FILE PATH")

        self.tree.column("date", width=140)
        self.tree.column("severity", width=85, anchor="center")
        self.tree.column("threat_name", width=200)
        self.tree.column("family", width=110)
        self.tree.column("action", width=110, anchor="center")
        self.tree.column("file_path", width=330)

        scrollbar = ttk.Scrollbar(table_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Bottom Bar
        bottom_bar = tk.Frame(self, bg=THEME["bg_darkest"])
        bottom_bar.pack(fill="x", padx=20, pady=(0, 20))

        self.btn_refresh = ttk.Button(
            bottom_bar,
            text="Refresh History",
            style="Secondary.TButton",
            command=self.refresh_data,
        )
        self.btn_refresh.pack(side="right")

    def refresh_data(self) -> None:
        """Query threat detections from history database."""
        self.tree.delete(*self.tree.get_children())
        records = self.engine.history_db.get_threat_history(limit=50)
        for r in records:
            self.tree.insert(
                "",
                "end",
                values=(
                    r["detected_at"],
                    r["severity"],
                    r["threat_name"],
                    r["threat_family"],
                    r["action_taken"],
                    r["file_path"],
                ),
            )
