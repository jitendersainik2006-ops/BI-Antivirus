"""
BI Antivirus - Threat & Scan History View
Displays audit trail of all historical scans, identified threats, and actions taken
with beginner-friendly empty states and clear risk level indicators.
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, Any

from bi_antivirus.config import THEME
from bi_antivirus.ui.widgets.cards import EmptyStateCard


class HistoryView(tk.Frame):
    """Historical audit log of scan sessions and threat detections."""

    def __init__(self, parent, engine, **kwargs):
        super().__init__(parent, bg=THEME["bg_darkest"], **kwargs)
        self.engine = engine
        self._build_ui()

    def _build_ui(self) -> None:
        header_frame = tk.Frame(self, bg=THEME["bg_panel"], padx=20, pady=16)
        header_frame.pack(fill="x", padx=20, pady=(20, 12))
        header_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        title_lbl = tk.Label(
            header_frame,
            text="THREAT HISTORY & AUDIT LOG",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 14, "bold"),
            anchor="w",
        )
        title_lbl.pack(fill="x")

        desc_lbl = tk.Label(
            header_frame,
            text="Chronological record of scan executions, detected malware signatures, and response actions taken.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10),
            anchor="w",
        )
        desc_lbl.pack(fill="x", pady=(2, 0))

        # Main Table Container
        self.table_container = tk.Frame(self, bg=THEME["bg_input"])
        self.table_container.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        columns = ("date", "severity", "threat_name", "family", "action", "file_path")
        self.tree = ttk.Treeview(self.table_container, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("date", text="DATE & TIME")
        self.tree.heading("severity", text="RISK LEVEL")
        self.tree.heading("threat_name", text="THREAT NAME")
        self.tree.heading("family", text="CATEGORY")
        self.tree.heading("action", text="ACTION TAKEN")
        self.tree.heading("file_path", text="FILE LOCATION")

        self.tree.column("date", width=130, minwidth=110)
        self.tree.column("severity", width=85, minwidth=70, anchor="center")
        self.tree.column("threat_name", width=180, minwidth=130)
        self.tree.column("family", width=100, minwidth=80)
        self.tree.column("action", width=110, minwidth=90, anchor="center")
        self.tree.column("file_path", width=210, minwidth=140)

        scrollbar = ttk.Scrollbar(self.table_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Empty State Card
        self.empty_card = EmptyStateCard(
            self.table_container,
            icon="📜",
            title="Scan History is Clean",
            message="No threats have been recorded on this computer. Past scans found zero malware.",
        )

        # Bottom Bar
        bottom_bar = tk.Frame(self, bg=THEME["bg_darkest"])
        bottom_bar.pack(fill="x", padx=20, pady=(0, 20))

        self.btn_refresh = ttk.Button(
            bottom_bar,
            text="🔄 Refresh History",
            style="Secondary.TButton",
            command=self.refresh_data,
        )
        self.btn_refresh.pack(side="right")

    def refresh_data(self) -> None:
        """Query threat detections from history database."""
        self.tree.delete(*self.tree.get_children())
        records = self.engine.history_db.get_threat_history(limit=50)

        if not records:
            self.tree.pack_forget()
            self.empty_card.pack(fill="both", expand=True)
        else:
            self.empty_card.pack_forget()
            self.tree.pack(side="left", fill="both", expand=True)
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
