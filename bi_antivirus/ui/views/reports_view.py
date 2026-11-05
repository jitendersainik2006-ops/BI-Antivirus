"""
BI Antivirus - Security Reports View
Generates, displays, and archives comprehensive security audit assessment reports on D: drive.
"""

import os
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from typing import Optional

from bi_antivirus.config import THEME, REPORTS_DIR


class ReportsView(tk.Frame):
    """Generates and previews security scan and compliance assessment reports."""

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
            text="SECURITY AUDIT REPORTS",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 14, "bold"),
            anchor="w",
        )
        title_lbl.pack(fill="x")

        desc_lbl = tk.Label(
            header_frame,
            text=f"Formal security assessment reports and telemetry diagnostics stored securely on D: drive: {REPORTS_DIR}",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10),
            anchor="w",
        )
        desc_lbl.pack(fill="x", pady=(2, 0))

        content_frame = tk.Frame(self, bg=THEME["bg_darkest"])
        content_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Left Column - Report File List
        left_col = tk.Frame(content_frame, bg=THEME["bg_panel"], padx=14, pady=14, width=280)
        left_col.pack(side="left", fill="y", padx=(0, 10))
        left_col.configure(highlightbackground=THEME["border"], highlightthickness=1)
        left_col.pack_propagate(False)

        list_hdr = tk.Label(
            left_col,
            text="AVAILABLE REPORTS",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9, "bold"),
            anchor="w",
        )
        list_hdr.pack(fill="x", pady=(0, 6))

        self.reports_listbox = tk.Listbox(
            left_col,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            selectbackground=THEME["border_highlight"],
            font=(THEME["font_mono"], 9),
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        self.reports_listbox.pack(fill="both", expand=True)
        self.reports_listbox.bind("<<ListboxSelect>>", self._on_select_report)

        btn_gen = ttk.Button(
            left_col,
            text="Generate Report",
            style="Primary.TButton",
            command=self._on_generate_report,
        )
        btn_gen.pack(fill="x", pady=(8, 0))

        # Right Column - Report Preview Pane
        right_col = tk.Frame(content_frame, bg=THEME["bg_panel"], padx=14, pady=14)
        right_col.pack(side="right", fill="both", expand=True, padx=(10, 0))
        right_col.configure(highlightbackground=THEME["border"], highlightthickness=1)

        self.preview_title = tk.Label(
            right_col,
            text="REPORT PREVIEW",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        self.preview_title.pack(fill="x", pady=(0, 6))

        self.text_preview = tk.Text(
            right_col,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            insertbackground=THEME["text_primary"],
            font=(THEME["font_mono"], 9),
            wrap="word",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=THEME["border"],
            padx=10,
            pady=10,
        )
        scroll = ttk.Scrollbar(right_col, orient="vertical", command=self.text_preview.yview)
        self.text_preview.configure(yscrollcommand=scroll.set)

        self.text_preview.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.refresh_data()

    def refresh_data(self) -> None:
        """Populate report files in listbox."""
        self.reports_listbox.delete(0, tk.END)
        if REPORTS_DIR.exists():
            reports = sorted(REPORTS_DIR.glob("*.md"), key=os.path.getmtime, reverse=True)
            for r in reports:
                self.reports_listbox.insert(tk.END, r.name)

        if self.reports_listbox.size() > 0:
            self.reports_listbox.select_set(0)
            self._load_report(self.reports_listbox.get(0))

    def _on_select_report(self, event=None) -> None:
        selected = self.reports_listbox.curselection()
        if selected:
            filename = self.reports_listbox.get(selected[0])
            self._load_report(filename)

    def _load_report(self, filename: str) -> None:
        report_path = REPORTS_DIR / filename
        if report_path.exists():
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.preview_title.config(text=f"REPORT PREVIEW: {filename}")
                self.text_preview.delete("1.0", tk.END)
                self.text_preview.insert(tk.END, content)
            except Exception as e:
                self.text_preview.delete("1.0", tk.END)
                self.text_preview.insert(tk.END, f"Failed reading report: {e}")

    def _on_generate_report(self) -> None:
        try:
            report_path = self.engine.generate_security_report()
            messagebox.showinfo("Report Ready", f"New security report generated:\n{report_path}")
            self.refresh_data()
        except Exception as e:
            messagebox.showerror("Error", f"Failed generating report: {e}")
