"""
BI Antivirus - Software Inventory & Patch Auditor View
Interactive visual control center for:
1. Windows Registry-based application discovery (64-bit and WOW6432)
2. Semantic version comparison against local verifiable CVE advisories
3. Actionable manual remediation playbooks (Zero silent installations)
4. Exporting software compliance and vulnerability audit reports.
"""

import os
import json
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, Any, List, Optional
from pathlib import Path

from bi_antivirus.config import THEME, REPORTS_DIR


class PatchView(tk.Frame):
    """Software Inventory and Vulnerability Patch Audit visual interface."""

    def __init__(self, parent, engine, **kwargs):
        super().__init__(parent, bg=THEME["bg_darkest"], **kwargs)
        self.engine = engine
        self._current_inventory: List[Dict[str, Any]] = []
        self._current_advisories: List[Dict[str, Any]] = []
        self._build_ui()
        self.after(500, self._load_data)

    def _build_ui(self) -> None:
        # 1. Header Panel
        header_frame = tk.Frame(self, bg=THEME["bg_panel"], padx=20, pady=14)
        header_frame.pack(fill="x", padx=16, pady=(16, 10))
        header_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        title_lbl = tk.Label(
            header_frame,
            text="SOFTWARE INVENTORY & PATCH AUDITOR",
            bg=THEME["bg_panel"],
            fg=THEME["accent_primary"],
            font=(THEME["font_family"], 13, "bold"),
            anchor="w",
        )
        title_lbl.pack(fill="x")

        desc_lbl = tk.Label(
            header_frame,
            text="Audits installed Windows applications against local CVE advisories. Zero silent modifications — actionable remediation guidance only.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            anchor="w",
        )
        desc_lbl.pack(fill="x", pady=(2, 0))

        # 2. Controls & Stat Cards
        stats_frame = tk.Frame(self, bg=THEME["bg_darkest"])
        stats_frame.pack(fill="x", padx=16, pady=(0, 10))

        # Stat cards
        self.card_total = self._create_stat_card(stats_frame, "INSTALLED SOFTWARE", "0", THEME["accent_primary"])
        self.card_total.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.card_up_to_date = self._create_stat_card(stats_frame, "UP TO DATE", "0", THEME["status_safe"])
        self.card_up_to_date.pack(side="left", fill="x", expand=True, padx=6)

        self.card_vulnerable = self._create_stat_card(stats_frame, "CONFIRMED VULNERABLE", "0", THEME["status_critical"])
        self.card_vulnerable.pack(side="left", fill="x", expand=True, padx=6)

        self.card_advisories = self._create_stat_card(stats_frame, "ACTIVE CVE ADVISORIES", "0", THEME["accent_secondary"])
        self.card_advisories.pack(side="left", fill="x", expand=True, padx=(6, 0))

        # Button Bar
        btn_bar = tk.Frame(self, bg=THEME["bg_darkest"])
        btn_bar.pack(fill="x", padx=16, pady=(0, 8))

        btn_scan = ttk.Button(
            btn_bar,
            text="🔄  Scan & Audit Applications Now",
            style="Accent.TButton",
            command=self._run_scan_and_audit,
        )
        btn_scan.pack(side="left", padx=(0, 8))

        btn_export = ttk.Button(
            btn_bar,
            text="📄  Export Compliance Report (Markdown)",
            style="Outline.TButton",
            command=self._export_report,
        )
        btn_export.pack(side="left", padx=4)

        # 3. Main Split View: Table on top, Details on bottom
        split_frame = tk.Frame(self, bg=THEME["bg_darkest"])
        split_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        # Table Frame
        table_container = tk.Frame(split_frame, bg=THEME["bg_input"])
        table_container.pack(fill="both", expand=True, pady=(0, 8))

        cols = ("name", "version", "publisher", "status", "cves", "installed_date")
        self.tree = ttk.Treeview(table_container, columns=cols, show="headings", selectmode="browse", height=10)
        self.tree.heading("name", text="Application Name")
        self.tree.heading("version", text="Installed Version")
        self.tree.heading("publisher", text="Publisher")
        self.tree.heading("status", text="Patch Status")
        self.tree.heading("cves", text="Advisory / CVEs")
        self.tree.heading("installed_date", text="Install Location / Date")

        self.tree.column("name", width=220, anchor="w")
        self.tree.column("version", width=110, anchor="center")
        self.tree.column("publisher", width=160, anchor="w")
        self.tree.column("status", width=140, anchor="center")
        self.tree.column("cves", width=160, anchor="w")
        self.tree.column("installed_date", width=150, anchor="w")

        scroll_y = ttk.Scrollbar(table_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll_y.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll_y.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self._on_select_app)

        # Details & Remediation Playbook Panel
        self.details_frame = tk.Frame(split_frame, bg=THEME["bg_panel"], padx=14, pady=10)
        self.details_frame.pack(fill="x")
        self.details_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        self.lbl_details_title = tk.Label(
            self.details_frame,
            text="Selected Application Details & Remediation Playbook",
            bg=THEME["bg_panel"],
            fg=THEME["accent_primary"],
            font=(THEME["font_family"], 10, "bold"),
            anchor="w",
        )
        self.lbl_details_title.pack(fill="x")

        self.txt_details = tk.Text(
            self.details_frame,
            bg=THEME["bg_dark"],
            fg=THEME["text_primary"],
            font=(THEME["font_mono"], 9),
            height=6,
            relief="flat",
            wrap="word",
        )
        self.txt_details.pack(fill="both", expand=True, pady=(6, 0))
        self.txt_details.insert("end", "Select an installed application from the table above to view vulnerability status and remediation playbooks.")
        self.txt_details.configure(state="disabled")

    def _create_stat_card(self, parent: tk.Frame, title: str, val: str, color: str) -> tk.Frame:
        card = tk.Frame(parent, bg=THEME["bg_panel"], padx=12, pady=10)
        card.configure(highlightbackground=THEME["border"], highlightthickness=1)

        t_lbl = tk.Label(
            card,
            text=title,
            bg=THEME["bg_panel"],
            fg=THEME["text_muted"],
            font=(THEME["font_family"], 7, "bold"),
            anchor="w",
        )
        t_lbl.pack(fill="x")

        v_lbl = tk.Label(
            card,
            text=val,
            bg=THEME["bg_panel"],
            fg=color,
            font=(THEME["font_family"], 15, "bold"),
            anchor="w",
        )
        v_lbl.pack(fill="x", pady=(2, 0))
        card.value_label = v_lbl
        return card

    def _load_data(self) -> None:
        """Fetch cached software inventory and advisories from history database."""
        try:
            self._current_inventory = self.engine.patch_auditor.history_db.get_software_inventory()
            self._current_advisories = self.engine.patch_auditor.history_db.get_cve_advisories()
            self._update_display()
        except Exception as e:
            pass

    def _update_display(self) -> None:
        """Refresh stat cards and table rows."""
        self.tree.delete(*self.tree.get_children())

        total = len(self._current_inventory)
        up_to_date = sum(1 for a in self._current_inventory if a.get("status") == "UP_TO_DATE")
        vulnerable = sum(1 for a in self._current_inventory if a.get("status") == "CONFIRMED_VULNERABLE")

        self.card_total.value_label.configure(text=str(total))
        self.card_up_to_date.value_label.configure(text=str(up_to_date))
        self.card_vulnerable.value_label.configure(text=str(vulnerable))
        self.card_advisories.value_label.configure(text=str(len(self._current_advisories)))

        for app in self._current_inventory:
            name = app.get("app_name", "")
            ver = app.get("version", "N/A")
            pub = app.get("publisher", "")
            st = app.get("status", "UNKNOWN")
            cve = app.get("matched_cve", "") or ("None" if st == "UP_TO_DATE" else "No Advisory")
            loc = app.get("install_location", "") or app.get("install_date", "Windows Registry")

            item_id = self.tree.insert("", "end", values=(name, ver, pub, st, cve, loc))

    def _run_scan_and_audit(self) -> None:
        """Perform live scan across Windows Registry and match CVE advisories."""
        try:
            res = self.engine.audit_software_patches()
            self._current_inventory = res.get("inventory", [])
            self._update_display()
            messagebox.showinfo(
                "Software Audit Completed",
                f"Scanned {res.get('total_installed', 0)} installed applications.\n"
                f"Up-to-date: {res.get('up_to_date_count', 0)}\n"
                f"Vulnerable: {res.get('vulnerable_count', 0)}\n"
                f"Unknown / No advisory: {res.get('unknown_count', 0)}",
                parent=self,
            )
        except Exception as e:
            messagebox.showerror("Audit Error", f"Failed auditing software: {e}", parent=self)

    def _on_select_app(self, event) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if not vals:
            return

        app_name, ver, pub, st, cve, loc = vals
        # Find matching app record
        matched = next((a for a in self._current_inventory if a.get("app_name") == app_name), None)

        text_lines = [
            f"Application: {app_name}",
            f"Installed Version: {ver} | Publisher: {pub}",
            f"Patch Status: {st}",
            f"Matched CVEs: {cve}",
            f"Location: {loc}",
            "---",
        ]

        if st == "CONFIRMED_VULNERABLE":
            text_lines.extend([
                "ACTIONABLE REMEDIATION PLAYBOOK:",
                "1. Manual Patch Verification: Download and install the latest vendor security patch.",
                "2. Policy Mitigation: Disallow untrusted execution of this binary via Application Control.",
                "3. Isolation: If active exploitation is suspected, engage Host Network Isolation.",
                "Note: BI Antivirus never modifies or updates software automatically without administrator consent.",
            ])
        elif st == "UP_TO_DATE":
            text_lines.append("SECURITY STATUS: Installed version satisfies or exceeds current vendor security advisories.")
        else:
            text_lines.append("SECURITY STATUS: Application is tracked in inventory. No matching local CVE advisory triggered.")

        self.txt_details.configure(state="normal")
        self.txt_details.delete("1.0", "end")
        self.txt_details.insert("end", "\n".join(text_lines))
        self.txt_details.configure(state="disabled")

    def _export_report(self) -> None:
        """Export software compliance and vulnerability audit report to Markdown."""
        if not self._current_inventory:
            messagebox.showwarning("No Data", "No software inventory to export. Run an audit first.", parent=self)
            return

        out_path = REPORTS_DIR / f"software_audit_{int(time.time())}.md"
        try:
            total = len(self._current_inventory)
            up_to_date = sum(1 for a in self._current_inventory if a.get("status") == "UP_TO_DATE")
            vulnerable = sum(1 for a in self._current_inventory if a.get("status") == "CONFIRMED_VULNERABLE")

            lines = [
                "# BI Antivirus — Software Inventory & Vulnerability Compliance Report",
                f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}  ",
                f"**Total Applications Discovered:** `{total}`  ",
                f"**Up-to-Date Applications:** `{up_to_date}`  ",
                f"**Confirmed Vulnerable Applications:** `{vulnerable}`  ",
                "",
                "---",
                "",
                "## 1. Vulnerability Findings & Advisories",
                "| Application Name | Version | Publisher | Patch Status | Matched CVEs | Guidance |",
                "|---|---|---|---|---|---|",
            ]

            for a in self._current_inventory:
                lines.append(
                    f"| {a.get('app_name')} | {a.get('version')} | {a.get('publisher')} | `{a.get('status')}` | `{a.get('matched_cve', 'None')}` | Manual Patch / Review |"
                )

            lines.extend([
                "",
                "---",
                "",
                "## 2. Policy & Compliance Guidance",
                "All vulnerability notifications in BI Antivirus provide clear remediation instructions.",
                "Zero silent installations or background modifications are executed, guaranteeing operational transparency.",
                "",
                "---",
                f"*Report generated by BI Antivirus — Storage: D:\\bit defender*",
            ])

            out_path.write_text("\n".join(lines), encoding="utf-8")
            messagebox.showinfo("Export Successful", f"Software compliance report exported to:\n{out_path}", parent=self)
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not export report: {e}", parent=self)
