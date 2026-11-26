"""
BI Antivirus - Enterprise EDR & Memory Exploit Shield View
Interactive visual control center for:
1. Correlated EDR Incident Graph & Evidence-Backed MITRE ATT&CK Mapping
2. Defensive Memory Security Posture (DEP, ASLR, CFG, Dynamic Code, RWX Anomalies)
3. One-click SOC forensic report generation and JSON SIEM export.
"""

import os
import json
import time
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, Any, List, Optional
from pathlib import Path

from bi_antivirus.config import THEME, REPORTS_DIR


class EDRView(tk.Frame):
    """EDR Incident Investigation and Memory Posture Audit visual interface."""

    def __init__(self, parent, engine, **kwargs):
        super().__init__(parent, bg=THEME["bg_darkest"], **kwargs)
        self.engine = engine
        self._current_incidents: List[Dict[str, Any]] = []
        self._memory_audit_results: List[Dict[str, Any]] = []
        self._build_ui()

    def _build_ui(self) -> None:
        # Header Panel
        header_frame = tk.Frame(self, bg=THEME["bg_panel"], padx=20, pady=14)
        header_frame.pack(fill="x", padx=16, pady=(16, 10))
        header_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        title_lbl = tk.Label(
            header_frame,
            text="ENTERPRISE EDR & MEMORY DEFENSE CENTER",
            bg=THEME["bg_panel"],
            fg=THEME["accent_primary"],
            font=(THEME["font_family"], 13, "bold"),
            anchor="w",
        )
        title_lbl.pack(fill="x")

        desc_lbl = tk.Label(
            header_frame,
            text="Cross-vector attack chain correlation, verified MITRE ATT&CK evidence, DEP/ASLR/CFG mitigations, and RWX memory anomaly auditing.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            anchor="w",
        )
        desc_lbl.pack(fill="x", pady=(2, 0))

        # Notebook tabs
        style = ttk.Style()
        style.configure("EDR.TNotebook", background=THEME["bg_darkest"])
        style.configure("EDR.TNotebook.Tab", padding=[16, 6], font=(THEME["font_family"], 9, "bold"))

        self.notebook = ttk.Notebook(self, style="EDR.TNotebook")
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(0, 14))

        # Tab 1: EDR Incident Graph
        self.tab_incidents = tk.Frame(self.notebook, bg=THEME["bg_darkest"])
        self.notebook.add(self.tab_incidents, text="  🧠 EDR Incident Graph & MITRE  ")
        self._build_incidents_tab(self.tab_incidents)

        # Tab 2: Memory Exploit Shield
        self.tab_memory = tk.Frame(self.notebook, bg=THEME["bg_darkest"])
        self.notebook.add(self.tab_memory, text="  🛡️ Memory Posture & Exploit Shield  ")
        self._build_memory_tab(self.tab_memory)

    # =========================================================================
    # TAB 1: EDR INCIDENTS & MITRE ATT&CK
    # =========================================================================
    def _build_incidents_tab(self, parent: tk.Frame) -> None:
        # Top Table: Incident Summary
        table_frame = tk.Frame(parent, bg=THEME["bg_input"])
        table_frame.pack(fill="both", expand=True, padx=4, pady=(6, 6))

        columns = ("id", "severity", "confidence", "title", "mitre", "status", "created")
        self.inc_tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse", height=7)
        self.inc_tree.heading("id", text="INCIDENT ID")
        self.inc_tree.heading("severity", text="SEVERITY")
        self.inc_tree.heading("confidence", text="CONFIDENCE")
        self.inc_tree.heading("title", text="CORRELATED TITLE")
        self.inc_tree.heading("mitre", text="MITRE TECHNIQUES")
        self.inc_tree.heading("status", text="STATUS")
        self.inc_tree.heading("created", text="CREATED AT")

        self.inc_tree.column("id", width=140, anchor="w")
        self.inc_tree.column("severity", width=85, anchor="center")
        self.inc_tree.column("confidence", width=95, anchor="center")
        self.inc_tree.column("title", width=260, anchor="w")
        self.inc_tree.column("mitre", width=180, anchor="w")
        self.inc_tree.column("status", width=85, anchor="center")
        self.inc_tree.column("created", width=140, anchor="w")

        inc_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.inc_tree.yview)
        self.inc_tree.configure(yscrollcommand=inc_scroll.set)
        self.inc_tree.pack(side="left", fill="both", expand=True)
        inc_scroll.pack(side="right", fill="y")

        self.inc_tree.bind("<<TreeviewSelect>>", self._on_incident_selected)

        # Bottom Detail Split (Timeline on left, MITRE evidence on right)
        detail_container = tk.Frame(parent, bg=THEME["bg_darkest"])
        detail_container.pack(fill="both", expand=True, padx=4, pady=(0, 6))
        detail_container.columnconfigure(0, weight=1)
        detail_container.columnconfigure(1, weight=1)
        detail_container.rowconfigure(0, weight=1)

        # Left Detail: Chronological Timeline
        left_box = tk.LabelFrame(
            detail_container,
            text=" Chronological Event Timeline ",
            bg=THEME["bg_panel"],
            fg=THEME["accent_primary"],
            font=(THEME["font_family"], 9, "bold"),
            padx=8,
            pady=8,
        )
        left_box.grid(row=0, column=0, sticky="nsew", padx=(0, 4))

        self.timeline_text = tk.Text(
            left_box,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=(THEME["font_mono"], 8),
            wrap="word",
            state="disabled",
            height=8,
        )
        self.timeline_text.pack(fill="both", expand=True)

        # Right Detail: MITRE ATT&CK & Concrete Evidence
        right_box = tk.LabelFrame(
            detail_container,
            text=" Verified MITRE ATT&CK Evidence ",
            bg=THEME["bg_panel"],
            fg=THEME["accent_primary"],
            font=(THEME["font_family"], 9, "bold"),
            padx=8,
            pady=8,
        )
        right_box.grid(row=0, column=1, sticky="nsew", padx=(4, 0))

        self.mitre_text = tk.Text(
            right_box,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=(THEME["font_mono"], 8),
            wrap="word",
            state="disabled",
            height=8,
        )
        self.mitre_text.pack(fill="both", expand=True)

        # Action Buttons Bar
        action_bar = tk.Frame(parent, bg=THEME["bg_darkest"])
        action_bar.pack(fill="x", padx=4, pady=(4, 4))

        btn_export_md = ttk.Button(
            action_bar,
            text="📄 Export Forensic Report (Markdown)",
            style="Primary.TButton",
            command=self._export_forensic_markdown,
        )
        btn_export_md.pack(side="left", padx=(0, 8))

        btn_export_json = ttk.Button(
            action_bar,
            text="💾 Export SIEM JSON",
            style="Secondary.TButton",
            command=self._export_incident_json,
        )
        btn_export_json.pack(side="left", padx=(0, 8))

        btn_refresh = ttk.Button(
            action_bar,
            text="🔄 Refresh Incidents",
            style="Secondary.TButton",
            command=self.refresh_incidents,
        )
        btn_refresh.pack(side="right")

    # =========================================================================
    # TAB 2: MEMORY EXPLOIT SHIELD
    # =========================================================================
    def _build_memory_tab(self, parent: tk.Frame) -> None:
        # Top toolbar
        toolbar = tk.Frame(parent, bg=THEME["bg_panel"], padx=12, pady=10)
        toolbar.pack(fill="x", padx=4, pady=(6, 6))

        btn_audit_now = ttk.Button(
            toolbar,
            text="🔍 Audit Memory Posture Now",
            style="Primary.TButton",
            command=self._run_memory_audit,
        )
        btn_audit_now.pack(side="left", padx=(0, 12))

        self.lbl_mem_status = tk.Label(
            toolbar,
            text="Click 'Audit Memory Posture Now' to inspect DEP, ASLR, CFG, and RWX memory regions.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
        )
        self.lbl_mem_status.pack(side="left")

        # Table: Process Mitigations & RWX
        mem_table_frame = tk.Frame(parent, bg=THEME["bg_input"])
        mem_table_frame.pack(fill="both", expand=True, padx=4, pady=(0, 6))

        mem_cols = ("pid", "name", "dep", "aslr", "cfg", "dyn_code", "rwx", "risk_score", "risk_level")
        self.mem_tree = ttk.Treeview(mem_table_frame, columns=mem_cols, show="headings", selectmode="browse")
        self.mem_tree.heading("pid", text="PID")
        self.mem_tree.heading("name", text="PROCESS NAME")
        self.mem_tree.heading("dep", text="DEP STATUS")
        self.mem_tree.heading("aslr", text="ASLR STATUS")
        self.mem_tree.heading("cfg", text="CFG (GUARD)")
        self.mem_tree.heading("dyn_code", text="DYNAMIC CODE")
        self.mem_tree.heading("rwx", text="RWX REGIONS")
        self.mem_tree.heading("risk_score", text="RISK SCORE")
        self.mem_tree.heading("risk_level", text="LEVEL")

        self.mem_tree.column("pid", width=70, anchor="center")
        self.mem_tree.column("name", width=180, anchor="w")
        self.mem_tree.column("dep", width=130, anchor="center")
        self.mem_tree.column("aslr", width=170, anchor="center")
        self.mem_tree.column("cfg", width=120, anchor="center")
        self.mem_tree.column("dyn_code", width=140, anchor="center")
        self.mem_tree.column("rwx", width=95, anchor="center")
        self.mem_tree.column("risk_score", width=85, anchor="center")
        self.mem_tree.column("risk_level", width=95, anchor="center")

        mem_scroll = ttk.Scrollbar(mem_table_frame, orient="vertical", command=self.mem_tree.yview)
        self.mem_tree.configure(yscrollcommand=mem_scroll.set)
        self.mem_tree.pack(side="left", fill="both", expand=True)
        mem_scroll.pack(side="right", fill="y")

        self.mem_tree.bind("<<TreeviewSelect>>", self._on_memory_process_selected)

        # Bottom Findings Box
        findings_frame = tk.LabelFrame(
            parent,
            text=" Exploit Shield Audit Findings & Diagnostic Evidence ",
            bg=THEME["bg_panel"],
            fg=THEME["accent_primary"],
            font=(THEME["font_family"], 9, "bold"),
            padx=8,
            pady=6,
        )
        findings_frame.pack(fill="x", padx=4, pady=(0, 4))

        self.findings_text = tk.Label(
            findings_frame,
            text="Select a process from the table to view mitigation details and memory findings.",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_mono"], 8),
            anchor="w",
            justify="left",
        )
        self.findings_text.pack(fill="x")

    # =========================================================================
    # REFRESH & INTERACTION LOGIC
    # =========================================================================
    def refresh_data(self) -> None:
        """Dashboard view refresh hook."""
        self.refresh_incidents()
        self.refresh_memory_audits()

    def refresh_incidents(self) -> None:
        """Query and populate recent EDR incidents."""
        self.inc_tree.delete(*self.inc_tree.get_children())
        if not hasattr(self.engine, "history_db") or not hasattr(self.engine.history_db, "get_edr_incidents"):
            return

        records = self.engine.history_db.get_edr_incidents(limit=25)
        self._current_incidents = records

        for r in records:
            techs = r.get("mitre_techniques", [])
            tech_ids = ", ".join([t.get("id", "") for t in techs if isinstance(t, dict)]) if techs else "None"
            conf_pct = f"{int(r.get('confidence', 0.5) * 100)}%"
            self.inc_tree.insert(
                "",
                "end",
                iid=r["incident_id"],
                values=(
                    r["incident_id"],
                    r["severity"],
                    conf_pct,
                    r["title"],
                    tech_ids,
                    r["status"],
                    r["created_at"],
                ),
            )

    def _on_incident_selected(self, event) -> None:
        """Render timeline and MITRE details for the clicked incident."""
        selected = self.inc_tree.selection()
        if not selected:
            return

        inc_id = selected[0]
        # Locate incident data
        inc = next((i for i in self._current_incidents if i["incident_id"] == inc_id), None)
        if not inc:
            return

        # Render timeline
        self.timeline_text.config(state="normal")
        self.timeline_text.delete("1.0", "end")
        for ev in inc.get("timeline", []):
            t_iso = ev.get("timestamp_iso", time.strftime("%H:%M:%S", time.localtime(ev.get("timestamp", 0))))
            src = ev.get("source", "Core")
            etype = ev.get("event_type", "EVENT")
            msg = ev.get("message", "")
            self.timeline_text.insert("end", f"[{t_iso}] [{src}] {etype}\n  ↳ {msg}\n\n")
        self.timeline_text.config(state="disabled")

        # Render MITRE evidence
        self.mitre_text.config(state="normal")
        self.mitre_text.delete("1.0", "end")
        techs = inc.get("mitre_techniques", [])
        if techs:
            for t in techs:
                tid = t.get("id", "T????")
                name = t.get("name", "Unknown")
                tactic = t.get("tactic", "Unknown")
                ev = t.get("evidence", "Observable event")
                self.mitre_text.insert("end", f"• {tid} — {name} [{tactic}]\n  Evidence: {ev}\n\n")
        else:
            self.mitre_text.insert("end", "No specific MITRE techniques mapped for this incident.\n")
        self.mitre_text.config(state="disabled")

    def _export_forensic_markdown(self) -> None:
        """Export full Markdown investigation report."""
        selected = self.inc_tree.selection()
        if not selected:
            messagebox.showinfo("Export Forensic Report", "Please select an incident from the table first.")
            return

        inc_id = selected[0]
        report_md = ""
        if hasattr(self.engine, "incident_graph") and hasattr(self.engine.incident_graph, "export_incident_markdown"):
            report_md = self.engine.incident_graph.export_incident_markdown(inc_id)
        else:
            messagebox.showerror("Export Error", "Incident graph engine not active.")
            return

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        report_file = REPORTS_DIR / f"{inc_id}_forensic_report.md"
        try:
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(report_md)
            messagebox.showinfo(
                "Forensic Report Exported",
                f"Forensic investigation report successfully generated:\n\n{report_file}",
            )
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not write report file: {e}")

    def _export_incident_json(self) -> None:
        """Export canonical JSON for SIEM integration."""
        selected = self.inc_tree.selection()
        if not selected:
            messagebox.showinfo("Export SIEM JSON", "Please select an incident from the table first.")
            return

        inc_id = selected[0]
        json_data = ""
        if hasattr(self.engine, "incident_graph") and hasattr(self.engine.incident_graph, "export_incident_json"):
            json_data = self.engine.incident_graph.export_incident_json(inc_id)
        else:
            messagebox.showerror("Export Error", "Incident graph engine not active.")
            return

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        json_file = REPORTS_DIR / f"{inc_id}_siem_event.json"
        try:
            with open(json_file, "w", encoding="utf-8") as f:
                f.write(json_data)
            messagebox.showinfo(
                "SIEM JSON Exported",
                f"Canonical incident JSON exported successfully:\n\n{json_file}",
            )
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not write JSON file: {e}")

    def _run_memory_audit(self) -> None:
        """Execute a live defensive sweep of user-space processes."""
        if not hasattr(self.engine, "exploit_shield"):
            messagebox.showerror("Exploit Shield", "Exploit Shield module is not active.")
            return

        self.lbl_mem_status.config(text="Auditing running processes and querying memory pages (read-only)...")
        self.update_idletasks()

        audits = self.engine.exploit_shield.audit_all_processes(limit=60)
        self._memory_audit_results = audits
        self._populate_memory_tree(audits)

        high_risk = sum(1 for a in audits if a.get("risk_score", 0) >= 40)
        rwx_count = sum(a.get("rwx_regions_count", 0) for a in audits)
        self.lbl_mem_status.config(
            text=f"Audit complete: {len(audits)} processes inspected | {rwx_count} RWX regions detected | {high_risk} elevated risk."
        )

    def refresh_memory_audits(self) -> None:
        """Populate memory audit table from history DB."""
        if not hasattr(self.engine, "history_db") or not hasattr(self.engine.history_db, "get_recent_memory_audits"):
            return

        db_records = self.engine.history_db.get_recent_memory_audits(limit=50)
        if db_records:
            self._populate_memory_tree(db_records)

    def _populate_memory_tree(self, records: List[Dict[str, Any]]) -> None:
        self.mem_tree.delete(*self.mem_tree.get_children())
        seen_iids = set()
        for idx, a in enumerate(records):
            pid = a.get("pid", 0)
            name = a.get("process_name", "")
            dep = a.get("dep", {}).get("status_str") if isinstance(a.get("dep"), dict) else a.get("dep_status", "UNKNOWN")
            aslr = a.get("aslr", {}).get("status_str") if isinstance(a.get("aslr"), dict) else a.get("aslr_status", "UNKNOWN")
            cfg = a.get("cfg", {}).get("status_str") if isinstance(a.get("cfg"), dict) else a.get("cfg_status", "UNKNOWN")
            dyn = a.get("dynamic_code", {}).get("status_str") if isinstance(a.get("dynamic_code"), dict) else a.get("dynamic_code_status", "UNKNOWN")
            rwx = a.get("rwx_regions_count", 0)
            score = a.get("risk_score", 0)
            level = a.get("risk_level", "LOW" if score < 20 else ("MEDIUM" if score < 40 else "HIGH"))

            iid = str(pid)
            if iid in seen_iids or self.mem_tree.exists(iid):
                iid = f"{pid}_{idx}"
            seen_iids.add(iid)

            self.mem_tree.insert(
                "",
                "end",
                iid=iid,
                values=(pid, name, dep, aslr, cfg, dyn, rwx, score, level),
            )

    def _on_memory_process_selected(self, event) -> None:
        """Display findings for selected process."""
        selected = self.mem_tree.selection()
        if not selected:
            return

        pid_str = selected[0].split("_")[0]
        # Find item in cache
        item = next((a for a in self._memory_audit_results if str(a.get("pid")) == pid_str), None)
        if not item:
            return

        findings = item.get("findings", [])
        if findings:
            findings_str = " | ".join(findings)
        else:
            findings_str = "All memory mitigations nominal. No RWX unbacked executable regions detected."

        self.findings_text.config(
            text=f"PID {item.get('pid')} ({item.get('process_name')}) [Risk Score: {item.get('risk_score')}/100]: {findings_str}"
        )
