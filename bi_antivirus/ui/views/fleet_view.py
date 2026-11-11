"""
BI Antivirus - Enterprise Fleet Management View
Visual dashboard for managing endpoint fleets, policies, incident responses,
network isolation containment, and compliance reports.
Targeting functional feature parity with Bitdefender GravityZone Business Security.
"""

import os
import json
import time
import platform
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, Any, List, Optional
from pathlib import Path

from bi_antivirus.config import THEME, REPORTS_DIR, APP_VERSION
from bi_antivirus.enterprise.fleet_manager import FleetManager
from bi_antivirus.enterprise.compliance_reporter import ComplianceReporter


class FleetView(tk.Frame):
    """Enterprise Fleet Management Visual Control Center."""

    def __init__(self, parent, engine, **kwargs):
        super().__init__(parent, bg=THEME["bg_darkest"], **kwargs)
        self.engine = engine
        self.fleet_manager: FleetManager = getattr(engine, "fleet_manager", FleetManager())
        self.compliance_reporter: ComplianceReporter = getattr(
            engine, "compliance_reporter", ComplianceReporter(fleet_manager=self.fleet_manager)
        )

        self._build_ui()
        self.after(400, self.refresh_data)

    def _build_ui(self) -> None:
        # 1. Header Panel
        header_frame = tk.Frame(self, bg=THEME["bg_panel"], padx=20, pady=14)
        header_frame.pack(fill="x", padx=16, pady=(16, 10))
        header_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        title_lbl = tk.Label(
            header_frame,
            text="ENTERPRISE FLEET MANAGEMENT CENTER",
            bg=THEME["bg_panel"],
            fg=THEME["accent_primary"],
            font=(THEME["font_family"], 13, "bold"),
            anchor="w",
        )
        title_lbl.pack(fill="x")

        desc_lbl = tk.Label(
            header_frame,
            text="Centralized GravityZone-inspired endpoint visibility, monotonic policy distribution, incident response, and compliance auditing.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            anchor="w",
        )
        desc_lbl.pack(fill="x", pady=(2, 0))

        # 2. Stat Cards Bar
        stats_frame = tk.Frame(self, bg=THEME["bg_darkest"])
        stats_frame.pack(fill="x", padx=16, pady=(0, 10))

        self.card_total = self._create_stat_card(stats_frame, "MANAGED ENDPOINTS", "0", THEME["accent_primary"])
        self.card_total.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.card_healthy = self._create_stat_card(stats_frame, "HEALTHY POSTURE", "100%", THEME["status_safe"])
        self.card_healthy.pack(side="left", fill="x", expand=True, padx=6)

        self.card_at_risk = self._create_stat_card(stats_frame, "AT-RISK / ISOLATED", "0", THEME["status_threat"])
        self.card_at_risk.pack(side="left", fill="x", expand=True, padx=6)

        self.card_incidents = self._create_stat_card(stats_frame, "ACTIVE INCIDENTS", "0", THEME["status_warning"])
        self.card_incidents.pack(side="left", fill="x", expand=True, padx=(6, 0))

        # 3. Main Notebook with Tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        # Tab 1: Endpoints
        self.tab_endpoints = tk.Frame(self.notebook, bg=THEME["bg_darkest"])
        self.notebook.add(self.tab_endpoints, text="  🖥️ Endpoints Directory  ")
        self._build_endpoints_tab(self.tab_endpoints)

        # Tab 2: Policies
        self.tab_policies = tk.Frame(self.notebook, bg=THEME["bg_darkest"])
        self.notebook.add(self.tab_policies, text="  📜 Fleet Policies  ")
        self._build_policies_tab(self.tab_policies)

        # Tab 3: Incidents
        self.tab_incidents = tk.Frame(self.notebook, bg=THEME["bg_darkest"])
        self.notebook.add(self.tab_incidents, text="  🚨 EDR Incidents  ")
        self._build_incidents_tab(self.tab_incidents)

        # Tab 4: Compliance & Audit
        self.tab_compliance = tk.Frame(self.notebook, bg=THEME["bg_darkest"])
        self.notebook.add(self.tab_compliance, text="  📊 Compliance & Audit Trail  ")
        self._build_compliance_tab(self.tab_compliance)

    def _create_stat_card(self, parent, title: str, value: str, accent_color: str) -> tk.Frame:
        card = tk.Frame(parent, bg=THEME["bg_panel"], padx=14, pady=10)
        card.configure(highlightbackground=THEME["border"], highlightthickness=1)

        t_lbl = tk.Label(
            card,
            text=title,
            bg=THEME["bg_panel"],
            fg=THEME["text_muted"],
            font=(THEME["font_family"], 8, "bold"),
            anchor="w",
        )
        t_lbl.pack(fill="x")

        v_lbl = tk.Label(
            card,
            text=value,
            bg=THEME["bg_panel"],
            fg=accent_color,
            font=(THEME["font_family"], 16, "bold"),
            anchor="w",
        )
        v_lbl.pack(fill="x", pady=(4, 0))
        card._val_lbl = v_lbl
        return card

    # --- Tab 1: Endpoints Directory ---

    def _build_endpoints_tab(self, parent: tk.Frame) -> None:
        toolbar = tk.Frame(parent, bg=THEME["bg_darkest"], pady=8)
        toolbar.pack(fill="x")

        # Search Box
        tk.Label(toolbar, text="Search:", bg=THEME["bg_darkest"], fg=THEME["text_secondary"]).pack(side="left", padx=(0, 6))
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(
            toolbar,
            textvariable=self.search_var,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            insertbackground=THEME["accent_primary"],
            width=24,
            relief="flat",
        )
        self.search_entry.pack(side="left", padx=(0, 10))
        self.search_entry.bind("<Return>", lambda e: self._search_endpoints())

        ttk.Button(toolbar, text="Find", command=self._search_endpoints).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Reset", command=self.refresh_data).pack(side="left", padx=4)

        # Action Buttons
        ttk.Button(toolbar, text="Enroll Local Host", command=self._enroll_local_endpoint).pack(side="right", padx=4)
        ttk.Button(toolbar, text="Isolate Endpoint", command=self._isolate_selected_endpoint).pack(side="right", padx=4)
        ttk.Button(toolbar, text="Unisolate Endpoint", command=self._unisolate_selected_endpoint).pack(side="right", padx=4)

        # Treeview
        tree_frame = tk.Frame(parent, bg=THEME["bg_panel"])
        tree_frame.pack(fill="both", expand=True)

        cols = ("id", "hostname", "ip", "os", "agent", "health", "policy", "isolation", "dept")
        self.ep_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        
        self.ep_tree.heading("id", text="Endpoint ID")
        self.ep_tree.heading("hostname", text="Hostname")
        self.ep_tree.heading("ip", text="IP Address")
        self.ep_tree.heading("os", text="OS Platform")
        self.ep_tree.heading("agent", text="Agent Ver")
        self.ep_tree.heading("health", text="Health")
        self.ep_tree.heading("policy", text="Assigned Policy")
        self.ep_tree.heading("isolation", text="Isolation")
        self.ep_tree.heading("dept", text="Department")

        self.ep_tree.column("id", width=120)
        self.ep_tree.column("hostname", width=130)
        self.ep_tree.column("ip", width=100)
        self.ep_tree.column("os", width=110)
        self.ep_tree.column("agent", width=80)
        self.ep_tree.column("health", width=90)
        self.ep_tree.column("policy", width=130)
        self.ep_tree.column("isolation", width=80)
        self.ep_tree.column("dept", width=100)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.ep_tree.yview)
        self.ep_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.ep_tree.pack(side="left", fill="both", expand=True)

    # --- Tab 2: Fleet Policies ---

    def _build_policies_tab(self, parent: tk.Frame) -> None:
        toolbar = tk.Frame(parent, bg=THEME["bg_darkest"], pady=8)
        toolbar.pack(fill="x")

        ttk.Button(toolbar, text="Refresh Policies", command=self._load_policies).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Assign Selected Policy to Endpoint", command=self._assign_policy_dialog).pack(side="left", padx=6)

        tree_frame = tk.Frame(parent, bg=THEME["bg_panel"])
        tree_frame.pack(fill="both", expand=True)

        cols = ("id", "name", "version", "updated", "description")
        self.pol_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")

        self.pol_tree.heading("id", text="Policy ID")
        self.pol_tree.heading("name", text="Policy Name")
        self.pol_tree.heading("version", text="Version")
        self.pol_tree.heading("updated", text="Last Updated")
        self.pol_tree.heading("description", text="Description")

        self.pol_tree.column("id", width=130)
        self.pol_tree.column("name", width=220)
        self.pol_tree.column("version", width=70)
        self.pol_tree.column("updated", width=140)
        self.pol_tree.column("description", width=300)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.pol_tree.yview)
        self.pol_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.pol_tree.pack(side="left", fill="both", expand=True)

    # --- Tab 3: Incidents ---

    def _build_incidents_tab(self, parent: tk.Frame) -> None:
        toolbar = tk.Frame(parent, bg=THEME["bg_darkest"], pady=8)
        toolbar.pack(fill="x")

        ttk.Button(toolbar, text="Refresh Incidents", command=self._load_incidents).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Mark Incident Resolved", command=self._resolve_incident_dialog).pack(side="left", padx=6)

        tree_frame = tk.Frame(parent, bg=THEME["bg_panel"])
        tree_frame.pack(fill="both", expand=True)

        cols = ("id", "title", "severity", "endpoints", "status", "created")
        self.inc_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")

        self.inc_tree.heading("id", text="Incident ID")
        self.inc_tree.heading("title", text="Title")
        self.inc_tree.heading("severity", text="Severity")
        self.inc_tree.heading("endpoints", text="Affected Endpoints")
        self.inc_tree.heading("status", text="Status")
        self.inc_tree.heading("created", text="Created")

        self.inc_tree.column("id", width=130)
        self.inc_tree.column("title", width=260)
        self.inc_tree.column("severity", width=90)
        self.inc_tree.column("endpoints", width=140)
        self.inc_tree.column("status", width=90)
        self.inc_tree.column("created", width=140)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.inc_tree.yview)
        self.inc_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.inc_tree.pack(side="left", fill="both", expand=True)

    # --- Tab 4: Compliance & Audit ---

    def _build_compliance_tab(self, parent: tk.Frame) -> None:
        toolbar = tk.Frame(parent, bg=THEME["bg_darkest"], pady=8)
        toolbar.pack(fill="x")

        ttk.Button(toolbar, text="Export Compliance Report (Markdown)", command=lambda: self._export_report("markdown")).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Export Compliance Report (JSON)", command=lambda: self._export_report("json")).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Refresh Audit Trail", command=self._load_audit_trail).pack(side="right", padx=4)

        tree_frame = tk.Frame(parent, bg=THEME["bg_panel"])
        tree_frame.pack(fill="both", expand=True)

        cols = ("id", "time", "admin", "action", "target", "details")
        self.audit_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")

        self.audit_tree.heading("id", text="Audit ID")
        self.audit_tree.heading("time", text="Timestamp")
        self.audit_tree.heading("admin", text="Admin ID")
        self.audit_tree.heading("action", text="Action")
        self.audit_tree.heading("target", text="Target")
        self.audit_tree.heading("details", text="Details")

        self.audit_tree.column("id", width=120)
        self.audit_tree.column("time", width=130)
        self.audit_tree.column("admin", width=90)
        self.audit_tree.column("action", width=140)
        self.audit_tree.column("target", width=120)
        self.audit_tree.column("details", width=280)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.audit_tree.yview)
        self.audit_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.audit_tree.pack(side="left", fill="both", expand=True)

    # --- Data Operations ---

    def refresh_data(self) -> None:
        """Fetch latest fleet data and update tables and stat cards."""
        # Offline sweep
        self.fleet_manager.sweep_offline_endpoints()

        stats = self.fleet_manager.db.get_fleet_stats()
        total = stats.get("total_endpoints", 0)
        healthy = stats.get("healthy_count", 0)
        at_risk = stats.get("at_risk_count", 0) + stats.get("isolated_count", 0)
        incidents = stats.get("active_incidents", 0)

        self.card_total._val_lbl.config(text=str(total))
        pct = round((healthy / total * 100), 1) if total > 0 else 100.0
        self.card_healthy._val_lbl.config(text=f"{pct}%")
        self.card_at_risk._val_lbl.config(text=str(at_risk))
        self.card_incidents._val_lbl.config(text=str(incidents))

        self._load_endpoints()
        self._load_policies()
        self._load_incidents()
        self._load_audit_trail()

    def _load_endpoints(self, endpoints: Optional[List[Any]] = None) -> None:
        for item in self.ep_tree.get_children():
            self.ep_tree.delete(item)

        eps = endpoints if endpoints is not None else self.fleet_manager.db.list_endpoints()
        for ep in eps:
            d = ep.to_dict() if hasattr(ep, "to_dict") else ep
            self.ep_tree.insert(
                "",
                "end",
                values=(
                    d.get("id"),
                    d.get("hostname"),
                    d.get("ip_address"),
                    d.get("os_version")[:16],
                    d.get("agent_version"),
                    d.get("health_status"),
                    d.get("assigned_policy_id"),
                    "ISOLATED" if d.get("isolation_status") else "NORMAL",
                    d.get("department"),
                ),
            )

    def _search_endpoints(self) -> None:
        q = self.search_var.get().strip()
        results = self.fleet_manager.search_endpoints(query=q)
        self._load_endpoints(results)

    def _load_policies(self) -> None:
        for item in self.pol_tree.get_children():
            self.pol_tree.delete(item)

        policies = self.fleet_manager.db.list_policies()
        for p in policies:
            up_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(p.updated_at))
            self.pol_tree.insert(
                "",
                "end",
                values=(p.policy_id, p.policy_name, f"v{p.version}", up_time, p.description),
            )

    def _load_incidents(self) -> None:
        for item in self.inc_tree.get_children():
            self.inc_tree.delete(item)

        incidents = self.fleet_manager.db.list_incidents()
        for inc in incidents:
            c_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(inc.created_at))
            self.inc_tree.insert(
                "",
                "end",
                values=(
                    inc.incident_id,
                    inc.title,
                    inc.severity,
                    ", ".join(inc.affected_endpoints),
                    inc.status,
                    c_time,
                ),
            )

    def _load_audit_trail(self) -> None:
        for item in self.audit_tree.get_children():
            self.audit_tree.delete(item)

        entries = self.fleet_manager.db.get_audit_log(limit=50)
        for e in entries:
            t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.timestamp))
            details_str = json.dumps(e.details)
            self.audit_tree.insert(
                "",
                "end",
                values=(e.audit_id, t_str, e.admin_id, e.action, f"{e.target_type}:{e.target_id}", details_str),
            )

    def _enroll_local_endpoint(self) -> None:
        """Enroll the local machine as a managed endpoint device."""
        hostname = platform.node() or "LocalWorkstation"
        ip = "127.0.0.1"
        os_ver = f"{platform.system()} {platform.release()}"
        agent_ver = APP_VERSION

        ok, msg, ep_data = self.fleet_manager.register_endpoint(
            hostname=hostname,
            ip_address=ip,
            os_version=os_ver,
            agent_version=agent_ver,
            enrollment_token=self.fleet_manager.master_enrollment_key,
            department="Cyber Ops",
            tags=["local-host", "primary"],
        )

        if ok:
            messagebox.showinfo("Enrollment Succeeded", f"Successfully registered local endpoint:\n{hostname} ({ep_data.get('id')})")
            self.refresh_data()
        else:
            messagebox.showerror("Enrollment Error", f"Registration failed:\n{msg}")

    def _isolate_selected_endpoint(self) -> None:
        sel = self.ep_tree.selection()
        if not sel:
            messagebox.showwarning("Selection Required", "Please select an endpoint from the table to isolate.")
            return

        item = self.ep_tree.item(sel[0])
        ep_id = item["values"][0]
        hostname = item["values"][1]

        if not messagebox.askyesno(
            "Confirm Network Isolation",
            f"Are you sure you want to isolate endpoint '{hostname}' ({ep_id})?\n\nThis will block network communication to contain potential malware.",
        ):
            return

        ok, msg = self.fleet_manager.isolate_endpoint(
            admin_token=self.fleet_manager.admin_token,
            endpoint_id=ep_id,
            reason="Operator containment order from UI",
        )
        if ok:
            messagebox.showinfo("Endpoint Isolated", msg)
            self.refresh_data()
        else:
            messagebox.showerror("Isolation Failed", msg)

    def _unisolate_selected_endpoint(self) -> None:
        sel = self.ep_tree.selection()
        if not sel:
            messagebox.showwarning("Selection Required", "Please select an endpoint from the table.")
            return

        item = self.ep_tree.item(sel[0])
        ep_id = item["values"][0]
        hostname = item["values"][1]

        ok, msg = self.fleet_manager.unisolate_endpoint(
            admin_token=self.fleet_manager.admin_token,
            endpoint_id=ep_id,
        )
        if ok:
            messagebox.showinfo("Connectivity Restored", msg)
            self.refresh_data()
        else:
            messagebox.showerror("Action Failed", msg)

    def _assign_policy_dialog(self) -> None:
        sel_pol = self.pol_tree.selection()
        sel_ep = self.ep_tree.selection()

        if not sel_pol:
            messagebox.showwarning("Policy Required", "Please select a policy from the Policies table.")
            return
        if not sel_ep:
            messagebox.showwarning("Endpoint Required", "Please select a target endpoint from the Endpoints Directory tab.")
            return

        pol_id = self.pol_tree.item(sel_pol[0])["values"][0]
        ep_id = self.ep_tree.item(sel_ep[0])["values"][0]

        ok, msg, _ = self.fleet_manager.assign_policy_to_endpoints(
            admin_token=self.fleet_manager.admin_token,
            policy_id=pol_id,
            endpoint_ids=[ep_id],
        )
        if ok:
            messagebox.showinfo("Policy Assigned", msg)
            self.refresh_data()
        else:
            messagebox.showerror("Policy Assignment Failed", msg)

    def _resolve_incident_dialog(self) -> None:
        sel = self.inc_tree.selection()
        if not sel:
            messagebox.showwarning("Selection Required", "Please select an incident to resolve.")
            return

        inc_id = self.inc_tree.item(sel[0])["values"][0]
        inc = self.fleet_manager.db.get_incident(inc_id)
        if inc:
            inc.status = "RESOLVED"
            inc.timeline.append({
                "timestamp": time.time(),
                "event": "Operator resolved incident via Enterprise Fleet UI.",
            })
            inc.updated_at = time.time()
            self.fleet_manager.db.save_incident(inc)
            messagebox.showinfo("Incident Resolved", f"Incident {inc_id} marked as RESOLVED.")
            self.refresh_data()

    def _export_report(self, fmt: str) -> None:
        try:
            dest = self.compliance_reporter.export_report_to_file(format=fmt)
            messagebox.showinfo("Compliance Report Exported", f"Successfully exported compliance report to:\n{dest}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Failed generating report: {e}")
