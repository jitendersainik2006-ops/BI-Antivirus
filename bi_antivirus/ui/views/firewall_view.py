"""
BI Antivirus - Firewall & Network Connections View
Passive network security audit inspecting active ports, remote sockets,
process associations, and Windows Defender Firewall profile states.
"""

import tkinter as tk
from tkinter import ttk
import threading

from bi_antivirus.config import THEME
from bi_antivirus.core.privilege_manager import is_user_admin


class FirewallView(tk.Frame):
    """Network connection monitor and Windows Defender Firewall audit dashboard."""

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
            text="FIREWALL & NETWORK CONNECTIONS",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 14, "bold"),
            anchor="w",
        )
        title_lbl.pack(fill="x")

        desc_lbl = tk.Label(
            header_frame,
            text="Passive network auditor. Inspects active process endpoints and verifies Windows Defender Firewall health.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10),
            anchor="w",
        )
        desc_lbl.pack(fill="x", pady=(2, 8))

        # Firewall Profiles Cards Bar
        cards_frame = tk.Frame(header_frame, bg=THEME["bg_panel"])
        cards_frame.pack(fill="x")

        self.lbl_domain = tk.Label(
            cards_frame,
            text="Domain Profile: AUDITING...",
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 9, "bold"),
            padx=12,
            pady=6,
        )
        self.lbl_domain.pack(side="left", padx=(0, 10))

        self.lbl_private = tk.Label(
            cards_frame,
            text="Private Profile: AUDITING...",
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 9, "bold"),
            padx=12,
            pady=6,
        )
        self.lbl_private.pack(side="left", padx=(0, 10))

        self.lbl_public = tk.Label(
            cards_frame,
            text="Public Profile: AUDITING...",
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 9, "bold"),
            padx=12,
            pady=6,
        )
        self.lbl_public.pack(side="left")

        is_adm = is_user_admin()
        status_note = (
            "🛡️ Enforcement Mode: Administrator (Active netsh rule application and rollback supported)"
            if is_adm
            else "⚠️ Enforcement Mode: Standard User (Audit-Only; active netsh rule changes require Administrator elevation)"
        )
        note_color = THEME["status_safe"] if is_adm else THEME["status_warning"]
        self.lbl_enforcement_note = tk.Label(
            header_frame,
            text=status_note,
            bg=THEME["bg_panel"],
            fg=note_color,
            font=(THEME["font_family"], 8, "bold"),
            anchor="w",
        )
        self.lbl_enforcement_note.pack(fill="x", pady=(8, 0))

        # Network Connections Table
        table_container = tk.Frame(self, bg=THEME["bg_input"])
        table_container.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        columns = ("proto", "local", "foreign", "state", "pid", "process", "audit")
        self.tree = ttk.Treeview(table_container, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("proto", text="PROTO")
        self.tree.heading("local", text="LOCAL ADDRESS")
        self.tree.heading("foreign", text="FOREIGN ENDPOINT")
        self.tree.heading("state", text="STATE")
        self.tree.heading("pid", text="PID")
        self.tree.heading("process", text="PROCESS")
        self.tree.heading("audit", text="AUDIT FLAG")

        self.tree.column("proto", width=60, anchor="center")
        self.tree.column("local", width=180)
        self.tree.column("foreign", width=180)
        self.tree.column("state", width=110, anchor="center")
        self.tree.column("pid", width=70, anchor="center")
        self.tree.column("process", width=160)
        self.tree.column("audit", width=140)

        scrollbar = ttk.Scrollbar(table_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Bottom Bar
        bottom_bar = tk.Frame(self, bg=THEME["bg_darkest"])
        bottom_bar.pack(fill="x", padx=20, pady=(0, 20))

        notice_lbl = tk.Label(
            bottom_bar,
            text="* System Compliance: Windows Defender & Windows Firewall are never modified or disabled.",
            bg=THEME["bg_darkest"],
            fg=THEME["text_muted"],
            font=(THEME["font_family"], 8),
        )
        notice_lbl.pack(side="left")

        self.btn_refresh = ttk.Button(
            bottom_bar,
            text="Audit Active Connections",
            style="Primary.TButton",
            command=self._async_refresh,
        )
        self.btn_refresh.pack(side="right")

    def _async_refresh(self) -> None:
        threading.Thread(target=self.refresh_data, daemon=True).start()

    def refresh_data(self) -> None:
        """Query firewall status and active network connections."""
        fw_status = self.engine.firewall_monitor.get_firewall_profiles_status()

        dom_state = fw_status.get("Domain", "ON")
        priv_state = fw_status.get("Private", "ON")
        pub_state = fw_status.get("Public", "ON")

        self.lbl_domain.config(text=f"Domain Profile: {dom_state}", fg=THEME["status_safe"] if dom_state == "ON" else THEME["status_warning"])
        self.lbl_private.config(text=f"Private Profile: {priv_state}", fg=THEME["status_safe"] if priv_state == "ON" else THEME["status_warning"])
        self.lbl_public.config(text=f"Public Profile: {pub_state}", fg=THEME["status_safe"] if pub_state == "ON" else THEME["status_warning"])

        conns = self.engine.firewall_monitor.get_active_connections(limit=35)

        def _update_ui():
            self.tree.delete(*self.tree.get_children())
            for c in conns:
                flag = "⚠️ Suspicious Port" if c.get("is_suspicious") else "Normal"
                self.tree.insert(
                    "",
                    "end",
                    values=(
                        c["protocol"],
                        c["local_address"],
                        c["foreign_address"],
                        c["state"],
                        c["pid"],
                        c["process_name"],
                        flag,
                    ),
                )

        self.after(0, _update_ui)
