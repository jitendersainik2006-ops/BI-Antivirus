"""
BI Antivirus - Automation & Integrations View
Controls loopback REST API status, n8n webhook configuration, voice alert sentinel,
and displays recent automated threat dispatch telemetry.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import time
from pathlib import Path
from typing import Dict, Any, Optional

from bi_antivirus.config import THEME, load_settings, save_settings, DATA_DIR
from bi_antivirus.api.auth import get_or_create_api_key, API_KEY_FILE
from bi_antivirus.api.n8n_daemon import n8n_daemon, check_n8n_health, N8nLocalDaemon


class AutomationView(tk.Frame):
    """Configuration and monitoring dashboard for n8n automation, REST API, and voice alerts."""

    def __init__(self, parent, engine, **kwargs):
        super().__init__(parent, bg=THEME["bg_darkest"], **kwargs)
        self.engine = engine
        self._key_visible = False
        self._build_ui()
        self.refresh_data()

    def _build_ui(self) -> None:
        # 1. Header Frame
        header_frame = tk.Frame(self, bg=THEME["bg_panel"], padx=20, pady=16)
        header_frame.pack(fill="x", padx=20, pady=(20, 15))
        header_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        title_lbl = tk.Label(
            header_frame,
            text="AUTOMATION & VOICE INTEGRATIONS",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 14, "bold"),
            anchor="w",
        )
        title_lbl.pack(fill="x")

        desc_lbl = tk.Label(
            header_frame,
            text="Local authenticated REST API (127.0.0.1:8765), n8n workflow triggers, and audible security alerts.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10),
            anchor="w",
        )
        desc_lbl.pack(fill="x", pady=(2, 0))

        # Main scrollable or 2-column container
        content_frame = tk.Frame(self, bg=THEME["bg_darkest"])
        content_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Split into Left Column (Controls & Settings) and Right Column (History & API Info)
        left_col = tk.Frame(content_frame, bg=THEME["bg_darkest"], width=480)
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 10))

        right_col = tk.Frame(content_frame, bg=THEME["bg_darkest"], width=520)
        right_col.pack(side="right", fill="both", expand=True, padx=(10, 0))

        # ==========================================
        # LEFT COLUMN: Status Badges, API & Voice
        # ==========================================

        # Card 1: API & Automation Status
        status_card = tk.Frame(left_col, bg=THEME["bg_panel"], padx=16, pady=14)
        status_card.pack(fill="x", pady=(0, 12))
        status_card.configure(highlightbackground=THEME["border"], highlightthickness=1)

        sc_title = tk.Label(
            status_card,
            text="INTEGRATION STATUS TELEMETRY",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        sc_title.pack(fill="x", pady=(0, 8))

        # Status Rows
        badges_frame = tk.Frame(status_card, bg=THEME["bg_panel"])
        badges_frame.pack(fill="x")

        # API Server Badge
        row1 = tk.Frame(badges_frame, bg=THEME["bg_panel"])
        row1.pack(fill="x", pady=2)
        tk.Label(row1, text="Local REST API: ", bg=THEME["bg_panel"], fg=THEME["text_secondary"], font=(THEME["font_family"], 9, "bold")).pack(side="left")
        self.lbl_api_status = tk.Label(row1, text="CHECKING...", bg=THEME["bg_panel"], fg=THEME["status_safe"], font=(THEME["font_family"], 9, "bold"))
        self.lbl_api_status.pack(side="left")

        # n8n Automation Badge
        row2 = tk.Frame(badges_frame, bg=THEME["bg_panel"])
        row2.pack(fill="x", pady=2)
        tk.Label(row2, text="n8n Automation: ", bg=THEME["bg_panel"], fg=THEME["text_secondary"], font=(THEME["font_family"], 9, "bold")).pack(side="left")
        self.lbl_n8n_status = tk.Label(row2, text="OFFLINE", bg=THEME["bg_panel"], fg=THEME["text_muted"], font=(THEME["font_family"], 9, "bold"))
        self.lbl_n8n_status.pack(side="left")

        # Voice Alert Engine Badge
        row3 = tk.Frame(badges_frame, bg=THEME["bg_panel"])
        row3.pack(fill="x", pady=2)
        tk.Label(row3, text="Voice Engine: ", bg=THEME["bg_panel"], fg=THEME["text_secondary"], font=(THEME["font_family"], 9, "bold")).pack(side="left")
        self.lbl_voice_status = tk.Label(row3, text="WINDOWS SAPI (Active)", bg=THEME["bg_panel"], fg=THEME["accent_primary"], font=(THEME["font_family"], 9, "bold"))
        self.lbl_voice_status.pack(side="left")

        # Card 2: REST API Key Access
        api_card = tk.Frame(left_col, bg=THEME["bg_panel"], padx=16, pady=14)
        api_card.pack(fill="x", pady=(0, 12))
        api_card.configure(highlightbackground=THEME["border"], highlightthickness=1)

        api_title = tk.Label(
            api_card,
            text="API AUTHENTICATION (X-BI-API-Key)",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        api_title.pack(fill="x")

        api_desc = tk.Label(
            api_card,
            text="256-bit token stored strictly on D: drive for loopback requests:",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            anchor="w",
        )
        api_desc.pack(fill="x", pady=(2, 6))

        # API Key input with Show/Hide and Copy
        key_row = tk.Frame(api_card, bg=THEME["bg_panel"])
        key_row.pack(fill="x", pady=(2, 6))

        self.key_entry = tk.Entry(
            key_row,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=(THEME["font_mono"], 9),
            show="•",
            relief="flat",
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        self.key_entry.pack(side="left", fill="x", expand=True, padx=(0, 6), ipady=4)

        self.btn_toggle_key = ttk.Button(key_row, text="Show", style="Secondary.TButton", width=6, command=self._toggle_key_visibility)
        self.btn_toggle_key.pack(side="left", padx=(0, 4))

        self.btn_copy_key = ttk.Button(key_row, text="Copy", style="Secondary.TButton", width=6, command=self._copy_api_key)
        self.btn_copy_key.pack(side="left")

        # Card 3: Voice Alert Controls
        voice_card = tk.Frame(left_col, bg=THEME["bg_panel"], padx=16, pady=14)
        voice_card.pack(fill="x", pady=(0, 0))
        voice_card.configure(highlightbackground=THEME["border"], highlightthickness=1)

        v_title = tk.Label(
            voice_card,
            text="VOICE ALERT SENTINEL CONTROLS",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        v_title.pack(fill="x")

        # Voice Engine Selector
        eng_row = tk.Frame(voice_card, bg=THEME["bg_panel"])
        eng_row.pack(fill="x", pady=(8, 4))

        tk.Label(eng_row, text="Engine:", bg=THEME["bg_panel"], fg=THEME["text_secondary"], font=(THEME["font_family"], 9, "bold")).pack(side="left", padx=(0, 8))
        self.voice_engine_var = tk.StringVar(value="SAPI")
        
        rb1 = tk.Radiobutton(
            eng_row,
            text="Windows SAPI (Offline, 0-dep)",
            variable=self.voice_engine_var,
            value="SAPI",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            selectcolor=THEME["bg_darkest"],
            activebackground=THEME["bg_panel"],
            activeforeground=THEME["accent_primary"],
            font=(THEME["font_family"], 9),
            command=self._on_voice_settings_change,
        )
        rb1.pack(side="left", padx=(0, 10))

        rb2 = tk.Radiobutton(
            eng_row,
            text="VoiceStudio (Local HTTP)",
            variable=self.voice_engine_var,
            value="VoiceStudio",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            selectcolor=THEME["bg_darkest"],
            activebackground=THEME["bg_panel"],
            activeforeground=THEME["accent_primary"],
            font=(THEME["font_family"], 9),
            command=self._on_voice_settings_change,
        )
        rb2.pack(side="left")

        # Volume Slider
        vol_row = tk.Frame(voice_card, bg=THEME["bg_panel"])
        vol_row.pack(fill="x", pady=(8, 4))

        tk.Label(vol_row, text="Alert Volume:", bg=THEME["bg_panel"], fg=THEME["text_secondary"], font=(THEME["font_family"], 9, "bold")).pack(side="left", padx=(0, 10))

        self.vol_scale = tk.Scale(
            vol_row,
            from_=0,
            to=100,
            orient="horizontal",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            highlightthickness=0,
            troughcolor=THEME["bg_input"],
            activebackground=THEME["accent_primary"],
            command=self._on_volume_slide,
        )
        self.vol_scale.set(85)
        self.vol_scale.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.lbl_vol_val = tk.Label(vol_row, text="85%", bg=THEME["bg_panel"], fg=THEME["accent_primary"], font=(THEME["font_mono"], 9, "bold"), width=5)
        self.lbl_vol_val.pack(side="left")

        # Mute and Test Row
        action_vrow = tk.Frame(voice_card, bg=THEME["bg_panel"])
        action_vrow.pack(fill="x", pady=(8, 2))

        self.mute_var = tk.BooleanVar(value=False)
        cb_mute = tk.Checkbutton(
            action_vrow,
            text="Mute Voice Alerts",
            variable=self.mute_var,
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            selectcolor=THEME["bg_darkest"],
            activebackground=THEME["bg_panel"],
            activeforeground=THEME["text_primary"],
            font=(THEME["font_family"], 9),
            command=self._on_voice_settings_change,
        )
        cb_mute.pack(side="left")

        btn_test_voice = ttk.Button(
            action_vrow,
            text="🔊 Test Voice Alert",
            style="Secondary.TButton",
            command=self._on_test_voice,
        )
        btn_test_voice.pack(side="right")

        # ==========================================
        # RIGHT COLUMN: n8n Webhook & Dispatch Table
        # ==========================================

        # Card 4: n8n Webhook Integration Configuration
        webhook_card = tk.Frame(right_col, bg=THEME["bg_panel"], padx=16, pady=14)
        webhook_card.pack(fill="x", pady=(0, 12))
        webhook_card.configure(highlightbackground=THEME["border"], highlightthickness=1)

        wh_title = tk.Label(
            webhook_card,
            text="N8N THREAT DISPATCH & APPROVAL",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        wh_title.pack(fill="x")

        wh_desc = tk.Label(
            webhook_card,
            text="Target endpoint receiving sanitized threat telemetry for Telegram / Email alerts:",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            anchor="w",
        )
        wh_desc.pack(fill="x", pady=(2, 6))

        # Webhook URL input
        wh_url_frame = tk.Frame(webhook_card, bg=THEME["bg_panel"])
        wh_url_frame.pack(fill="x", pady=(2, 6))

        tk.Label(wh_url_frame, text="Webhook URL: ", bg=THEME["bg_panel"], fg=THEME["text_secondary"], font=(THEME["font_family"], 9)).pack(side="left")
        self.wh_entry = tk.Entry(
            wh_url_frame,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=(THEME["font_mono"], 9),
            relief="flat",
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        self.wh_entry.pack(side="left", fill="x", expand=True, padx=(4, 0), ipady=3)

        # Safeguard Approval Toggle & Save Button
        wh_opts_frame = tk.Frame(webhook_card, bg=THEME["bg_panel"])
        wh_opts_frame.pack(fill="x", pady=(6, 0))

        self.wh_approval_var = tk.BooleanVar(value=True)
        cb_approval = tk.Checkbutton(
            wh_opts_frame,
            text="Integration Approved (Enable automated outgoing threat events)",
            variable=self.wh_approval_var,
            bg=THEME["bg_panel"],
            fg=THEME["status_safe"],
            selectcolor=THEME["bg_darkest"],
            activebackground=THEME["bg_panel"],
            activeforeground=THEME["status_safe"],
            font=(THEME["font_family"], 9, "bold"),
            command=self._on_approval_toggle,
        )
        cb_approval.pack(side="left")

        btn_save_wh = ttk.Button(
            wh_opts_frame,
            text="Save Settings",
            style="Primary.TButton",
            command=self._on_save_webhook_settings,
        )
        btn_save_wh.pack(side="right")

        # Local n8n Bridge Control Toolbar
        bridge_frame = tk.Frame(webhook_card, bg=THEME["bg_panel"])
        bridge_frame.pack(fill="x", pady=(10, 2))

        self.btn_toggle_bridge = ttk.Button(
            bridge_frame,
            text="Start Local n8n Bridge (127.0.0.1:5678)",
            style="Secondary.TButton",
            command=self._on_toggle_bridge,
        )
        self.btn_toggle_bridge.pack(side="left", padx=(0, 8))

        btn_test_n8n_conn = ttk.Button(
            bridge_frame,
            text="Verify Connection",
            style="Secondary.TButton",
            command=self._on_test_n8n_connection,
        )
        btn_test_n8n_conn.pack(side="left")

        # Card 5: Recent Dispatch History Table
        hist_card = tk.Frame(right_col, bg=THEME["bg_panel"], padx=16, pady=14)
        hist_card.pack(fill="both", expand=True)
        hist_card.configure(highlightbackground=THEME["border"], highlightthickness=1)

        hist_header_row = tk.Frame(hist_card, bg=THEME["bg_panel"])
        hist_header_row.pack(fill="x", pady=(0, 8))

        tk.Label(
            hist_header_row,
            text="AUTOMATION DISPATCH LOG",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
        ).pack(side="left")

        btn_refresh = ttk.Button(
            hist_header_row,
            text="↻ Refresh",
            style="Secondary.TButton",
            command=self.refresh_data,
        )
        btn_refresh.pack(side="right")

        # Table
        tbl_container = tk.Frame(hist_card, bg=THEME["bg_panel"])
        tbl_container.pack(fill="both", expand=True)

        columns = ("time", "threat", "severity", "status", "retries")
        self.tree = ttk.Treeview(tbl_container, columns=columns, show="headings", selectmode="browse", height=7)

        self.tree.heading("time", text="TIME (UTC)")
        self.tree.heading("threat", text="THREAT NAME")
        self.tree.heading("severity", text="SEVERITY")
        self.tree.heading("status", text="DELIVERY")
        self.tree.heading("retries", text="ATTEMPTS")

        self.tree.column("time", width=120, anchor="w")
        self.tree.column("threat", width=140, anchor="w")
        self.tree.column("severity", width=75, anchor="center")
        self.tree.column("status", width=95, anchor="center")
        self.tree.column("retries", width=65, anchor="center")

        tree_scroll = ttk.Scrollbar(tbl_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")

    def _toggle_key_visibility(self) -> None:
        """Toggle masked vs plain text display of the API key."""
        self._key_visible = not self._key_visible
        if self._key_visible:
            self.key_entry.configure(show="")
            self.btn_toggle_key.configure(text="Hide")
        else:
            self.key_entry.configure(show="•")
            self.btn_toggle_key.configure(text="Show")

    def _copy_api_key(self) -> None:
        """Copy the local API key to clipboard."""
        try:
            key = self.key_entry.get().strip()
            self.clipboard_clear()
            self.clipboard_append(key)
            messagebox.showinfo("Copied", "BI Antivirus API Key copied to clipboard.\nKeep this key confidential.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed copying to clipboard: {e}")

    def _on_volume_slide(self, val: str) -> None:
        """Handle volume scale slider drag."""
        vol = int(float(val))
        self.lbl_vol_val.config(text=f"{vol}%")
        settings = load_settings()
        settings["voice_volume"] = vol
        save_settings(settings)

    def _on_voice_settings_change(self) -> None:
        """Persist engine mode and mute state."""
        settings = load_settings()
        settings["voice_engine"] = self.voice_engine_var.get()
        settings["voice_muted"] = bool(self.mute_var.get())
        save_settings(settings)
        self._update_badges()

    def _on_test_voice(self) -> None:
        """Trigger a safe audio test announcement."""
        engine_type = self.voice_engine_var.get()
        text = "BI Antivirus voice alert sentinel is operational."
        if hasattr(self.engine, "voice") and self.engine.voice:
            res = self.engine.voice.announce(text, priority="CRITICAL", force=True)
            messagebox.showinfo(
                "Voice Test Dispatched",
                f"Dispatched voice announcement via {engine_type}.\nResult: {res.get('status')}",
            )
        else:
            messagebox.showwarning("Voice Service", "Voice service instance is not attached.")

    def _on_approval_toggle(self) -> None:
        """Save webhook approval state."""
        settings = load_settings()
        settings["webhook_enabled"] = bool(self.wh_approval_var.get())
        save_settings(settings)
        self._update_badges()

    def _on_save_webhook_settings(self) -> None:
        """Save configured webhook endpoint."""
        url = self.wh_entry.get().strip()
        settings = load_settings()
        settings["webhook_url"] = url
        settings["webhook_enabled"] = bool(self.wh_approval_var.get())
        save_settings(settings)
        messagebox.showinfo("Saved", "Automation webhook settings updated successfully.")
        self._update_badges()

    def _on_toggle_bridge(self) -> None:
        """Start or stop the localhost n8n automation bridge daemon."""
        if n8n_daemon.is_running:
            n8n_daemon.stop()
            self.btn_toggle_bridge.configure(text="Start Local n8n Bridge (127.0.0.1:5678)")
            messagebox.showinfo("n8n Bridge", "Local n8n automation bridge stopped.")
        else:
            started = n8n_daemon.start()
            if started:
                self.btn_toggle_bridge.configure(text="Stop Local n8n Bridge (127.0.0.1:5678)")
                messagebox.showinfo(
                    "n8n Bridge Online",
                    "Local n8n automation bridge started on http://127.0.0.1:5678\n"
                    "Ready to receive threat webhooks and test automation.",
                )
            else:
                messagebox.showerror("Error", "Failed to bind to http://127.0.0.1:5678\n(Port may already be in use)")
        self._update_badges()

    def _on_test_n8n_connection(self) -> None:
        """Run loopback health and connectivity check between n8n and BI Antivirus API."""
        n8n_alive, n8n_info = check_n8n_health()
        code, api_info = N8nLocalDaemon.execute_workflow_05_status_monitor()

        lines = []
        if n8n_alive:
            lines.append("✔ n8n Local Bridge: ONLINE (127.0.0.1:5678)")
            lines.append(f"   Service: {n8n_info.get('service', 'n8n')}")
            lines.append(f"   Uptime: {n8n_info.get('uptime_seconds', 0)}s")
        else:
            lines.append("✖ n8n Local Bridge: OFFLINE (Click 'Start Local n8n Bridge')")

        if code == 200:
            lines.append(f"✔ BI Antivirus REST API: ONLINE (127.0.0.1:8765)")
            lines.append(f"   Engine Status: {api_info.get('status', 'PROTECTED')}")
            lines.append(f"   Signatures: {api_info.get('total_signatures', 0)}")
        else:
            lines.append(f"✖ BI Antivirus REST API: HTTP {code}")

        if n8n_alive and code == 200:
            lines.append("\n✅ Two-way loopback integration is operational!")
            messagebox.showinfo("n8n ↔ Antivirus Verification", "\n".join(lines))
        else:
            lines.append("\n⚠️ Review service status above.")
            messagebox.showwarning("n8n ↔ Antivirus Verification", "\n".join(lines))

    def _update_badges(self) -> None:
        """Update live status badges based on engine and settings state."""
        # 1. API Server Status
        if hasattr(self.engine, "api_server") and getattr(self.engine.api_server, "is_running", False):
            self.lbl_api_status.config(text="● ACTIVE (127.0.0.1:8765)", fg=THEME["status_safe"])
        else:
            self.lbl_api_status.config(text="● STOPPED", fg=THEME["status_threat"])

        # 2. n8n Automation Status
        settings = load_settings()
        wh_url = settings.get("webhook_url", "")
        wh_enabled = settings.get("webhook_enabled", True)

        if not wh_enabled:
            self.lbl_n8n_status.config(text="● PAUSED (Approval Required)", fg=THEME["status_warning"])
        elif not wh_url:
            self.lbl_n8n_status.config(text="● OFFLINE (No Webhook Set)", fg=THEME["text_muted"])
        else:
            # Active probe of localhost:5678
            is_alive, _ = check_n8n_health()
            if is_alive:
                self.lbl_n8n_status.config(text="● ACTIVE (n8n Listening on 127.0.0.1:5678)", fg=THEME["status_safe"])
            else:
                self.lbl_n8n_status.config(text="● STANDBY (Approved, Daemon Offline)", fg=THEME["status_warning"])

        # 3. Voice Status
        v_eng = settings.get("voice_engine", "SAPI")
        v_muted = settings.get("voice_muted", False)
        if v_muted:
            self.lbl_voice_status.config(text=f"● MUTED ({v_eng})", fg=THEME["text_muted"])
        else:
            self.lbl_voice_status.config(text=f"● ACTIVE ({v_eng})", fg=THEME["accent_primary"])

    def refresh_data(self) -> None:
        """Reload settings, API key, badges, and recent dispatch history."""
        settings = load_settings()

        # Update API key
        current_key = get_or_create_api_key()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, current_key)

        # Update controls
        self.wh_entry.delete(0, tk.END)
        self.wh_entry.insert(0, settings.get("webhook_url", "http://127.0.0.1:5678/webhook/bi-antivirus-threat"))

        self.wh_approval_var.set(settings.get("webhook_enabled", True))
        self.voice_engine_var.set(settings.get("voice_engine", "SAPI"))
        self.mute_var.set(settings.get("voice_muted", False))
        vol = int(settings.get("voice_volume", 85))
        self.vol_scale.set(vol)
        self.lbl_vol_val.config(text=f"{vol}%")

        self._update_badges()

        if hasattr(self, "btn_toggle_bridge"):
            if n8n_daemon.is_running:
                self.btn_toggle_bridge.configure(text="Stop Local n8n Bridge (127.0.0.1:5678)")
            else:
                self.btn_toggle_bridge.configure(text="Start Local n8n Bridge (127.0.0.1:5678)")

        # Refresh dispatch table
        for item in self.tree.get_children():
            self.tree.delete(item)

        history = []
        if hasattr(self.engine, "dispatcher") and self.engine.dispatcher:
            history = getattr(self.engine.dispatcher, "dispatched_history", [])

        if not history:
            # Add placeholder row
            self.tree.insert("", "end", values=("No events yet", "System idle", "NONE", "IDLE", "0"))
        else:
            # Show newest first
            for evt in reversed(history[-50:]):
                t_str = evt.get("timestamp", "")
                t_display = t_str[11:19] if len(t_str) >= 19 else t_str
                self.tree.insert(
                    "",
                    "end",
                    values=(
                        t_display,
                        evt.get("threat_name", "Unknown"),
                        evt.get("severity", "NORMAL"),
                        evt.get("delivery_status", evt.get("status", "SENT")),
                        evt.get("attempts", 1),
                    ),
                )
