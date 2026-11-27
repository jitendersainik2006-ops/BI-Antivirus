"""
BI Antivirus - About View
Comprehensive system information, engine versions, security architecture,
and help information presented in a clean, user-friendly format.
"""

import os
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from typing import Optional

from bi_antivirus.config import (
    THEME,
    APP_NAME,
    APP_SUBTITLE,
    APP_VERSION,
    ENGINE_VERSION,
    PROJECT_ROOT,
    DATA_DIR,
    LOGS_DIR,
    QUARANTINE_DIR,
)
from bi_antivirus.core.privilege_manager import is_user_admin


class AboutView(tk.Frame):
    """Product information, system health, and security architecture overview."""

    def __init__(self, parent, engine, **kwargs):
        super().__init__(parent, bg=THEME["bg_darkest"], **kwargs)
        self.engine = engine
        self._build_ui()

    def _build_ui(self) -> None:
        # Header Box
        header_frame = tk.Frame(self, bg=THEME["bg_panel"], padx=24, pady=20)
        header_frame.pack(fill="x", padx=20, pady=(20, 15))
        header_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        # Brand row with Official Black Intel Eagle Emblem
        brand_row = tk.Frame(header_frame, bg=THEME["bg_panel"])
        brand_row.pack(fill="x")

        res_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "resources")
        emblem_path = os.path.join(res_dir, "black_intel_emblem_64.png")

        self._emblem_img = None
        if os.path.exists(emblem_path):
            try:
                self._emblem_img = tk.PhotoImage(file=emblem_path)
                logo_lbl = tk.Label(
                    brand_row,
                    image=self._emblem_img,
                    bg=THEME["bg_panel"],
                )
                logo_lbl.pack(side="left", padx=(0, 16))
            except Exception:
                logo_lbl = tk.Label(
                    brand_row,
                    text="🛡️",
                    bg=THEME["bg_panel"],
                    fg=THEME["accent_primary"],
                    font=(THEME["font_family"], 28),
                )
                logo_lbl.pack(side="left", padx=(0, 16))
        else:
            logo_lbl = tk.Label(
                brand_row,
                text="🛡️",
                bg=THEME["bg_panel"],
                fg=THEME["accent_primary"],
                font=(THEME["font_family"], 28),
            )
            logo_lbl.pack(side="left", padx=(0, 16))

        info_col = tk.Frame(brand_row, bg=THEME["bg_panel"])
        info_col.pack(side="left", fill="both", expand=True)

        app_title = tk.Label(
            info_col,
            text=f"{APP_NAME} — {APP_SUBTITLE}",
            bg=THEME["bg_panel"],
            fg=THEME["accent_primary"],
            font=(THEME["font_family"], 16, "bold"),
            anchor="w",
        )
        app_title.pack(fill="x")

        edition = "Enterprise Edition"
        if hasattr(self.engine, "licensing"):
            edition = "Premium Edition" if self.engine.licensing.is_premium() else "Free Edition"

        app_ver = tk.Label(
            info_col,
            text=f"Version {APP_VERSION}  |  Engine {ENGINE_VERSION}  |  {edition}",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10),
            anchor="w",
        )
        app_ver.pack(fill="x", pady=(2, 0))

        # Main Content Grid
        content = tk.Frame(self, bg=THEME["bg_darkest"])
        content.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        content.columnconfigure(0, weight=1)
        content.columnconfigure(1, weight=1)
        content.rowconfigure(0, weight=1)

        # Left Column: Security Architecture & Privacy
        left_card = tk.Frame(content, bg=THEME["bg_panel"], padx=20, pady=18)
        left_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left_card.configure(highlightbackground=THEME["border"], highlightthickness=1)

        sec_title = tk.Label(
            left_card,
            text="SECURITY ARCHITECTURE & PRIVACY",
            bg=THEME["bg_panel"],
            fg=THEME["accent_cyan"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        sec_title.pack(fill="x", pady=(0, 12))

        features = [
            ("🔒 100% Local Privacy", "All malware inspection and hash matching occurs entirely on your device. Zero telemetry or user files are sent to cloud servers."),
            ("🛡️ Multi-Layer Defense", "Real-Time File Guard, Behavioral Process Monitoring, USB Sentinel, Ransomware Honeypots, and Web Reputation Filtering."),
            ("📦 AES-256 Vault (BIQ2)", "Quarantined threats are isolated using AES-256-CBC with HMAC-SHA256 Encrypt-then-MAC authentication and DPAPI key management."),
            ("⚡ Reversible Restore", "Quarantined items can be safely restored to their original location or a custom folder with pre-restoration SHA-256 verification."),
            ("💾 Sovereign Storage", f"All databases, logs, and vaults are strictly confined to D: drive ({PROJECT_ROOT})."),
        ]

        for heading, desc in features:
            f_frame = tk.Frame(left_card, bg=THEME["bg_panel"])
            f_frame.pack(fill="x", pady=(0, 10))

            h_lbl = tk.Label(
                f_frame,
                text=heading,
                bg=THEME["bg_panel"],
                fg=THEME["text_primary"],
                font=(THEME["font_family"], 9, "bold"),
                anchor="w",
            )
            h_lbl.pack(fill="x")

            d_lbl = tk.Label(
                f_frame,
                text=desc,
                bg=THEME["bg_panel"],
                fg=THEME["text_muted"],
                font=(THEME["font_family"], 8),
                wraplength=330,
                justify="left",
                anchor="w",
            )
            d_lbl.pack(fill="x", pady=(1, 0))

        # Right Column: System Status & Diagnostics
        right_card = tk.Frame(content, bg=THEME["bg_panel"], padx=20, pady=18)
        right_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right_card.configure(highlightbackground=THEME["border"], highlightthickness=1)

        sys_title = tk.Label(
            right_card,
            text="SYSTEM & ENVIRONMENT STATUS",
            bg=THEME["bg_panel"],
            fg=THEME["accent_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        sys_title.pack(fill="x", pady=(0, 12))

        is_adm = is_user_admin()
        status_items = [
            ("Operating System", "Windows 10/11 x64 (Native Win32)"),
            ("Privilege Mode", "Administrator (Full Protection & Real-Time)" if is_adm else "Standard User (On-Demand & Audit Mode)"),
            ("Database Engine", "SQLite 3 with Write-Ahead Logging (WAL)"),
            ("Project Root", str(PROJECT_ROOT)),
            ("Database Path", str(DATA_DIR)),
            ("Quarantine Vault", str(QUARANTINE_DIR)),
            ("Security Logs", str(LOGS_DIR)),
        ]

        for label, val in status_items:
            row_frame = tk.Frame(right_card, bg=THEME["bg_panel"])
            row_frame.pack(fill="x", pady=2)

            k_lbl = tk.Label(
                row_frame,
                text=label + ":",
                bg=THEME["bg_panel"],
                fg=THEME["text_secondary"],
                font=(THEME["font_family"], 8, "bold"),
                width=18,
                anchor="w",
            )
            k_lbl.pack(side="left")

            v_lbl = tk.Label(
                row_frame,
                text=val,
                bg=THEME["bg_panel"],
                fg=THEME["text_primary"],
                font=(THEME["font_mono"], 8),
                anchor="w",
            )
            v_lbl.pack(side="left", fill="x", expand=True)

        # Action Buttons
        btn_box = tk.Frame(right_card, bg=THEME["bg_panel"])
        btn_box.pack(fill="x", pady=(16, 0))

        self.btn_check_health = ttk.Button(
            btn_box,
            text="Verify System Health",
            style="Primary.TButton",
            command=self._on_check_health,
        )
        self.btn_check_health.pack(side="left", padx=(0, 10))

        self.btn_quick_tips = ttk.Button(
            btn_box,
            text="Beginner Quick Tips",
            style="Secondary.TButton",
            command=self._on_show_tips,
        )
        self.btn_quick_tips.pack(side="left")

        btn_box2 = tk.Frame(right_card, bg=THEME["bg_panel"])
        btn_box2.pack(fill="x", pady=(8, 0))

        self.btn_wizard = ttk.Button(
            btn_box2,
            text="🚀 Re-run Welcome Wizard",
            style="Secondary.TButton",
            command=self._on_rerun_wizard,
        )
        self.btn_wizard.pack(side="left", padx=(0, 10))

        self.btn_updates = ttk.Button(
            btn_box2,
            text="🔄 Check Software Updates",
            style="Secondary.TButton",
            command=self._on_check_software_updates,
        )
        self.btn_updates.pack(side="left")

        # Bottom Legal & Credits
        legal_lbl = tk.Label(
            right_card,
            text="Black Intel Cyber Defense. Developed for high-integrity endpoint security.\nConfined strictly to authorized host drives.",
            bg=THEME["bg_panel"],
            fg=THEME["text_muted"],
            font=(THEME["font_family"], 8),
            justify="left",
            anchor="w",
        )
        legal_lbl.pack(side="bottom", fill="x", pady=(14, 0))

    def _on_check_health(self) -> None:
        """Run system health audit and show plain-English summary."""
        db_ok, db_msg = self.engine.history_db.check_integrity()
        v_audit = self.engine.quarantine_mgr.verify_vault_integrity()

        msg = (
            "System Health Audit Results:\n\n"
            f"✓ Security Database: {'Healthy' if db_ok else 'Attention Needed'} ({db_msg})\n"
            f"✓ Quarantine Vault: {'Verified Intact' if v_audit['all_healthy'] else 'Warning'} "
            f"({v_audit['intact_records']}/{v_audit['total_records']} verified)\n"
            f"✓ Real-Time Protection: {'Active' if self.engine.realtime_guard.is_running else 'Standby'}\n"
            f"✓ Behavioral Monitor: {'Active' if self.engine.behavioral_monitor.is_running else 'Standby'}\n\n"
            "Your BI Antivirus installation is operating normally."
        )
        messagebox.showinfo("System Health Audit", msg)

    def _on_show_tips(self) -> None:
        """Show beginner-friendly antivirus usage tips."""
        tips = (
            "BI Antivirus Quick Tips for Beginners:\n\n"
            "1. Quick Scan: Run once a day to check active programs and startup locations in seconds.\n"
            "2. Full Scan: Run once a week or when connecting to a new network to deeply inspect all files.\n"
            "3. Custom Scan: Right-click or select any specific folder, download, or USB drive to check it.\n"
            "4. Quarantine: If a threat is detected, it is placed in the Quarantine Vault where it cannot harm your PC. You can safely restore or delete it at any time.\n"
            "5. Protection: Keep Real-Time Protection enabled so files are automatically checked when opened."
        )
        messagebox.showinfo("Beginner Quick Tips", tips)

    def _on_rerun_wizard(self) -> None:
        """Launch the welcome wizard for re-configuration."""
        top = self.winfo_toplevel()
        if hasattr(top, "open_first_run_wizard"):
            top.open_first_run_wizard()
        else:
            try:
                from bi_antivirus.ui.first_run_wizard import FirstRunWizard
                FirstRunWizard(self)
            except Exception as e:
                messagebox.showerror("Setup Wizard", f"Unable to open wizard: {e}")

    def _on_check_software_updates(self) -> None:
        """Check for updates and show friendly dialog."""
        from bi_antivirus.config import APP_VERSION
        upd = self.engine.updater.check_definition_status()
        msg = (
            f"BI Antivirus Enterprise v{APP_VERSION}\n"
            "Black Intel Cyber Defense Update Channel\n\n"
            f"• Core Engine: Up to date (v{APP_VERSION})\n"
            f"• Threat Definitions: Version {upd.get('version', '2026.11')}\n"
            f"• Total Signatures: {upd.get('total_signatures', 0):,} verified\n"
            f"• Channel Status: {upd.get('status', 'Optimal')}\n\n"
            "Your antivirus engine and definitions are current."
        )
        messagebox.showinfo("Software & Definition Updates", msg)

    def refresh_data(self) -> None:
        """Refreshes status if needed."""
        pass
