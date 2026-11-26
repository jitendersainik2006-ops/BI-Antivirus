"""
BI Antivirus - Quarantine Vault View
Reversibly inspects, restores, or permanently purges isolated threats on D: drive
with AES-256 (BIQ2) authenticated encryption, pre-restoration integrity checks,
and clear user-friendly confirmation dialogs.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from typing import Dict, Any, Optional

from bi_antivirus.config import THEME, QUARANTINE_DIR
from bi_antivirus.ui.widgets.cards import EmptyStateCard


class QuarantineView(tk.Frame):
    """Quarantine vault management interface supporting 100% reversible restoration."""

    def __init__(self, parent, engine, **kwargs):
        super().__init__(parent, bg=THEME["bg_darkest"], **kwargs)
        self.engine = engine
        self._build_ui()

    def _build_ui(self) -> None:
        # Header Box
        header_frame = tk.Frame(self, bg=THEME["bg_panel"], padx=20, pady=16)
        header_frame.pack(fill="x", padx=20, pady=(20, 12))
        header_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        header_top = tk.Frame(header_frame, bg=THEME["bg_panel"])
        header_top.pack(fill="x")

        title_lbl = tk.Label(
            header_top,
            text="QUARANTINE VAULT",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 14, "bold"),
            anchor="w",
        )
        title_lbl.pack(side="left")

        self.vault_status_badge = tk.Label(
            header_top,
            text="🔒 AES-256 AUTHENTICATED (BIQ2)",
            bg=THEME["bg_panel"],
            fg=THEME["accent_primary"],
            font=(THEME["font_family"], 9, "bold"),
        )
        self.vault_status_badge.pack(side="right")

        desc_lbl = tk.Label(
            header_frame,
            text=(
                "Files here are safely encrypted and neutralized so they cannot execute or harm your PC.\n"
                "You can safely restore false positives to their original location, extract them to a test folder, or permanently delete them."
            ),
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            anchor="w",
            justify="left",
        )
        desc_lbl.pack(fill="x", pady=(6, 0))

        # Main Table Container
        self.table_container = tk.Frame(self, bg=THEME["bg_input"])
        self.table_container.pack(fill="both", expand=True, padx=20, pady=(0, 12))

        columns = ("id", "filename", "threat_name", "severity", "date", "original_path")
        self.tree = ttk.Treeview(self.table_container, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("id", text="QUARANTINE ID")
        self.tree.heading("filename", text="FILE NAME")
        self.tree.heading("threat_name", text="THREAT DETECTED")
        self.tree.heading("severity", text="RISK LEVEL")
        self.tree.heading("date", text="DATE QUARANTINED")
        self.tree.heading("original_path", text="ORIGINAL LOCATION")

        self.tree.column("id", width=140, minwidth=110)
        self.tree.column("filename", width=140, minwidth=100)
        self.tree.column("threat_name", width=150, minwidth=120)
        self.tree.column("severity", width=85, minwidth=70, anchor="center")
        self.tree.column("date", width=130, minwidth=110)
        self.tree.column("original_path", width=170, minwidth=130)

        scrollbar = ttk.Scrollbar(self.table_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Empty State Card (Shown when vault is empty)
        self.empty_card = EmptyStateCard(
            self.table_container,
            icon="📦",
            title="Quarantine Vault is Empty",
            message="No suspicious or malicious files are currently isolated on your system. Your PC is clean and healthy.",
        )

        # Action Button Toolbar
        toolbar = tk.Frame(self, bg=THEME["bg_darkest"])
        toolbar.pack(fill="x", padx=20, pady=(0, 20))

        self.btn_restore = ttk.Button(
            toolbar,
            text="✓ Restore to Original",
            style="Primary.TButton",
            command=self._on_restore_original,
        )
        self.btn_restore.pack(side="left", padx=(0, 8))

        self.btn_restore_to = ttk.Button(
            toolbar,
            text="📁 Restore to Folder...",
            style="Secondary.TButton",
            command=self._on_restore_custom,
        )
        self.btn_restore_to.pack(side="left", padx=(0, 8))

        self.btn_purge = ttk.Button(
            toolbar,
            text="🗑️ Permanently Delete",
            style="Danger.TButton",
            command=self._on_purge,
        )
        self.btn_purge.pack(side="left", padx=(0, 8))

        self.btn_verify = ttk.Button(
            toolbar,
            text="🔍 Verify Vault Integrity",
            style="Secondary.TButton",
            command=self._on_verify_integrity,
        )
        self.btn_verify.pack(side="left", padx=(0, 8))

        self.btn_refresh = ttk.Button(
            toolbar,
            text="🔄 Refresh Vault",
            style="Secondary.TButton",
            command=self.refresh_data,
        )
        self.btn_refresh.pack(side="right")

    def _on_verify_integrity(self) -> None:
        """Execute physical vault integrity audit against disk files."""
        res = self.engine.quarantine_mgr.verify_vault_integrity()
        status_msg = (
            "Quarantine Vault Integrity Audit Results:\n\n"
            f"• Total Quarantined Records: {res['total_records']}\n"
            f"• Verified Intact on Disk: {res['intact_records']}\n"
            f"• Missing Vault Files: {res['missing_records']}\n"
            f"• Corrupt / Invalid Files: {res['corrupt_records']}\n\n"
            f"Vault Status: {'HEALTHY — All records verified cryptographically' if res['all_healthy'] else 'WARNING — Issues detected'}"
        )
        if res.get("issues"):
            status_msg += "\n\nIssues Identified:\n" + "\n".join(res["issues"][:5])

        if res["all_healthy"]:
            messagebox.showinfo("Vault Integrity Audit", status_msg)
        else:
            messagebox.showwarning("Vault Integrity Warning", status_msg)

    def refresh_data(self) -> None:
        """Query quarantine records and repopulate table with friendly empty-state handling."""
        self.tree.delete(*self.tree.get_children())
        records = self.engine.quarantine_mgr.list_quarantine(status="QUARANTINED")

        if not records:
            self.tree.pack_forget()
            self.empty_card.pack(fill="both", expand=True)
            self.vault_status_badge.config(text="● 0 ITEMS ISOLATED", fg=THEME["status_safe"])
        else:
            self.empty_card.pack_forget()
            self.tree.pack(side="left", fill="both", expand=True)
            self.vault_status_badge.config(text=f"● {len(records)} ITEM(S) ISOLATED", fg=THEME["status_warning"])
            for r in records:
                self.tree.insert(
                    "",
                    "end",
                    values=(
                        r["quarantine_id"],
                        r["file_name"],
                        r["threat_name"],
                        r["severity"],
                        r["quarantined_at"],
                        r["original_path"],
                    ),
                )

    def _get_selected_id(self) -> Optional[str]:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please click to select an item from the Quarantine list first.")
            return None
        values = self.tree.item(selected[0]).get("values", [])
        return str(values[0]) if values else None

    def _on_restore_original(self) -> None:
        qid = self._get_selected_id()
        if not qid:
            return

        rec = self.engine.quarantine_mgr.get_record(qid)
        fname = rec["file_name"] if rec else qid
        orig_path = rec["original_path"] if rec else "original location"

        confirm = messagebox.askyesno(
            "Confirm File Restoration",
            f"Are you sure you want to restore this file back to its original location?\n\n"
            f"File: {fname}\n"
            f"Destination: {orig_path}\n\n"
            "The file will be decrypted and returned to normal access.",
        )
        if not confirm:
            return

        ok, msg = self.engine.restore_threat(qid)
        if ok:
            messagebox.showinfo("Restoration Successful", f"File restored successfully:\n{msg}")
            self.refresh_data()
        else:
            messagebox.showerror("Restoration Failed", f"Could not restore file:\n{msg}")

    def _on_restore_custom(self) -> None:
        qid = self._get_selected_id()
        if not qid:
            return

        rec = self.engine.quarantine_mgr.get_record(qid)
        if not rec:
            messagebox.showerror("Error", "Quarantine record not found.")
            return

        target_dir = filedialog.askdirectory(title="Select Safe Destination Folder for Restored File")
        if not target_dir:
            return

        dest_file = Path(target_dir) / rec["file_name"]
        confirm = messagebox.askyesno(
            "Confirm Custom Destination",
            f"Restore file to this location?\n\nDestination: {dest_file}",
        )
        if not confirm:
            return

        ok, msg = self.engine.restore_threat(qid, custom_target=dest_file)
        if ok:
            messagebox.showinfo("Restoration Successful", f"File restored successfully to:\n{dest_file}")
            self.refresh_data()
        else:
            messagebox.showerror("Restoration Failed", f"Could not restore file:\n{msg}")

    def _on_purge(self) -> None:
        qid = self._get_selected_id()
        if not qid:
            return

        rec = self.engine.quarantine_mgr.get_record(qid)
        fname = rec["file_name"] if rec else qid

        confirm = messagebox.askyesno(
            "Permanent Deletion Warning",
            f"⚠️ PERMANENT DELETION WARNING\n\n"
            f"Are you sure you want to permanently delete:\n{fname} ({qid})?\n\n"
            "This will completely erase the file from your computer.\n"
            "This action CANNOT be undone.",
        )
        if not confirm:
            return

        ok, msg = self.engine.purge_quarantined_threat(qid)
        if ok:
            messagebox.showinfo("File Purged", "The file has been permanently deleted from your computer.")
            self.refresh_data()
        else:
            messagebox.showerror("Error", f"Failed deleting file: {msg}")
