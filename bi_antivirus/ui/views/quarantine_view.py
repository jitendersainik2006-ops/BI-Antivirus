"""
BI Antivirus - Quarantine Vault View
Reversibly inspects, restores, or permanently purges isolated threats on D: drive.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from typing import Dict, Any, Optional

from bi_antivirus.config import THEME


class QuarantineView(tk.Frame):
    """Quarantine vault management interface supporting 100% reversible restoration."""

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
            text="QUARANTINE VAULT",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 14, "bold"),
            anchor="w",
        )
        title_lbl.pack(fill="x")

        desc_lbl = tk.Label(
            header_frame,
            text="Suspicious files are safely ciphered and neutralized in D:\\BI-Antivirus\\quarantine\\vault. Files can be reversibly restored at any time.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 10),
            anchor="w",
        )
        desc_lbl.pack(fill="x", pady=(2, 0))

        # Vault Data Table
        table_container = tk.Frame(self, bg=THEME["bg_input"])
        table_container.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        columns = ("id", "filename", "threat_name", "severity", "date", "original_path")
        self.tree = ttk.Treeview(table_container, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("id", text="QUARANTINE ID")
        self.tree.heading("filename", text="FILE NAME")
        self.tree.heading("threat_name", text="THREAT NAME")
        self.tree.heading("severity", text="SEVERITY")
        self.tree.heading("date", text="DATE QUARANTINED")
        self.tree.heading("original_path", text="ORIGINAL LOCATION")

        self.tree.column("id", width=180)
        self.tree.column("filename", width=140)
        self.tree.column("threat_name", width=180)
        self.tree.column("severity", width=85, anchor="center")
        self.tree.column("date", width=140)
        self.tree.column("original_path", width=250)

        scrollbar = ttk.Scrollbar(table_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Action Button Toolbar
        toolbar = tk.Frame(self, bg=THEME["bg_darkest"])
        toolbar.pack(fill="x", padx=20, pady=(0, 20))

        self.btn_restore = ttk.Button(
            toolbar,
            text="Restore to Original",
            style="Primary.TButton",
            command=self._on_restore_original,
        )
        self.btn_restore.pack(side="left", padx=(0, 10))

        self.btn_restore_to = ttk.Button(
            toolbar,
            text="Restore to Folder...",
            style="Secondary.TButton",
            command=self._on_restore_custom,
        )
        self.btn_restore_to.pack(side="left", padx=(0, 10))

        self.btn_purge = ttk.Button(
            toolbar,
            text="Safely Purge Item",
            style="Danger.TButton",
            command=self._on_purge,
        )
        self.btn_purge.pack(side="left", padx=(0, 10))

        self.btn_verify = ttk.Button(
            toolbar,
            text="Verify Vault Integrity",
            style="Secondary.TButton",
            command=self._on_verify_integrity,
        )
        self.btn_verify.pack(side="left", padx=(0, 10))

        self.btn_refresh = ttk.Button(
            toolbar,
            text="Refresh Vault",
            style="Secondary.TButton",
            command=self.refresh_data,
        )
        self.btn_refresh.pack(side="right")

    def _on_verify_integrity(self) -> None:
        """Execute physical vault integrity audit against disk files."""
        res = self.engine.quarantine_mgr.verify_vault_integrity()
        status_msg = (
            f"Quarantine Vault Physical Audit Results:\n\n"
            f"• Total Active Records: {res['total_records']}\n"
            f"• Verified Intact on Disk: {res['intact_records']}\n"
            f"• Missing Vault Files: {res['missing_records']}\n"
            f"• Corrupt / Invalid Files: {res['corrupt_records']}\n\n"
            f"Vault Status: {'HEALTHY - All records verified' if res['all_healthy'] else 'WARNING - Issues detected'}"
        )
        if res.get("issues"):
            status_msg += "\n\nIssues Identified:\n" + "\n".join(res["issues"][:5])

        if res["all_healthy"]:
            messagebox.showinfo("Quarantine Vault Integrity", status_msg)
        else:
            messagebox.showwarning("Quarantine Vault Warning", status_msg)

    def refresh_data(self) -> None:
        """Query quarantine records and repopulate table."""
        self.tree.delete(*self.tree.get_children())
        records = self.engine.quarantine_mgr.list_quarantine(status="QUARANTINED")
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
            messagebox.showinfo("Vault Selection", "Please select a quarantined item from the list.")
            return None
        values = self.tree.item(selected[0]).get("values", [])
        return str(values[0]) if values else None

    def _on_restore_original(self) -> None:
        qid = self._get_selected_id()
        if not qid:
            return

        confirm = messagebox.askyesno(
            "Restore File",
            f"Are you sure you want to restore {qid} back to its original location?",
        )
        if not confirm:
            return

        ok, msg = self.engine.restore_threat(qid)
        if ok:
            messagebox.showinfo("Restore Success", f"File restored successfully: {msg}")
            self.refresh_data()
        else:
            messagebox.showerror("Restore Failed", f"Failed restoring file: {msg}")

    def _on_restore_custom(self) -> None:
        qid = self._get_selected_id()
        if not qid:
            return

        target_dir = filedialog.askdirectory(title="Select Destination Folder for Restored File")
        if not target_dir:
            return

        rec = self.engine.quarantine_mgr.get_record(qid)
        if not rec:
            messagebox.showerror("Error", "Record not found.")
            return

        dest_file = Path(target_dir) / rec["file_name"]
        ok, msg = self.engine.restore_threat(qid, custom_target=dest_file)
        if ok:
            messagebox.showinfo("Restore Success", f"File restored to:\n{dest_file}")
            self.refresh_data()
        else:
            messagebox.showerror("Restore Failed", f"Failed restoring file: {msg}")

    def _on_purge(self) -> None:
        qid = self._get_selected_id()
        if not qid:
            return

        confirm = messagebox.askyesno(
            "Purge Item",
            f"Are you sure you want to permanently delete {qid} from disk?\nThis action cannot be undone.",
        )
        if not confirm:
            return

        ok, msg = self.engine.purge_quarantined_threat(qid)
        if ok:
            messagebox.showinfo("Purged", "Item permanently purged from quarantine vault.")
            self.refresh_data()
        else:
            messagebox.showerror("Error", f"Failed purging item: {msg}")
