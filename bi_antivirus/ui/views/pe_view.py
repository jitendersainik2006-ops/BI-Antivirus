"""
BI Antivirus - PE Static Security Inspector View
Interactive visual control center for:
1. Portable Executable (PE32/PE32+) static binary parsing
2. Section header analysis and Shannon entropy calculations
3. RWX executable section detection and mitigation checks (DEP, ASLR, CFG)
4. Suspicious API import profiling and explainable heuristic scoring.
"""

import os
import json
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, Any, List, Optional
from pathlib import Path

from bi_antivirus.config import THEME, REPORTS_DIR


class PEClassifierView(tk.Frame):
    """PE Static Feature Extraction and Heuristic Security Analysis visual interface."""

    def __init__(self, parent, engine, **kwargs):
        super().__init__(parent, bg=THEME["bg_darkest"], **kwargs)
        self.engine = engine
        self._current_report: Dict[str, Any] = {}
        self._build_ui()

    def _build_ui(self) -> None:
        # 1. Header Panel
        header_frame = tk.Frame(self, bg=THEME["bg_panel"], padx=20, pady=14)
        header_frame.pack(fill="x", padx=16, pady=(16, 10))
        header_frame.configure(highlightbackground=THEME["border"], highlightthickness=1)

        title_lbl = tk.Label(
            header_frame,
            text="PE STATIC SECURITY INSPECTOR",
            bg=THEME["bg_panel"],
            fg=THEME["accent_primary"],
            font=(THEME["font_family"], 13, "bold"),
            anchor="w",
        )
        title_lbl.pack(fill="x")

        desc_lbl = tk.Label(
            header_frame,
            text="Explainable static feature analysis, Shannon entropy calculation, RWX memory permissions, and compiler mitigation auditing for Windows binaries.",
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            anchor="w",
        )
        desc_lbl.pack(fill="x", pady=(2, 0))

        # 2. File Selection Bar
        file_bar = tk.Frame(self, bg=THEME["bg_panel"], padx=14, pady=10)
        file_bar.pack(fill="x", padx=16, pady=(0, 10))
        file_bar.configure(highlightbackground=THEME["border"], highlightthickness=1)

        lbl_select = tk.Label(
            file_bar,
            text="Target Binary:",
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 9, "bold"),
        )
        lbl_select.pack(side="left", padx=(0, 8))

        self.ent_path = ttk.Entry(file_bar, font=(THEME["font_mono"], 9))
        self.ent_path.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.ent_path.insert(0, r"C:\Windows\explorer.exe")

        btn_browse = ttk.Button(
            file_bar,
            text="Browse...",
            style="Outline.TButton",
            command=self._browse_file,
        )
        btn_browse.pack(side="left", padx=(0, 8))

        btn_inspect = ttk.Button(
            file_bar,
            text="🔬 Inspect Binary Now",
            style="Accent.TButton",
            command=self._run_inspection,
        )
        btn_inspect.pack(side="left", padx=(0, 8))

        btn_export = ttk.Button(
            file_bar,
            text="📄 Export Report",
            style="Outline.TButton",
            command=self._export_report,
        )
        btn_export.pack(side="left")

        # 3. Stat & Verdict Cards
        stats_frame = tk.Frame(self, bg=THEME["bg_darkest"])
        stats_frame.pack(fill="x", padx=16, pady=(0, 10))

        self.card_verdict = self._create_stat_card(stats_frame, "VERDICT", "STANDBY", THEME["text_muted"])
        self.card_verdict.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.card_score = self._create_stat_card(stats_frame, "SUSPICION SCORE", "0 / 100", THEME["accent_primary"])
        self.card_score.pack(side="left", fill="x", expand=True, padx=6)

        self.card_arch = self._create_stat_card(stats_frame, "PE ARCHITECTURE", "N/A", THEME["text_secondary"])
        self.card_arch.pack(side="left", fill="x", expand=True, padx=6)

        self.card_sections = self._create_stat_card(stats_frame, "SECTIONS AUDITED", "0", THEME["accent_secondary"])
        self.card_sections.pack(side="left", fill="x", expand=True, padx=(6, 0))

        # 4. Notebook Tabs: Sections, Suspicious Imports, Mitigations & Reasons
        style = ttk.Style()
        style.configure("PE.TNotebook", background=THEME["bg_darkest"])
        style.configure("PE.TNotebook.Tab", padding=[16, 6], font=(THEME["font_family"], 9, "bold"))

        self.notebook = ttk.Notebook(self, style="PE.TNotebook")
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        # Tab A: Sections & Entropy
        self.tab_sections = tk.Frame(self.notebook, bg=THEME["bg_darkest"])
        self.notebook.add(self.tab_sections, text="  📊 Sections & Entropy  ")
        self._build_sections_tab(self.tab_sections)

        # Tab B: Suspicious Imports & APIs
        self.tab_imports = tk.Frame(self.notebook, bg=THEME["bg_darkest"])
        self.notebook.add(self.tab_imports, text="  💉 Suspicious APIs & IAT  ")
        self._build_imports_tab(self.tab_imports)

        # Tab C: Mitigations & Explainable Scoring
        self.tab_reasons = tk.Frame(self.notebook, bg=THEME["bg_darkest"])
        self.notebook.add(self.tab_reasons, text="  🛡️ Mitigations & Heuristics  ")
        self._build_reasons_tab(self.tab_reasons)

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
            font=(THEME["font_family"], 14, "bold"),
            anchor="w",
        )
        v_lbl.pack(fill="x", pady=(2, 0))
        card.value_label = v_lbl
        return card

    def _build_sections_tab(self, parent: tk.Frame) -> None:
        table_container = tk.Frame(parent, bg=THEME["bg_input"])
        table_container.pack(fill="both", expand=True, padx=4, pady=6)

        cols = ("name", "virt_size", "virt_addr", "raw_size", "entropy", "executable", "writable", "rwx")
        self.tree_sections = ttk.Treeview(table_container, columns=cols, show="headings", selectmode="browse")
        self.tree_sections.heading("name", text="Section")
        self.tree_sections.heading("virt_size", text="Virtual Size")
        self.tree_sections.heading("virt_addr", text="RVA")
        self.tree_sections.heading("raw_size", text="Raw Size")
        self.tree_sections.heading("entropy", text="Entropy (bits)")
        self.tree_sections.heading("executable", text="Executable")
        self.tree_sections.heading("writable", text="Writable")
        self.tree_sections.heading("rwx", text="RWX Dangerous")

        self.tree_sections.column("name", width=100, anchor="w")
        self.tree_sections.column("virt_size", width=110, anchor="center")
        self.tree_sections.column("virt_addr", width=110, anchor="center")
        self.tree_sections.column("raw_size", width=110, anchor="center")
        self.tree_sections.column("entropy", width=120, anchor="center")
        self.tree_sections.column("executable", width=90, anchor="center")
        self.tree_sections.column("writable", width=90, anchor="center")
        self.tree_sections.column("rwx", width=120, anchor="center")

        scroll_y = ttk.Scrollbar(table_container, orient="vertical", command=self.tree_sections.yview)
        self.tree_sections.configure(yscrollcommand=scroll_y.set)

        self.tree_sections.pack(side="left", fill="both", expand=True)
        scroll_y.pack(side="right", fill="y")

    def _build_imports_tab(self, parent: tk.Frame) -> None:
        pane = tk.Frame(parent, bg=THEME["bg_darkest"])
        pane.pack(fill="both", expand=True, padx=4, pady=6)

        self.txt_imports = tk.Text(
            pane,
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_mono"], 9),
            relief="flat",
        )
        scroll_y = ttk.Scrollbar(pane, orient="vertical", command=self.txt_imports.yview)
        self.txt_imports.configure(yscrollcommand=scroll_y.set)

        self.txt_imports.pack(side="left", fill="both", expand=True)
        scroll_y.pack(side="right", fill="y")
        self.txt_imports.insert("end", "Run an inspection on a PE file to view imported DLLs and flagged suspicious APIs.")
        self.txt_imports.configure(state="disabled")

    def _build_reasons_tab(self, parent: tk.Frame) -> None:
        pane = tk.Frame(parent, bg=THEME["bg_darkest"])
        pane.pack(fill="both", expand=True, padx=4, pady=6)

        self.txt_reasons = tk.Text(
            pane,
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_mono"], 9),
            relief="flat",
        )
        scroll_y = ttk.Scrollbar(pane, orient="vertical", command=self.txt_reasons.yview)
        self.txt_reasons.configure(yscrollcommand=scroll_y.set)

        self.txt_reasons.pack(side="left", fill="both", expand=True)
        scroll_y.pack(side="right", fill="y")
        self.txt_reasons.insert("end", "Run an inspection to see explainable heuristic scoring reasons and security mitigations.")
        self.txt_reasons.configure(state="disabled")

    def _browse_file(self) -> None:
        f = filedialog.askopenfilename(
            title="Select Windows PE Executable",
            filetypes=[("Executable Files", "*.exe;*.dll;*.sys;*.scr;*.ocx"), ("All Files", "*.*")],
            parent=self,
        )
        if f:
            self.ent_path.delete(0, "end")
            self.ent_path.insert(0, f)

    def _run_inspection(self) -> None:
        p = self.ent_path.get().strip()
        if not p or not Path(p).exists():
            messagebox.showwarning("File Missing", "Please select an existing PE file.", parent=self)
            return

        try:
            report = self.engine.inspect_pe_file(Path(p))
            self._current_report = report
            self._display_report(report)
        except Exception as e:
            messagebox.showerror("Inspection Failed", f"Could not analyze PE file: {e}", parent=self)

    def _display_report(self, r: Dict[str, Any]) -> None:
        verdict = r.get("verdict", "UNKNOWN")
        score = r.get("suspicion_score", 0)
        arch = r.get("architecture", "Unknown")
        sections = r.get("sections", [])

        # Update cards
        v_color = THEME["status_safe"]
        if verdict == "POTENTIALLY_MALICIOUS":
            v_color = THEME["status_critical"]
        elif verdict == "SUSPICIOUS_HEURISTIC":
            v_color = THEME["status_warning"]

        self.card_verdict.value_label.configure(text=verdict, fg=v_color)
        self.card_score.value_label.configure(text=f"{score} / 100")
        self.card_arch.value_label.configure(text=arch)
        self.card_sections.value_label.configure(text=str(len(sections)))

        # Update Sections Tree
        self.tree_sections.delete(*self.tree_sections.get_children())
        for s in sections:
            ent = f"{s.get('entropy', 0.0):.2f}"
            is_rwx = "⚠️ YES (RWX)" if s.get("is_rwx") else "No"
            self.tree_sections.insert(
                "",
                "end",
                values=(
                    s.get("name"),
                    f"0x{s.get('virtual_size', 0):X}",
                    f"0x{s.get('virtual_address', 0):X}",
                    f"0x{s.get('raw_size', 0):X}",
                    ent,
                    str(s.get("is_executable")),
                    str(s.get("is_writable")),
                    is_rwx,
                ),
            )

        # Update Imports
        lines_imp = [
            f"=== IMPORTED LIBRARIES & SUSPICIOUS APIS ({len(r.get('imported_dlls', []))} DLLs) ===",
            "",
            "Flagged High-Risk Suspicious APIs:",
        ]
        susp_apis = r.get("suspicious_imports_found", [])
        if susp_apis:
            for api in susp_apis:
                lines_imp.append(f"  • {api}")
        else:
            lines_imp.append("  (No high-risk injection or evasion APIs matched)")

        lines_imp.extend(["", "Imported Dynamic Link Libraries (DLLs):"])
        for dll in r.get("imported_dlls", []):
            lines_imp.append(f"  - {dll}")

        self.txt_imports.configure(state="normal")
        self.txt_imports.delete("1.0", "end")
        self.txt_imports.insert("end", "\n".join(lines_imp))
        self.txt_imports.configure(state="disabled")

        # Update Mitigations & Reasons
        mit = r.get("mitigations", {})
        lines_rea = [
            "=== SECURITY MITIGATIONS & BINARY HARDENING ===",
            f"  • Data Execution Prevention (DEP / NX): {'ENABLED' if mit.get('dep_nx_enabled') else 'DISABLED'}",
            f"  • ASLR Enabled: {'ENABLED' if mit.get('aslr_enabled') else 'DISABLED'}",
            f"  • High Entropy VA (64-bit ASLR): {'ENABLED' if mit.get('high_entropy_va') else 'DISABLED'}",
            f"  • Control Flow Guard (CFG): {'ENABLED' if mit.get('cfg_enabled') else 'DISABLED'}",
            f"  • Structured Exception Handling (SEH): {'ENABLED' if mit.get('seh_enabled') else 'NO SEH'}",
            f"  • Authenticode Certificate Present: {'YES' if r.get('has_authenticode') else 'NO'}",
            f"  • Non-Zero Overlay Present: {'YES' if r.get('has_overlay') else 'NO'}",
            f"  • TLS Callbacks Present: {'YES' if r.get('has_tls') else 'NO'}",
            "",
            "=== EXPLAINABLE HEURISTIC SCORING REASONS ===",
        ]
        reasons = r.get("reasons", [])
        if reasons:
            for rea in reasons:
                lines_rea.append(f"  [+] {rea}")
        else:
            lines_rea.append("  (Standard benign binary profile with zero suspicious indicators)")

        self.txt_reasons.configure(state="normal")
        self.txt_reasons.delete("1.0", "end")
        self.txt_reasons.insert("end", "\n".join(lines_rea))
        self.txt_reasons.configure(state="disabled")

    def _export_report(self) -> None:
        """Export PE static inspection report to Markdown."""
        if not self._current_report:
            messagebox.showwarning("No Data", "Inspect a binary first before exporting.", parent=self)
            return

        r = self._current_report
        out_path = REPORTS_DIR / f"pe_analysis_{int(time.time())}.md"
        try:
            lines = [
                f"# BI Antivirus — Portable Executable Static Forensic Report",
                f"**Target Binary:** `{r.get('file_path')}`  ",
                f"**SHA-256 Hash:** `{r.get('sha256')}`  ",
                f"**Architecture:** `{r.get('architecture')}`  ",
                f"**Verdict:** `{r.get('verdict')}`  ",
                f"**Suspicion Score:** `{r.get('suspicion_score')} / 100`  ",
                f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}  ",
                "",
                "---",
                "",
                "## 1. Section Table & Entropy Profile",
                "| Section | Virtual Address | Virtual Size | Raw Size | Entropy (bits) | RWX Dangerous |",
                "|---|---|---|---|---|---|",
            ]
            for s in r.get("sections", []):
                lines.append(
                    f"| `{s.get('name')}` | `0x{s.get('virtual_address', 0):X}` | `0x{s.get('virtual_size', 0):X}` | `0x{s.get('raw_size', 0):X}` | `{s.get('entropy', 0.0):.2f}` | `{'YES (RWX)' if s.get('is_rwx') else 'No'}` |"
                )

            lines.extend([
                "",
                "---",
                "",
                "## 2. Binary Mitigations",
                f"- **DEP / NX:** `{'Enabled' if r.get('mitigations', {}).get('dep_nx_enabled') else 'Disabled'}`",
                f"- **ASLR:** `{'Enabled' if r.get('mitigations', {}).get('aslr_enabled') else 'Disabled'}`",
                f"- **Control Flow Guard (CFG):** `{'Enabled' if r.get('mitigations', {}).get('cfg_enabled') else 'Disabled'}`",
                f"- **Authenticode Certificate:** `{'Present' if r.get('has_authenticode') else 'None'}`",
                "",
                "---",
                "",
                "## 3. Explainable Scoring Reasons",
            ])
            for rea in r.get("reasons", []):
                lines.append(f"- {rea}")

            lines.extend([
                "",
                "---",
                f"*Report generated by BI Antivirus PE Static Security Inspector — Storage: D:\\bit defender*",
            ])

            out_path.write_text("\n".join(lines), encoding="utf-8")
            messagebox.showinfo("Export Successful", f"Forensic PE report exported to:\n{out_path}", parent=self)
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not export report: {e}", parent=self)
