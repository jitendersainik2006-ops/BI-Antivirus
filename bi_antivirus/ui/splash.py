"""
BI Antivirus Enterprise - Executive Splash Screen
Displays the official Black Intel Eagle Emblem, gold typography,
and initialization status during application startup.
"""

import os
import tkinter as tk
from tkinter import ttk
from typing import Optional, Callable
from bi_antivirus.config import APP_NAME, APP_SUBTITLE, APP_VERSION, THEME


class SplashScreen(tk.Toplevel):
    """Executive frameless splash screen displayed during engine initialization."""

    def __init__(self, parent: tk.Tk, on_complete: Optional[Callable[[], None]] = None, duration_ms: int = 1400):
        super().__init__(parent)
        self.parent = parent
        self.on_complete = on_complete
        self.duration_ms = duration_ms

        self.overrideredirect(True)
        self.configure(bg=THEME["bg_darkest"])
        self.attributes("-topmost", True)

        width = 460
        height = 340
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - width) // 2
        y = (sh - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")

        self._build_ui()
        self._start_animation()

    def _build_ui(self) -> None:
        # Outer Gold Border
        outer_frame = tk.Frame(
            self,
            bg=THEME["bg_darkest"],
            highlightbackground=THEME["accent_primary"],
            highlightthickness=2,
            padx=20,
            pady=20,
        )
        outer_frame.pack(fill="both", expand=True)

        # 1. Emblem Image
        resources_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "resources")
        emblem_path = os.path.join(resources_dir, "black_intel_emblem_128.png")

        self._emblem_photo = None
        if os.path.exists(emblem_path):
            try:
                self._emblem_photo = tk.PhotoImage(file=emblem_path)
                emblem_lbl = tk.Label(
                    outer_frame,
                    image=self._emblem_photo,
                    bg=THEME["bg_darkest"]
                )
                emblem_lbl.pack(pady=(4, 10))
            except Exception:
                self._fallback_emblem(outer_frame)
        else:
            self._fallback_emblem(outer_frame)

        # 2. Titles
        title_lbl = tk.Label(
            outer_frame,
            text=f"{APP_NAME} ENTERPRISE",
            bg=THEME["bg_darkest"],
            fg=THEME["accent_primary"],
            font=(THEME["font_family"], 14, "bold"),
        )
        title_lbl.pack(pady=(0, 2))

        sub_lbl = tk.Label(
            outer_frame,
            text="BLACK INTEL CYBER DEFENSE PLATFORM",
            bg=THEME["bg_darkest"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 8, "bold"),
        )
        sub_lbl.pack(pady=(0, 14))

        # 3. Progress Bar
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Splash.Horizontal.TProgressbar",
            troughcolor=THEME["bg_card"],
            background=THEME["accent_primary"],
            bordercolor=THEME["border"],
            lightcolor=THEME["accent_primary"],
            darkcolor=THEME["accent_hover"],
            thickness=6,
        )

        self.progress = ttk.Progressbar(
            outer_frame,
            style="Splash.Horizontal.TProgressbar",
            mode="determinate",
            length=360,
        )
        self.progress.pack(pady=(0, 10))

        # 4. Status Text
        self.status_lbl = tk.Label(
            outer_frame,
            text="Initializing Sovereign Defense Engine...",
            bg=THEME["bg_darkest"],
            fg=THEME["text_muted"],
            font=(THEME["font_family"], 9),
        )
        self.status_lbl.pack()

        # 5. Version Tag
        ver_lbl = tk.Label(
            outer_frame,
            text=f"v{APP_VERSION} (Build 2026.11) &bull; 100% Offline Sovereign Security",
            bg=THEME["bg_darkest"],
            fg=THEME["border"],
            font=(THEME["font_family"], 7),
        )
        ver_lbl.pack(side="bottom", pady=(6, 0))

    def _fallback_emblem(self, parent: tk.Widget) -> None:
        lbl = tk.Label(
            parent,
            text="🛡️",
            bg=THEME["bg_darkest"],
            fg=THEME["accent_primary"],
            font=(THEME["font_family"], 44),
        )
        lbl.pack(pady=(4, 10))

    def _start_animation(self) -> None:
        self.stages = [
            (25, "Verifying Authenticode & Integrity...", 250),
            (55, "Loading SQLite Threat Catalog...", 550),
            (85, "Initializing Encrypted Vault & Sentinel...", 950),
            (100, "Protection Active &bull; Launching Dashboard", 1300),
        ]
        for pct, text, delay in self.stages:
            self.after(delay, lambda p=pct, t=text: self._update_status(p, t))

        self.after(self.duration_ms, self._finish)

    def _update_status(self, pct: int, text: str) -> None:
        try:
            self.progress["value"] = pct
            self.status_lbl.config(text=text)
        except Exception:
            pass

    def _finish(self) -> None:
        try:
            self.destroy()
        except Exception:
            pass
        if self.on_complete:
            self.on_complete()
