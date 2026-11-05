"""
BI Antivirus - Custom Dark Cyber UI Widgets
Modern Canvas-rendered status shields, metric stat cards, and action panels.
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional, Callable
from bi_antivirus.config import THEME


class StatusShield(tk.Canvas):
    """Draws high-tech cybersecurity status shield with glowing perimeter."""

    def __init__(self, parent, size: int = 120, status: str = "PROTECTED", **kwargs):
        super().__init__(
            parent,
            width=size,
            height=size,
            bg=THEME["bg_panel"],
            highlightthickness=0,
            **kwargs,
        )
        self.size = size
        self.status = status
        self.draw_shield()

    def set_status(self, status: str) -> None:
        self.status = status
        self.draw_shield()

    def draw_shield(self) -> None:
        self.delete("all")
        s = self.size
        cx, cy = s / 2, s / 2

        if self.status == "PROTECTED":
            accent = THEME["status_safe"]
            icon = "✓"
            glow = "#073826"
        elif self.status == "THREAT_DETECTED":
            accent = THEME["status_threat"]
            icon = "!"
            glow = "#400f19"
        elif self.status == "SCANNING":
            accent = THEME["status_warning"]
            icon = "⟳"
            glow = "#3b2a09"
        else:
            accent = THEME["status_info"]
            icon = "ℹ"
            glow = "#0c2838"

        # Outer glow circle
        r_glow = s * 0.46
        self.create_oval(cx - r_glow, cy - r_glow, cx + r_glow, cy + r_glow, fill=glow, outline="")

        # Shield Polygon points
        w = s * 0.36
        h = s * 0.42
        points = [
            cx, cy - h,             # top center
            cx + w, cy - h * 0.5,    # top right
            cx + w * 0.85, cy + h * 0.4, # mid right
            cx, cy + h,             # bottom tip
            cx - w * 0.85, cy + h * 0.4, # mid left
            cx - w, cy - h * 0.5,    # top left
        ]

        # Inner shield
        self.create_polygon(points, fill=THEME["bg_darkest"], outline=accent, width=3, smooth=True)

        # Center Icon
        font_size = int(s * 0.28)
        self.create_text(
            cx, cy,
            text=icon,
            fill=accent,
            font=(THEME["font_family"], font_size, "bold")
        )


class StatCard(tk.Frame):
    """Modern dark dashboard metric card."""

    def __init__(self, parent, title: str, value: str, subtext: str = "", accent: str = None, **kwargs):
        super().__init__(parent, bg=THEME["bg_panel"], padx=14, pady=12, **kwargs)
        self.accent_color = accent or THEME["accent_primary"]

        # Accent top border indicator
        top_bar = tk.Frame(self, bg=self.accent_color, height=3)
        top_bar.pack(fill="x", side="top", pady=(0, 6))

        self.title_lbl = tk.Label(
            self,
            text=title.upper(),
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 8, "bold"),
            anchor="w",
        )
        self.title_lbl.pack(fill="x")

        self.value_lbl = tk.Label(
            self,
            text=value,
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 16, "bold"),
            anchor="w",
        )
        self.value_lbl.pack(fill="x", pady=(2, 2))

        self.sub_lbl = tk.Label(
            self,
            text=subtext,
            bg=THEME["bg_panel"],
            fg=THEME["text_muted"],
            font=(THEME["font_family"], 8),
            anchor="w",
        )
        self.sub_lbl.pack(fill="x")

    def update_value(self, value: str, subtext: Optional[str] = None) -> None:
        self.value_lbl.config(text=value)
        if subtext is not None:
            self.sub_lbl.config(text=subtext)


class ActionCard(tk.Frame):
    """Interactive card for launching Quick Scan, Full Scan, or Custom Scan."""

    def __init__(
        self,
        parent,
        title: str,
        description: str,
        button_text: str,
        on_click: Callable[[], None],
        accent: str = None,
        **kwargs,
    ):
        super().__init__(parent, bg=THEME["bg_panel"], padx=16, pady=16, **kwargs)
        accent_color = accent or THEME["accent_primary"]

        # Border outline effect
        self.configure(highlightbackground=THEME["border"], highlightthickness=1)

        title_lbl = tk.Label(
            self,
            text=title,
            bg=THEME["bg_panel"],
            fg=THEME["text_primary"],
            font=(THEME["font_family"], 11, "bold"),
            anchor="w",
        )
        title_lbl.pack(fill="x")

        desc_lbl = tk.Label(
            self,
            text=description,
            bg=THEME["bg_panel"],
            fg=THEME["text_secondary"],
            font=(THEME["font_family"], 9),
            anchor="w",
            wraplength=200,
            justify="left",
        )
        desc_lbl.pack(fill="x", pady=(4, 12))

        btn = ttk.Button(self, text=button_text, style="Primary.TButton", command=on_click)
        btn.pack(fill="x", side="bottom")
