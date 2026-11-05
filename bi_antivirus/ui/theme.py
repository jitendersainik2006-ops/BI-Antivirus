"""
BI Antivirus - UI Theme and Style Definitions
Implements Bitdefender-inspired modern cyber dark palette and ttk widget styling.
"""

import tkinter as tk
from tkinter import ttk
from bi_antivirus.config import THEME

def apply_theme(root: tk.Tk) -> ttk.Style:
    """Configure modern dark ttk style for the application."""
    root.configure(bg=THEME["bg_darkest"])
    style = ttk.Style(root)
    style.theme_use("clam")

    # Frame backgrounds
    style.configure("TFrame", background=THEME["bg_darkest"])
    style.configure("Dark.TFrame", background=THEME["bg_dark"])
    style.configure("Card.TFrame", background=THEME["bg_panel"], relief="flat")

    # Label styling
    style.configure(
        "TLabel",
        background=THEME["bg_darkest"],
        foreground=THEME["text_primary"],
        font=(THEME["font_family"], 10),
    )
    style.configure(
        "Card.TLabel",
        background=THEME["bg_panel"],
        foreground=THEME["text_primary"],
        font=(THEME["font_family"], 10),
    )
    style.configure(
        "Title.TLabel",
        background=THEME["bg_darkest"],
        foreground=THEME["text_primary"],
        font=(THEME["font_family"], 16, "bold"),
    )
    style.configure(
        "Subtitle.TLabel",
        background=THEME["bg_darkest"],
        foreground=THEME["text_secondary"],
        font=(THEME["font_family"], 10),
    )
    style.configure(
        "CardTitle.TLabel",
        background=THEME["bg_panel"],
        foreground=THEME["text_secondary"],
        font=(THEME["font_family"], 9, "bold"),
    )
    style.configure(
        "CardValue.TLabel",
        background=THEME["bg_panel"],
        foreground=THEME["text_primary"],
        font=(THEME["font_family"], 18, "bold"),
    )

    # Modern Dark Buttons
    style.configure(
        "Primary.TButton",
        background=THEME["accent_primary"],
        foreground="#000000",
        font=(THEME["font_family"], 10, "bold"),
        padding=(16, 8),
        borderwidth=0,
    )
    style.map(
        "Primary.TButton",
        background=[("active", THEME["accent_hover"]), ("pressed", THEME["accent_primary"])],
    )

    style.configure(
        "Secondary.TButton",
        background=THEME["bg_panel_hover"],
        foreground=THEME["text_primary"],
        font=(THEME["font_family"], 9, "bold"),
        padding=(12, 6),
        borderwidth=0,
    )
    style.map(
        "Secondary.TButton",
        background=[("active", THEME["border_highlight"])],
    )

    style.configure(
        "Danger.TButton",
        background=THEME["status_threat"],
        foreground="#ffffff",
        font=(THEME["font_family"], 9, "bold"),
        padding=(12, 6),
        borderwidth=0,
    )
    style.map(
        "Danger.TButton",
        background=[("active", "#ff5c7a")],
    )

    # Sidebar Nav Buttons
    style.configure(
        "Nav.TButton",
        background=THEME["bg_dark"],
        foreground=THEME["text_secondary"],
        font=(THEME["font_family"], 10),
        anchor="w",
        padding=(16, 10),
        borderwidth=0,
    )
    style.map(
        "Nav.TButton",
        background=[("active", THEME["bg_panel_hover"]), ("selected", THEME["bg_panel"])],
        foreground=[("active", THEME["text_primary"]), ("selected", THEME["accent_primary"])],
    )

    style.configure(
        "NavActive.TButton",
        background=THEME["bg_panel"],
        foreground=THEME["accent_primary"],
        font=(THEME["font_family"], 10, "bold"),
        anchor="w",
        padding=(16, 10),
        borderwidth=0,
    )

    # Progressbar
    style.configure(
        "Cyber.Horizontal.TProgressbar",
        background=THEME["accent_primary"],
        troughcolor=THEME["bg_input"],
        bordercolor=THEME["border"],
        lightcolor=THEME["accent_primary"],
        darkcolor=THEME["accent_primary"],
        thickness=12,
    )

    # Treeview (Data Tables)
    style.configure(
        "Treeview",
        background=THEME["bg_input"],
        foreground=THEME["text_primary"],
        fieldbackground=THEME["bg_input"],
        font=(THEME["font_family"], 9),
        rowheight=28,
        borderwidth=0,
    )
    style.map(
        "Treeview",
        background=[("selected", THEME["border_highlight"])],
        foreground=[("selected", THEME["text_primary"])],
    )
    style.configure(
        "Treeview.Heading",
        background=THEME["bg_panel"],
        foreground=THEME["text_secondary"],
        font=(THEME["font_family"], 9, "bold"),
        padding=(8, 6),
        borderwidth=0,
    )

    return style
