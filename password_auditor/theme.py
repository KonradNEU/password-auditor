"""Colours, fonts and small drawing helpers shared by the GUI widgets.

Kept separate from :mod:`password_auditor.gui` so the look of the app can be
retuned in one place without touching layout or behaviour.
"""

from __future__ import annotations

import tkinter as tk

# --------------------------------------------------------------------------- #
# Palette (dark)
# --------------------------------------------------------------------------- #

BG = "#0f1218"  # window background
SURFACE = "#171b24"  # card background
SURFACE_2 = "#1f2430"  # inset / track background
SURFACE_3 = "#262c3a"  # hover
BORDER = "#252b38"
BORDER_FOCUS = "#3d5bb8"

TEXT = "#e7eaf0"
TEXT_MUTED = "#8b93a7"
TEXT_FAINT = "#5f6779"

ACCENT = "#5b8cff"
ACCENT_HOVER = "#7aa2ff"
ACCENT_TEXT = "#0b0e14"

RED = "#ff5f5f"
RED_DIM = "#3a1c22"
AMBER = "#ffb020"
AMBER_DIM = "#3a2c12"
GREEN = "#3ad07f"
GREEN_DIM = "#13301f"

BAND_COLOR: dict[str, str] = {
    "Very Weak": RED,
    "Weak": RED,
    "Fair": AMBER,
    "Strong": GREEN,
    "Very Strong": GREEN,
}

BAND_SURFACE: dict[str, str] = {
    "Very Weak": RED_DIM,
    "Weak": RED_DIM,
    "Fair": AMBER_DIM,
    "Strong": GREEN_DIM,
    "Very Strong": GREEN_DIM,
}

# --------------------------------------------------------------------------- #
# Fonts
# --------------------------------------------------------------------------- #

UI = "Segoe UI"
MONO = "Consolas"

FONT_TITLE = (UI, 17, "bold")
FONT_SUBTITLE = (UI, 9)
FONT_H2 = (UI, 10, "bold")
FONT_BODY = (UI, 9)
FONT_SMALL = (UI, 8)
FONT_SCORE = (UI, 34, "bold")
FONT_BAND = (UI, 12, "bold")
FONT_MONO = (MONO, 9)
FONT_BUTTON = (UI, 10, "bold")


def rounded_rect(
    canvas: tk.Canvas,
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    radius: float,
    **kwargs,
) -> int:
    """Draw a rounded rectangle on ``canvas`` and return its item id.

    Tkinter has no rounded-rectangle primitive, so this uses a smoothed
    polygon: the corner points are doubled up, and ``smooth=True`` turns the
    resulting path into curves of roughly ``radius``.
    """
    radius = max(0.0, min(radius, (x2 - x1) / 2, (y2 - y1) / 2))
    points = [
        x1 + radius, y1,
        x2 - radius, y1,
        x2, y1,
        x2, y1 + radius,
        x2, y2 - radius,
        x2, y2,
        x2 - radius, y2,
        x1 + radius, y2,
        x1, y2,
        x1, y2 - radius,
        x1, y1 + radius,
        x1, y1,
    ]
    return canvas.create_polygon(points, smooth=True, **kwargs)


def enable_dark_titlebar(window: tk.Misc) -> None:
    """Ask Windows to draw a dark title bar. Silently ignored elsewhere."""
    try:
        import ctypes

        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        # DWMWA_USE_IMMERSIVE_DARK_MODE = 20 on current Windows 10/11 builds.
        value = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 20, ctypes.byref(value), ctypes.sizeof(value)
        )
    except Exception:
        pass  # not Windows, or an older build: the light title bar is fine
