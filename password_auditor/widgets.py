"""Custom Tkinter widgets: flat buttons, a switch, pills, a score meter.

Tkinter's stock widgets cannot be styled into a modern flat look on Windows
(the checkbutton indicator and ttk entry borders in particular), so the few
controls that matter are drawn here instead.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable

from password_auditor import theme as t


class FlatButton(tk.Frame):
    """A borderless button with hover and disabled states."""

    def __init__(
        self,
        master: tk.Misc,
        text: str,
        command: Callable[[], None],
        *,
        kind: str = "primary",
        padx: int = 18,
        pady: int = 8,
    ) -> None:
        self._palette = {
            "primary": (t.ACCENT, t.ACCENT_HOVER, t.ACCENT_TEXT),
            "ghost": (t.SURFACE_2, t.SURFACE_3, t.TEXT),
        }[kind]
        base, _hover, fg = self._palette
        super().__init__(master, bg=base, cursor="hand2", highlightthickness=0)

        self._command = command
        self._enabled = True
        self._text = text
        self.label = tk.Label(
            self, text=text, bg=base, fg=fg, font=t.FONT_BUTTON, padx=padx, pady=pady
        )
        self.label.pack()

        for widget in (self, self.label):
            widget.bind("<Button-1>", self._on_click)
            widget.bind("<Enter>", self._on_enter)
            widget.bind("<Leave>", self._on_leave)

    # -- state ---------------------------------------------------------- #

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        base, _hover, fg = self._palette
        self._paint(base, fg if enabled else t.TEXT_FAINT)
        self.configure(cursor="hand2" if enabled else "arrow")

    def set_text(self, text: str) -> None:
        self._text = text
        self.label.configure(text=text)

    # -- events --------------------------------------------------------- #

    def _on_click(self, _event: tk.Event) -> None:
        if self._enabled:
            self._command()

    def _on_enter(self, _event: tk.Event) -> None:
        if self._enabled:
            base, hover, fg = self._palette
            self._paint(hover, fg)

    def _on_leave(self, _event: tk.Event) -> None:
        base, _hover, fg = self._palette
        self._paint(base, fg if self._enabled else t.TEXT_FAINT)

    def _paint(self, bg: str, fg: str) -> None:
        self.configure(bg=bg)
        self.label.configure(bg=bg, fg=fg)


class Switch(tk.Frame):
    """A pill-shaped on/off switch with a caption, drawn on a canvas."""

    WIDTH = 38
    HEIGHT = 20

    def __init__(
        self,
        master: tk.Misc,
        text: str,
        *,
        value: bool = True,
        command: Callable[[bool], None] | None = None,
        bg: str = t.SURFACE,
    ) -> None:
        super().__init__(master, bg=bg, cursor="hand2")
        self._value = value
        self._command = command

        self.canvas = tk.Canvas(
            self,
            width=self.WIDTH,
            height=self.HEIGHT,
            bg=bg,
            highlightthickness=0,
            bd=0,
        )
        self.canvas.pack(side="left")
        self.caption = tk.Label(
            self, text=text, bg=bg, fg=t.TEXT_MUTED, font=t.FONT_BODY, padx=8
        )
        self.caption.pack(side="left")

        for widget in (self, self.canvas, self.caption):
            widget.bind("<Button-1>", self._toggle)
        self._draw()

    def get(self) -> bool:
        return self._value

    def set(self, value: bool) -> None:
        self._value = bool(value)
        self._draw()

    def _toggle(self, _event: tk.Event) -> None:
        self._value = not self._value
        self._draw()
        if self._command is not None:
            self._command(self._value)

    def _draw(self) -> None:
        self.canvas.delete("all")
        track = t.ACCENT if self._value else t.SURFACE_3
        t.rounded_rect(
            self.canvas,
            1,
            1,
            self.WIDTH - 1,
            self.HEIGHT - 1,
            self.HEIGHT / 2,
            fill=track,
            outline="",
        )
        knob_radius = (self.HEIGHT - 8) / 2
        centre_x = self.WIDTH - knob_radius - 5 if self._value else knob_radius + 5
        centre_y = self.HEIGHT / 2
        self.canvas.create_oval(
            centre_x - knob_radius,
            centre_y - knob_radius,
            centre_x + knob_radius,
            centre_y + knob_radius,
            fill="#ffffff" if self._value else t.TEXT_MUTED,
            outline="",
        )
        self.caption.configure(fg=t.TEXT if self._value else t.TEXT_MUTED)


class Pill(tk.Canvas):
    """A small rounded badge, used for character classes and pattern tags."""

    def __init__(
        self,
        master: tk.Misc,
        text: str,
        *,
        color: str = t.TEXT_MUTED,
        fill: str = t.SURFACE_2,
        bg: str = t.SURFACE,
        font: tuple = t.FONT_SMALL,
    ) -> None:
        # Measure the text so the pill hugs it.
        probe = tk.Label(master, text=text, font=font)
        width = probe.winfo_reqwidth() + 20
        height = probe.winfo_reqheight() + 8
        probe.destroy()

        super().__init__(
            master, width=width, height=height, bg=bg, highlightthickness=0, bd=0
        )
        t.rounded_rect(self, 0, 0, width, height, height / 2, fill=fill, outline="")
        self.create_text(
            width / 2, height / 2 + 1, text=text, fill=color, font=font
        )


class ScoreMeter(tk.Canvas):
    """A rounded progress track that animates up to the score."""

    HEIGHT = 12

    def __init__(self, master: tk.Misc, *, width: int = 320, bg: str = t.SURFACE) -> None:
        super().__init__(
            master, width=width, height=self.HEIGHT, bg=bg, highlightthickness=0, bd=0
        )
        self._width = width
        self._target = 0
        self._shown = 0.0
        self._color = t.ACCENT
        self._animation: str | None = None
        self.bind("<Configure>", self._on_resize)
        self._draw()

    def set_score(self, score: int, color: str, *, animate: bool = True) -> None:
        self._target = max(0, min(100, score))
        self._color = color
        if self._animation is not None:
            self.after_cancel(self._animation)
            self._animation = None
        if animate:
            self._shown = 0.0
            self._step()
        else:
            self._shown = float(self._target)
            self._draw()

    def _step(self) -> None:
        # Ease out: close 22% of the remaining distance per frame.
        remaining = self._target - self._shown
        if abs(remaining) < 0.5:
            self._shown = float(self._target)
            self._draw()
            self._animation = None
            return
        self._shown += remaining * 0.22
        self._draw()
        self._animation = self.after(16, self._step)

    def _on_resize(self, event: tk.Event) -> None:
        self._width = max(40, event.width)
        self._draw()

    def _draw(self) -> None:
        self.delete("all")
        radius = self.HEIGHT / 2
        t.rounded_rect(
            self, 0, 0, self._width, self.HEIGHT, radius, fill=t.SURFACE_2, outline=""
        )
        filled = self._width * self._shown / 100.0
        if filled >= 2:
            t.rounded_rect(
                self,
                0,
                0,
                max(filled, self.HEIGHT),
                self.HEIGHT,
                radius,
                fill=self._color,
                outline="",
            )
        # Band boundaries at 20/40/60/80, drawn over the fill as faint notches.
        for mark in (20, 40, 60, 80):
            x = self._width * mark / 100.0
            self.create_line(x, 2, x, self.HEIGHT - 2, fill=t.BG, width=1)


class Card(tk.Frame):
    """A surface panel with a 1px border, an optional heading, and padding."""

    def __init__(self, master: tk.Misc, title: str | None = None, *, pad: int = 14):
        super().__init__(master, bg=t.BORDER, highlightthickness=0)
        self.inner = tk.Frame(self, bg=t.SURFACE)
        self.inner.pack(fill="both", expand=True, padx=1, pady=1)
        self.body = tk.Frame(self.inner, bg=t.SURFACE)
        self.body.pack(fill="both", expand=True, padx=pad, pady=pad)

        if title is not None:
            heading = tk.Label(
                self.body,
                text=title.upper(),
                bg=t.SURFACE,
                fg=t.TEXT_FAINT,
                font=(t.UI, 8, "bold"),
                anchor="w",
            )
            heading.pack(fill="x", pady=(0, 10))


class ScrollableFrame(tk.Frame):
    """A vertically scrolling container whose inner frame tracks the width."""

    def __init__(self, master: tk.Misc, *, bg: str = t.BG) -> None:
        super().__init__(master, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.scrollbar = tk.Scrollbar(
            self,
            orient="vertical",
            command=self.canvas.yview,
            width=10,
            troughcolor=bg,
            bg=t.SURFACE_2,
            activebackground=t.SURFACE_3,
            bd=0,
            relief="flat",
            highlightthickness=0,
        )
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.content = tk.Frame(self.canvas, bg=bg)
        self._window = self.canvas.create_window(
            (0, 0), window=self.content, anchor="nw"
        )

        self.content.bind("<Configure>", self._on_content_resize)
        self.canvas.bind("<Configure>", self._on_canvas_resize)
        # Wheel scrolling only while the pointer is over this widget.
        self.canvas.bind("<Enter>", self._bind_wheel)
        self.canvas.bind("<Leave>", self._unbind_wheel)

    def scroll_to_top(self) -> None:
        self.canvas.yview_moveto(0.0)

    def _on_content_resize(self, _event: tk.Event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_resize(self, event: tk.Event) -> None:
        self.canvas.itemconfigure(self._window, width=event.width)

    def _bind_wheel(self, _event: tk.Event) -> None:
        self.canvas.bind_all("<MouseWheel>", self._on_wheel)

    def _unbind_wheel(self, _event: tk.Event) -> None:
        self.canvas.unbind_all("<MouseWheel>")

    def _on_wheel(self, event: tk.Event) -> None:
        # Windows reports multiples of 120; one notch scrolls three units.
        self.canvas.yview_scroll(int(-event.delta / 120) * 3, "units")
