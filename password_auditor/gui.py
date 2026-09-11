"""Desktop window for Password Auditor.

A front end over exactly the same code as the CLI: it calls
:func:`password_auditor.auditor.audit`, so the scoring, the k-anonymity lookup
and the privacy properties are identical. The password lives only in the entry
widget and the local variable handed to the worker thread; it is never written
to disk, never logged, and never rendered back into the report.
"""

from __future__ import annotations

import threading
import tkinter as tk

from password_auditor import theme as t
from password_auditor.auditor import AuditResult, audit
from password_auditor.crack import AttackPlan, character_bits, plan_attack
from password_auditor.report import render_text
from password_auditor.strength import GUESSES_PER_SECOND
from password_auditor.widgets import (
    Card,
    FlatButton,
    Pill,
    ScoreMeter,
    ScrollableFrame,
    Switch,
)

CLASS_ORDER = ("lowercase", "uppercase", "digits", "symbols", "other")
CLASS_LABELS = {
    "lowercase": "a-z",
    "uppercase": "A-Z",
    "digits": "0-9",
    "symbols": "!@#",
    "other": "non-ASCII",
}

EMPTY_STATE = (
    "Type a password and press Enter.\n\n"
    "Scoring happens entirely on this machine. If the breach check is on, the "
    "only thing that leaves your computer is the first five characters of the "
    "password's SHA-1 hash - never the password, never the full hash. The "
    "server replies with every leaked hash sharing those five characters, and "
    "the comparison happens locally."
)


class AuditorWindow(tk.Tk):
    """The main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Password Auditor")
        self.configure(bg=t.BG)
        self.minsize(720, 680)
        self.geometry("780x760")

        self._busy = False
        self._revealed = False
        self._last_result: AuditResult | None = None
        self._wrap_targets: list[tk.Label] = []
        self._replay_jobs: list[str] = []
        self._steps_host: tk.Frame | None = None

        self._build()
        t.enable_dark_titlebar(self)
        self.entry.focus_set()

    # ------------------------------------------------------------------ #
    # Layout
    # ------------------------------------------------------------------ #

    def _build(self) -> None:
        root = tk.Frame(self, bg=t.BG)
        root.pack(fill="both", expand=True, padx=18, pady=16)

        self._build_header(root)
        self._build_input(root)

        self.results = ScrollableFrame(root)
        self.results.pack(fill="both", expand=True, pady=(14, 0))
        self.results.canvas.bind("<Configure>", self._on_results_resize, add="+")
        self._show_empty_state()

    def _build_header(self, parent: tk.Frame) -> None:
        header = tk.Frame(parent, bg=t.BG)
        header.pack(fill="x")

        tk.Label(
            header,
            text="Password Auditor",
            bg=t.BG,
            fg=t.TEXT,
            font=t.FONT_TITLE,
            anchor="w",
        ).pack(fill="x")
        tk.Label(
            header,
            text="Offline strength scoring, plus a breach check that never sends your password",
            bg=t.BG,
            fg=t.TEXT_MUTED,
            font=t.FONT_SUBTITLE,
            anchor="w",
        ).pack(fill="x", pady=(2, 0))

    def _build_input(self, parent: tk.Frame) -> None:
        card = Card(parent)
        card.pack(fill="x", pady=(14, 0))
        body = card.body

        tk.Label(
            body,
            text="PASSWORD",
            bg=t.SURFACE,
            fg=t.TEXT_FAINT,
            font=(t.UI, 8, "bold"),
            anchor="w",
        ).pack(fill="x", pady=(0, 6))

        # Entry, wrapped so the border can change colour on focus.
        self.entry_border = tk.Frame(body, bg=t.BORDER)
        self.entry_border.pack(fill="x")
        entry_bg = tk.Frame(self.entry_border, bg=t.SURFACE_2)
        entry_bg.pack(fill="x", padx=1, pady=1)

        self.entry = tk.Entry(
            entry_bg,
            show="•",
            bg=t.SURFACE_2,
            fg=t.TEXT,
            font=t.FONT_MONO,
            relief="flat",
            bd=0,
            insertbackground=t.ACCENT,
            highlightthickness=0,
        )
        self.entry.pack(side="left", fill="x", expand=True, padx=12, pady=11)
        self.entry.bind("<Return>", lambda _e: self.start_audit())
        self.entry.bind("<Escape>", lambda _e: self.clear())
        self.entry.bind("<FocusIn>", lambda _e: self.entry_border.configure(bg=t.BORDER_FOCUS))
        self.entry.bind("<FocusOut>", lambda _e: self.entry_border.configure(bg=t.BORDER))

        self.reveal_button = FlatButton(
            entry_bg, "Show", self._toggle_reveal, kind="ghost", padx=12, pady=5
        )
        self.reveal_button.pack(side="right", padx=(0, 6), pady=5)

        # Controls
        controls = tk.Frame(body, bg=t.SURFACE)
        controls.pack(fill="x", pady=(12, 0))

        self.audit_button = FlatButton(controls, "Audit", self.start_audit)
        self.audit_button.pack(side="left")
        FlatButton(controls, "Clear", self.clear, kind="ghost").pack(
            side="left", padx=(8, 0)
        )
        self.breach_switch = Switch(
            controls, "Check for breaches", value=True, bg=t.SURFACE
        )
        self.breach_switch.pack(side="right")

        self.status = tk.Label(
            body,
            text="Ready.",
            bg=t.SURFACE,
            fg=t.TEXT_MUTED,
            font=t.FONT_SMALL,
            anchor="w",
        )
        self.status.pack(fill="x", pady=(10, 0))

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #

    def _toggle_reveal(self) -> None:
        self._revealed = not self._revealed
        self.entry.configure(show="" if self._revealed else "•")
        self.reveal_button.set_text("Hide" if self._revealed else "Show")

    def clear(self) -> None:
        """Forget the password and reset the window."""
        self.entry.delete(0, "end")
        self._last_result = None
        self.status.configure(text="Ready.", fg=t.TEXT_MUTED)
        self._show_empty_state()
        self.entry.focus_set()

    def start_audit(self) -> None:
        if self._busy:
            return
        password = self.entry.get()
        if not password:
            self.status.configure(text="Enter a password first.", fg=t.AMBER)
            return

        self._busy = True
        self.audit_button.set_enabled(False)
        checking = self.breach_switch.get()
        self.status.configure(
            text="Checking against Have I Been Pwned..." if checking else "Scoring...",
            fg=t.TEXT_MUTED,
        )
        # Off the UI thread: the network call must not freeze the window.
        threading.Thread(
            target=self._worker, args=(password, checking), daemon=True
        ).start()

    def _worker(self, password: str, check_breach: bool) -> None:
        try:
            result = audit(password, check_breach=check_breach)
        except Exception as exc:  # surface unexpected failures in the window
            self.after(0, self._show_error, f"{type(exc).__name__}: {exc}")
        else:
            self.after(0, self._show_result, result)

    def copy_report(self) -> None:
        """Copy the text report to the clipboard. It contains no password."""
        if self._last_result is None:
            return
        self.clipboard_clear()
        self.clipboard_append(render_text(self._last_result, color=False))
        self.status.configure(text="Report copied to clipboard.", fg=t.GREEN)

    # ------------------------------------------------------------------ #
    # Results rendering
    # ------------------------------------------------------------------ #

    def _reset_results(self) -> tk.Frame:
        # Cancel any pending replay callbacks before their widgets vanish.
        for handle in self._replay_jobs:
            try:
                self.after_cancel(handle)
            except Exception:
                pass
        self._replay_jobs.clear()
        self._steps_host = None

        for child in self.results.content.winfo_children():
            child.destroy()
        self._wrap_targets.clear()
        self.results.scroll_to_top()
        return self.results.content

    def _show_empty_state(self) -> None:
        content = self._reset_results()
        card = Card(content, "how this works")
        card.pack(fill="x")
        self._paragraph(card.body, EMPTY_STATE, color=t.TEXT_MUTED)

    def _show_error(self, message: str) -> None:
        content = self._reset_results()
        self.status.configure(text="Something went wrong.", fg=t.RED)
        card = Card(content, "error")
        card.pack(fill="x")
        self._paragraph(card.body, message, color=t.RED, font=t.FONT_MONO)
        self._finish()

    def _show_result(self, result: AuditResult) -> None:
        self._last_result = result
        content = self._reset_results()

        self._status_from_result(result)
        self._score_card(content, result)
        self._attack_card(content, result)
        self._composition_card(content, result)
        self._breach_card(content, result)
        self._patterns_card(content, result)
        self._suggestions_card(content, result)

        footer = tk.Frame(content, bg=t.BG)
        footer.pack(fill="x", pady=(12, 4))
        FlatButton(footer, "Copy report", self.copy_report, kind="ghost").pack(
            side="right"
        )

        self._finish()
        self._on_results_resize()

    def _status_from_result(self, result: AuditResult) -> None:
        if result.breached:
            text = f"Found in breach data {result.breach.count:,} time(s)."
            color = t.RED
        elif result.breach is not None:
            text = "Not found in Pwned Passwords."
            color = t.GREEN
        elif result.breach_error:
            text = f"Breach check unavailable: {result.breach_error}"
            color = t.AMBER
        else:
            text = "Breach check skipped - scored offline only."
            color = t.TEXT_MUTED
        self.status.configure(text=text, fg=color)

    def _score_card(self, parent: tk.Frame, result: AuditResult) -> None:
        color = t.BAND_COLOR.get(result.band, t.ACCENT)
        card = Card(parent, "strength")
        card.pack(fill="x")

        row = tk.Frame(card.body, bg=t.SURFACE)
        row.pack(fill="x")

        # Big number on the left.
        number = tk.Frame(row, bg=t.SURFACE)
        number.pack(side="left", padx=(0, 18))
        tk.Label(
            number,
            text=str(result.score),
            bg=t.SURFACE,
            fg=color,
            font=t.FONT_SCORE,
        ).pack(side="left")
        tk.Label(
            number, text="/100", bg=t.SURFACE, fg=t.TEXT_FAINT, font=t.FONT_BODY
        ).pack(side="left", anchor="s", pady=(0, 8))

        # Band, meter and crack time on the right.
        detail = tk.Frame(row, bg=t.SURFACE)
        detail.pack(side="left", fill="x", expand=True)
        tk.Label(
            detail,
            text=result.band.upper(),
            bg=t.SURFACE,
            fg=color,
            font=t.FONT_BAND,
            anchor="w",
        ).pack(fill="x")

        meter = ScoreMeter(detail)
        meter.pack(fill="x", pady=(8, 8))
        meter.set_score(result.score, color)

        tk.Label(
            detail,
            text=(
                f"Cracked in {result.strength.crack_time_display} at "
                f"{GUESSES_PER_SECOND:.0e} guesses/sec offline"
            ),
            bg=t.SURFACE,
            fg=t.TEXT_MUTED,
            font=t.FONT_SMALL,
            anchor="w",
        ).pack(fill="x")

        if result.breached and result.strength.score > result.score:
            self._paragraph(
                card.body,
                f"The offline score was {result.strength.score}/100. It is capped "
                "because a password in a breach corpus is already in attackers' "
                "wordlists, whatever its entropy.",
                color=t.AMBER,
                font=t.FONT_SMALL,
                pady=(12, 0),
            )

    def _attack_card(self, parent: tk.Frame, result: AuditResult) -> None:
        """The headline feature: how this password actually falls."""
        strength = result.strength
        if not strength.length:
            return

        card = Card(parent, "how it falls  -  attack replay")
        card.pack(fill="x", pady=(12, 0))

        self._heatmap(card.body, result)

        plan = plan_attack(strength, result.breach)
        self._steps_host = tk.Frame(card.body, bg=t.SURFACE)
        self._steps_host.pack(fill="x", pady=(14, 0))

        footer = tk.Frame(card.body, bg=t.SURFACE)
        footer.pack(fill="x", pady=(10, 0))
        self._plan_headline = tk.Label(
            footer,
            text="",
            bg=t.SURFACE,
            fg=t.TEXT,
            font=t.FONT_H2,
            anchor="w",
            justify="left",
            wraplength=520,
        )
        self._plan_headline.pack(side="left", fill="x", expand=True)
        self._wrap_targets.append(self._plan_headline)
        FlatButton(
            footer, "Replay", lambda: self._play_plan(plan), kind="ghost", pady=5
        ).pack(side="right")

        self._play_plan(plan)

    def _heatmap(self, parent: tk.Frame, result: AuditResult) -> None:
        """One block per position, coloured by the entropy that survives there."""
        strength = result.strength
        bits = character_bits(strength)
        ceiling = max(bits) if bits else 0.0

        tk.Label(
            parent,
            text="WHERE THE ENTROPY IS",
            bg=t.SURFACE,
            fg=t.TEXT_FAINT,
            font=(t.UI, 8, "bold"),
            anchor="w",
        ).pack(fill="x", pady=(0, 6))

        rows = tk.Frame(parent, bg=t.SURFACE)
        rows.pack(fill="x")

        per_row = 32
        for offset in range(0, strength.length, per_row):
            row = tk.Frame(rows, bg=t.SURFACE)
            row.pack(anchor="w", pady=1)
            for index in range(offset, min(offset + per_row, strength.length)):
                value = bits[index]
                if ceiling <= 0 or value <= 0.05 * ceiling:
                    color, glyph_color = t.RED_DIM, t.RED
                elif value < 0.55 * ceiling:
                    color, glyph_color = t.AMBER_DIM, t.AMBER
                else:
                    color, glyph_color = t.GREEN_DIM, t.GREEN
                self._heat_block(row, strength.shape[index], color, glyph_color)

        tk.Label(
            parent,
            text=(
                "a lower   A upper   9 digit   # symbol      "
                "green = the attacker must guess it   red = free"
            ),
            bg=t.SURFACE,
            fg=t.TEXT_FAINT,
            font=t.FONT_SMALL,
            anchor="w",
        ).pack(fill="x", pady=(6, 0))

    def _heat_block(
        self, parent: tk.Frame, glyph: str, fill: str, glyph_color: str
    ) -> None:
        size_x, size_y = 17, 24
        canvas = tk.Canvas(
            parent,
            width=size_x,
            height=size_y,
            bg=t.SURFACE,
            highlightthickness=0,
            bd=0,
        )
        canvas.pack(side="left", padx=1)
        t.rounded_rect(canvas, 0, 0, size_x, size_y, 4, fill=fill, outline="")
        canvas.create_text(
            size_x / 2,
            size_y / 2,
            text=glyph,
            fill=glyph_color,
            font=(t.MONO, 9, "bold"),
        )

    def _play_plan(self, plan: AttackPlan) -> None:
        """Reveal the attack stages one at a time, cheapest first."""
        for child in self._steps_host.winfo_children():
            child.destroy()
        self._plan_headline.configure(text="")
        for handle in self._replay_jobs:
            try:
                self.after_cancel(handle)
            except Exception:
                pass
        self._replay_jobs.clear()

        for index, step in enumerate(plan.steps):
            handle = self.after(
                200 + index * 260, self._reveal_step, plan, index, step
            )
            self._replay_jobs.append(handle)

        final = self.after(
            200 + len(plan.steps) * 260,
            lambda: self._plan_headline.configure(
                text=plan.headline,
                fg=t.RED if plan.shortcut else t.TEXT,
            ),
        )
        self._replay_jobs.append(final)

    def _reveal_step(self, plan: AttackPlan, index: int, step) -> None:
        if self._steps_host is None or not self._steps_host.winfo_exists():
            return
        accent = (
            t.RED if step.kind == "breach" else t.TEXT_FAINT if step.bypassed else t.ACCENT
        )
        row = tk.Frame(self._steps_host, bg=t.SURFACE)
        row.pack(fill="x", pady=(0, 8))

        tk.Frame(row, bg=accent, width=3).pack(side="left", fill="y")
        body = tk.Frame(row, bg=t.SURFACE)
        body.pack(side="left", fill="x", expand=True, padx=(10, 0))

        head = tk.Frame(body, bg=t.SURFACE)
        head.pack(fill="x")
        tk.Label(
            head,
            text=f"{index + 1}.",
            bg=t.SURFACE,
            fg=t.TEXT_FAINT,
            font=t.FONT_SMALL,
        ).pack(side="left", padx=(0, 6))
        tk.Label(
            head,
            text=step.label + (" — bypassed" if step.bypassed else ""),
            bg=t.SURFACE,
            fg=t.TEXT_FAINT if step.bypassed else t.TEXT,
            font=t.FONT_H2,
        ).pack(side="left")
        tk.Label(
            head,
            text=f"{step.guess_display} guesses",
            bg=t.SURFACE,
            fg=accent,
            font=(t.MONO, 8),
        ).pack(side="right")

        self._paragraph(
            body,
            step.detail,
            color=t.TEXT_FAINT if step.bypassed else t.TEXT_MUTED,
            font=t.FONT_SMALL,
        )
        self._on_results_resize()

    def _composition_card(self, parent: tk.Frame, result: AuditResult) -> None:
        strength = result.strength
        card = Card(parent, "composition")
        card.pack(fill="x", pady=(12, 0))

        stats = tk.Frame(card.body, bg=t.SURFACE)
        stats.pack(fill="x")
        self._stat(stats, "Length", f"{strength.length}")
        self._stat(stats, "Pool", f"{strength.pool_size}")
        self._stat(stats, "Entropy", f"{strength.effective_bits:.0f} bits")
        self._stat(stats, "Raw entropy", f"{strength.raw_bits:.0f} bits")

        pills = tk.Frame(card.body, bg=t.SURFACE)
        pills.pack(fill="x", pady=(14, 0))
        for name in CLASS_ORDER:
            count = strength.classes.get(name, 0)
            if name == "other" and not count:
                continue  # do not nag about non-ASCII
            present = bool(count)
            Pill(
                pills,
                f"{CLASS_LABELS[name]}  {count}" if present else CLASS_LABELS[name],
                color=t.TEXT if present else t.TEXT_FAINT,
                fill=t.SURFACE_3 if present else t.SURFACE_2,
            ).pack(side="left", padx=(0, 6))

        if strength.missing_classes:
            self._paragraph(
                card.body,
                "Missing: " + ", ".join(strength.missing_classes),
                color=t.TEXT_MUTED,
                font=t.FONT_SMALL,
                pady=(10, 0),
            )

    def _breach_card(self, parent: tk.Frame, result: AuditResult) -> None:
        card = Card(parent, "breach check  -  hibp k-anonymity")
        card.pack(fill="x", pady=(12, 0))

        if result.breach is None:
            reason = result.breach_error or "switched off, so no request was made"
            self._banner(card.body, "NOT CHECKED", t.TEXT_MUTED, t.SURFACE_2)
            self._paragraph(card.body, reason, color=t.TEXT_MUTED, pady=(10, 0))
            return

        if result.breach.breached:
            self._banner(
                card.body,
                f"FOUND  -  {result.breach.count:,} time(s) in breach data",
                t.RED,
                t.RED_DIM,
            )
        else:
            self._banner(
                card.body, "NOT FOUND in Pwned Passwords", t.GREEN, t.GREEN_DIM
            )

        self._paragraph(
            card.body,
            f"Sent the hash prefix {result.breach.prefix} and nothing else. The "
            f"reply held {result.breach.candidates:,} hash suffixes, which were "
            "compared here on your machine - so the server could not tell which "
            "of them was yours.",
            color=t.TEXT_MUTED,
            font=t.FONT_SMALL,
            pady=(10, 0),
        )

    def _patterns_card(self, parent: tk.Frame, result: AuditResult) -> None:
        findings = result.strength.findings
        card = Card(parent, f"predictable patterns  ({len(findings)})")
        card.pack(fill="x", pady=(12, 0))

        if not findings:
            self._paragraph(
                card.body,
                "None detected - no dictionary words, keyboard walks, sequences, "
                "repeats or dates.",
                color=t.GREEN,
            )
            return

        for finding in findings:
            row = tk.Frame(card.body, bg=t.SURFACE)
            row.pack(fill="x", pady=(0, 8))

            tk.Frame(row, bg=t.AMBER, width=3).pack(side="left", fill="y")
            text = tk.Frame(row, bg=t.SURFACE)
            text.pack(side="left", fill="x", expand=True, padx=(10, 0))

            head = tk.Frame(text, bg=t.SURFACE)
            head.pack(fill="x")
            tk.Label(
                head,
                text=finding.kind.replace("_", " "),
                bg=t.SURFACE,
                fg=t.TEXT,
                font=t.FONT_H2,
            ).pack(side="left")
            tk.Label(
                head,
                text=f"characters {finding.start + 1}-{finding.end}",
                bg=t.SURFACE,
                fg=t.TEXT_FAINT,
                font=t.FONT_SMALL,
            ).pack(side="left", padx=(8, 0))

            self._paragraph(
                text, finding.detail, color=t.TEXT_MUTED, font=t.FONT_SMALL
            )

    def _suggestions_card(self, parent: tk.Frame, result: AuditResult) -> None:
        card = Card(parent, "suggestions")
        card.pack(fill="x", pady=(12, 0))
        for index, suggestion in enumerate(result.suggestions, start=1):
            row = tk.Frame(card.body, bg=t.SURFACE)
            row.pack(fill="x", pady=(0, 7))
            tk.Label(
                row,
                text=f"{index}",
                bg=t.SURFACE,
                fg=t.ACCENT,
                font=t.FONT_H2,
                width=2,
                anchor="nw",
            ).pack(side="left")
            self._paragraph(row, suggestion, color=t.TEXT_MUTED, side="left")

    # ------------------------------------------------------------------ #
    # Small building blocks
    # ------------------------------------------------------------------ #

    def _stat(self, parent: tk.Frame, label: str, value: str) -> None:
        cell = tk.Frame(parent, bg=t.SURFACE)
        cell.pack(side="left", padx=(0, 26))
        tk.Label(
            cell, text=value, bg=t.SURFACE, fg=t.TEXT, font=(t.UI, 13, "bold")
        ).pack(anchor="w")
        tk.Label(
            cell, text=label, bg=t.SURFACE, fg=t.TEXT_FAINT, font=t.FONT_SMALL
        ).pack(anchor="w")

    def _banner(self, parent: tk.Frame, text: str, fg: str, bg: str) -> None:
        banner = tk.Frame(parent, bg=bg)
        banner.pack(fill="x")
        tk.Label(
            banner, text=text, bg=bg, fg=fg, font=t.FONT_H2, anchor="w", padx=12, pady=9
        ).pack(fill="x")

    def _paragraph(
        self,
        parent: tk.Frame,
        text: str,
        *,
        color: str = t.TEXT,
        font: tuple = t.FONT_BODY,
        pady: tuple = (0, 0),
        side: str | None = None,
    ) -> tk.Label:
        label = tk.Label(
            parent,
            text=text,
            bg=t.SURFACE,
            fg=color,
            font=font,
            anchor="w",
            justify="left",
            wraplength=560,
        )
        if side:
            label.pack(side=side, fill="x", expand=True, pady=pady)
        else:
            label.pack(fill="x", pady=pady)
        self._wrap_targets.append(label)
        return label

    def _on_results_resize(self, _event: tk.Event | None = None) -> None:
        """Keep wrapped text matched to the window width."""
        width = self.results.canvas.winfo_width()
        if width <= 1:
            return
        wrap = max(240, width - 90)
        for label in self._wrap_targets:
            label.configure(wraplength=wrap)

    def _finish(self) -> None:
        self._busy = False
        self.audit_button.set_enabled(True)


def run() -> int:
    """Open the window. Returns an exit code for symmetry with the CLI."""
    AuditorWindow().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
