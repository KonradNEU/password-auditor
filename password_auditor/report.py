"""Terminal rendering for an :class:`~password_auditor.auditor.AuditResult`.

The renderer never prints the password itself, only its length, the classes of
characters it used, the *kind* of patterns found, and the hash prefix that was
sent to the API.
"""

from __future__ import annotations

import json

from password_auditor.auditor import AuditResult
from password_auditor.crack import character_bits, plan_attack
from password_auditor.strength import GUESSES_PER_SECOND

WIDTH = 66
BAR_WIDTH = 30

_RESET = "\033[0m"
_COLORS = {
    "Very Weak": "\033[91m",
    "Weak": "\033[91m",
    "Fair": "\033[93m",
    "Strong": "\033[92m",
    "Very Strong": "\033[92m",
    "dim": "\033[2m",
    "bold": "\033[1m",
}

_CLASS_LABELS = {
    "lowercase": "lowercase",
    "uppercase": "uppercase",
    "digits": "digits",
    "symbols": "symbols",
    "other": "non-ASCII",
}


class Painter:
    """Applies ANSI colour, or not, depending on ``enabled``."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, key: str) -> str:
        if not self.enabled:
            return text
        code = _COLORS.get(key)
        return f"{code}{text}{_RESET}" if code else text


def _rule(char: str = "-") -> str:
    return char * WIDTH


def _score_bar(score: int) -> str:
    filled = round(BAR_WIDTH * score / 100)
    return "#" * filled + "." * (BAR_WIDTH - filled)


def render_text(result: AuditResult, *, color: bool = True) -> str:
    """Render the audit as a plain-text report."""
    paint = Painter(color)
    strength = result.strength
    lines: list[str] = []

    lines.append(_rule("="))
    lines.append(paint("  PASSWORD AUDIT REPORT", "bold"))
    lines.append(_rule("="))
    lines.append("")

    # --- Strength ------------------------------------------------------- #
    bar = _score_bar(result.score)
    lines.append(
        f"  Strength   {paint(bar, result.band)}  "
        f"{paint(f'{result.score}/100', result.band)}  "
        f"{paint(result.band.upper(), result.band)}"
    )
    if result.breached and strength.score > result.score:
        lines.append(
            paint(
                f"             (offline score was {strength.score}/100, capped "
                "because the password is breached)",
                "dim",
            )
        )
    lines.append("")

    # --- Composition ---------------------------------------------------- #
    used = [
        f"{_CLASS_LABELS[name]} x{count}"
        for name, count in strength.classes.items()
        if count
    ]
    lines.append(f"  Length     {strength.length} characters")
    lines.append(f"  Variety    {', '.join(used) if used else 'none'}")
    lines.append(
        f"  Entropy    {strength.effective_bits:.1f} bits effective "
        f"(of {strength.raw_bits:.1f} raw, pool of {strength.pool_size})"
    )
    lines.append(
        f"  Crack time {strength.crack_time_display} "
        f"at {GUESSES_PER_SECOND:.0e} guesses/sec offline"
    )
    lines.append("")

    # --- Patterns ------------------------------------------------------- #
    lines.append(paint("  Predictable patterns", "bold"))
    if strength.findings:
        for finding in strength.findings:
            location = f"chars {finding.start + 1}-{finding.end}"
            lines.append(
                f"    ! {finding.kind.replace('_', ' ')} ({location}): {finding.detail}"
            )
    else:
        lines.append("    - none detected")
    lines.append("")

    # --- Attack replay -------------------------------------------------- #
    lines.extend(_attack_section(result, paint))

    # --- Breach --------------------------------------------------------- #
    lines.append(paint("  Breach check (HIBP, k-anonymity)", "bold"))
    if result.breach is None:
        reason = result.breach_error or "skipped at your request"
        lines.append(f"    - not checked: {reason}")
    elif result.breach.breached:
        lines.append(
            paint(
                f"    ! FOUND in breach data {result.breach.count:,} time(s)",
                "Very Weak",
            )
        )
        lines.append(
            paint(
                f"      sent hash prefix {result.breach.prefix} only; matched "
                f"locally against {result.breach.candidates:,} candidates",
                "dim",
            )
        )
    else:
        lines.append(paint("    + not found in Pwned Passwords", "Strong"))
        lines.append(
            paint(
                f"      sent hash prefix {result.breach.prefix} only; compared "
                f"locally against {result.breach.candidates:,} candidates",
                "dim",
            )
        )
    lines.append("")

    # --- Remediation ---------------------------------------------------- #
    lines.append(paint("  Suggestions", "bold"))
    for index, suggestion in enumerate(result.suggestions, start=1):
        lines.extend(_wrap_numbered(index, suggestion))
    lines.append("")
    lines.append(_rule("="))
    return "\n".join(lines)


def _attack_section(result: AuditResult, paint: Painter) -> list[str]:
    """Render the entropy heatmap and the reconstructed attack stages."""
    strength = result.strength
    lines: list[str] = [paint("  How it falls", "bold")]

    if not strength.length:
        return lines + ["    - nothing to attack", ""]

    # Heatmap: the password's shape, coloured by surviving entropy per
    # position. Character classes, never the characters themselves.
    bits = character_bits(strength)
    ceiling = max(bits) if bits else 0.0
    shape_row = ""
    for glyph, value in zip(strength.shape, bits):
        if ceiling <= 0 or value <= 0.05 * ceiling:
            shape_row += paint(glyph, "Very Weak")
        elif value < 0.55 * ceiling:
            shape_row += paint(glyph, "Fair")
        else:
            shape_row += paint(glyph, "Strong")
    lines.append(f"    shape  {shape_row}")
    lines.append(
        paint(
            "           a=lower A=upper 9=digit #=symbol; red costs an "
            "attacker nothing",
            "dim",
        )
    )
    lines.append("")

    plan = plan_attack(strength, result.breach)
    for index, step in enumerate(plan.steps, start=1):
        marker = "x" if step.kind == "breach" else ("-" if step.bypassed else ">")
        label = step.label
        if step.bypassed:
            label += " (bypassed)"
        lines.append(f"    {marker} {index}. {label}")
        lines.append(paint(f"         {step.guess_display} guesses", "dim"))
    lines.append(f"    = {plan.headline}")
    lines.append("")
    return lines


def _wrap_numbered(index: int, text: str, indent: int = 4) -> list[str]:
    """Wrap ``text`` into report-width lines prefixed with ``index.``."""
    prefix = " " * indent + f"{index}. "
    continuation = " " * len(prefix)
    limit = WIDTH - len(prefix)
    words = text.split()
    out: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > limit and current:
            out.append((prefix if not out else continuation) + current)
            current = word
        else:
            current = candidate
    if current:
        out.append((prefix if not out else continuation) + current)
    return out


def render_json(result: AuditResult) -> str:
    """Render the audit as JSON for scripting."""
    return json.dumps(result.to_dict(), indent=2)
