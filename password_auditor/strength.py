"""Offline strength scoring: length, character variety and pattern penalties.

The model is deliberately simple and explainable:

1. Work out the search space implied by the character classes used (the pool).
2. Charge every character ``log2(pool)`` bits of entropy.
3. Refund most of those bits for any span a detector in
   :mod:`password_auditor.patterns` recognised, because an attacker running a
   wordlist or rule-based attack does not pay full price for predictable spans.
4. Map the surviving bits onto a 0-100 score.

This is an estimate, not a guarantee. It is intentionally pessimistic: a
password it rates highly may still be weak for reasons no offline checker can
see (it is your dog's name, it is reused elsewhere), which is exactly why the
breach lookup in :mod:`password_auditor.hibp` also runs.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass, field

from password_auditor.patterns import Finding, analyze_patterns

# Bits of entropy that map to a score of 100. 75 bits is comfortably beyond
# what offline GPU cracking of a fast hash can brute-force today.
TARGET_BITS = 75.0

# Guesses per second assumed for the crack-time estimate: a well-funded
# attacker against a fast, unsalted hash (the worst realistic case).
GUESSES_PER_SECOND = 1e11

# Character-class pool sizes.
_SYMBOLS = set(string.punctuation) | {" "}
_CLASS_POOLS: dict[str, int] = {
    "lowercase": 26,
    "uppercase": 26,
    "digits": 10,
    "symbols": len(_SYMBOLS),
    "other": 100,  # non-ASCII: charged conservatively
}

# One glyph per character class, used to show the *shape* of a password
# (e.g. "Aaaaaaa99") without ever echoing the characters themselves.
CLASS_GLYPH: dict[str, str] = {
    "lowercase": "a",
    "uppercase": "A",
    "digits": "9",
    "symbols": "#",
    "other": "?",
}

BANDS: tuple[tuple[int, str], ...] = (
    (20, "Very Weak"),
    (40, "Weak"),
    (60, "Fair"),
    (80, "Strong"),
    (101, "Very Strong"),
)


@dataclass
class StrengthResult:
    """The outcome of offline scoring for one password."""

    length: int
    classes: dict[str, int]
    pool_size: int
    raw_bits: float
    effective_bits: float
    score: int
    band: str
    findings: list[Finding] = field(default_factory=list)
    # Per-position character-class glyphs: the password's shape, not its text.
    shape: list[str] = field(default_factory=list)

    @property
    def guesses(self) -> float:
        """Expected guesses to crack, derived from the surviving entropy."""
        return 2.0**self.effective_bits

    @property
    def crack_time_seconds(self) -> float:
        return self.guesses / GUESSES_PER_SECOND

    @property
    def crack_time_display(self) -> str:
        return humanize_seconds(self.crack_time_seconds)

    @property
    def missing_classes(self) -> list[str]:
        return [name for name in ("lowercase", "uppercase", "digits", "symbols") if not self.classes.get(name)]


def character_class(ch: str) -> str:
    """Return the character-class name for a single character."""
    if ch.isascii():
        if ch.islower():
            return "lowercase"
        if ch.isupper():
            return "uppercase"
        if ch.isdigit():
            return "digits"
    if ch in _SYMBOLS:
        return "symbols"
    return "other"


def classify_characters(password: str) -> dict[str, int]:
    """Count how many characters fall into each character class."""
    counts = {name: 0 for name in _CLASS_POOLS}
    for ch in password:
        counts[character_class(ch)] += 1
    return counts


def shape_of(password: str) -> list[str]:
    """Return one class glyph per position: the shape, never the characters."""
    return [CLASS_GLYPH[character_class(ch)] for ch in password]


def pool_size(classes: dict[str, int]) -> int:
    """Sum the pool of every character class the password actually uses."""
    return sum(size for name, size in _CLASS_POOLS.items() if classes.get(name))


def score_from_bits(bits: float) -> int:
    """Map surviving entropy bits onto a 0-100 score."""
    return max(0, min(100, round(100.0 * bits / TARGET_BITS)))


def band_for_score(score: int) -> str:
    """Return the human-readable strength band for a score."""
    for ceiling, label in BANDS:
        if score < ceiling:
            return label
    return BANDS[-1][1]


def humanize_seconds(seconds: float) -> str:
    """Render a duration as a short, readable phrase."""
    if seconds < 1:
        return "instantly"
    units: tuple[tuple[str, float], ...] = (
        ("second", 1.0),
        ("minute", 60.0),
        ("hour", 3600.0),
        ("day", 86400.0),
        ("month", 2_629_800.0),
        ("year", 31_557_600.0),
    )
    if seconds >= 31_557_600.0 * 1000:
        exponent = int(math.log10(seconds / 31_557_600.0))
        return f"~10^{exponent} years"
    label, size = units[0]
    for name, unit_size in units:
        if seconds >= unit_size:
            label, size = name, unit_size
    value = seconds / size
    rounded = round(value)
    plural = "" if rounded == 1 else "s"
    return f"{rounded:,} {label}{plural}"


def analyze(password: str) -> StrengthResult:
    """Score ``password`` offline and return the full breakdown."""
    classes = classify_characters(password)
    pool = pool_size(classes)
    bits_per_char = math.log2(pool) if pool > 1 else 0.0
    raw_bits = len(password) * bits_per_char

    findings = analyze_patterns(password)
    # Refund entropy for predictable spans. Findings are non-overlapping, so
    # the discounts simply add up.
    discount = sum(f.length * bits_per_char * f.predictability for f in findings)
    effective_bits = max(0.0, raw_bits - discount)

    score = score_from_bits(effective_bits)
    return StrengthResult(
        length=len(password),
        classes=classes,
        pool_size=pool,
        raw_bits=raw_bits,
        effective_bits=effective_bits,
        score=score,
        band=band_for_score(score),
        findings=findings,
        shape=shape_of(password),
    )
