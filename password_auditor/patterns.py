"""Offline pattern detection: dictionary words, sequences, keyboard walks, repeats.

Every detector returns :class:`Finding` objects that carry the span of the
password they explain. :mod:`password_auditor.strength` converts those spans
into an entropy penalty, so a detector's job is only to say "characters
``[start:end)`` are predictable, and here is roughly how predictable".

Nothing in this module performs I/O: detection is fully local so that a
password is never transmitted in order to score it.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

# Minimum run length before a pattern is considered non-accidental.
MIN_RUN = 3
MIN_WORD = 3

# --------------------------------------------------------------------------- #
# Finding
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Finding:
    """A predictable region of a password.

    Attributes:
        kind: Machine-readable detector name, e.g. ``"keyboard_walk"``.
        start: Inclusive start index into the password.
        end: Exclusive end index into the password.
        token: The matched substring.
        detail: Human-readable explanation for the report.
        predictability: Fraction of the span's entropy the pattern destroys, in
            ``[0, 1]``. ``0.9`` means "this span is worth about 10% of what its
            length and character set alone would suggest".
    """

    kind: str
    start: int
    end: int
    token: str
    detail: str
    predictability: float

    @property
    def length(self) -> int:
        return self.end - self.start


# --------------------------------------------------------------------------- #
# Word list
# --------------------------------------------------------------------------- #


@lru_cache(maxsize=1)
def load_wordlist() -> frozenset[str]:
    """Load the bundled lowercase word list, ignoring comments and blank lines."""
    text = (
        resources.files("password_auditor.data")
        .joinpath("common_words.txt")
        .read_text(encoding="utf-8")
    )
    words = {
        line.strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    }
    return frozenset(w for w in words if len(w) >= MIN_WORD)


# --------------------------------------------------------------------------- #
# Leetspeak normalisation
# --------------------------------------------------------------------------- #

# Each substitute maps to one or more plausible letters. Substitutions are
# strictly one character to one character, so indices in a normalised variant
# still line up with indices in the original password.
LEET_MAP: dict[str, tuple[str, ...]] = {
    "0": ("o",),
    "1": ("l", "i"),
    "2": ("z",),
    "3": ("e",),
    "4": ("a",),
    "5": ("s",),
    "6": ("g",),
    "7": ("t",),
    "8": ("b",),
    "9": ("g",),
    "@": ("a",),
    "$": ("s",),
    "!": ("i",),
    "|": ("l", "i"),
    "+": ("t",),
    "(": ("c",),
}

# Cap on generated variants; ambiguous substitutions beyond this budget are
# pinned to their first candidate rather than fanning out combinatorially.
MAX_LEET_VARIANTS = 64


def leet_variants(password: str) -> list[str]:
    """Return index-aligned lowercase variants with leet substitutions undone.

    The first element is always the plain lowercase password. Every variant has
    the same length as ``password``, so a match at ``[i:j)`` in a variant refers
    to the same span of the original.
    """
    lowered = password.lower()
    choices: list[tuple[str, ...]] = []
    budget = MAX_LEET_VARIANTS
    for ch in lowered:
        options = LEET_MAP.get(ch)
        if not options:
            choices.append((ch,))
            continue
        if len(options) > 1 and budget // len(options) >= 1:
            budget //= len(options)
            choices.append(options)
        else:
            choices.append((options[0],))

    variants = ["".join(combo) for combo in itertools.product(*choices)]
    if lowered not in variants:
        variants.insert(0, lowered)
    return variants


# --------------------------------------------------------------------------- #
# Keyboard adjacency graph
# --------------------------------------------------------------------------- #

# Each row is (unshifted, shifted, x-offset in key widths). The offsets encode
# the physical stagger of a US QWERTY board so diagonal neighbours such as
# "1qaz" come out right.
_ROWS: tuple[tuple[str, str, float], ...] = (
    ("`1234567890-=", "~!@#$%^&*()_+", 0.0),
    ("qwertyuiop[]\\", "QWERTYUIOP{}|", 1.5),
    ("asdfghjkl;'", 'ASDFGHJKL:"', 1.75),
    ("zxcvbnm,./", "ZXCVBNM<>?", 2.25),
)


@lru_cache(maxsize=1)
def _key_positions() -> dict[str, tuple[int, float]]:
    """Map every keyboard character to its ``(row, x)`` physical position."""
    positions: dict[str, tuple[int, float]] = {}
    for row_index, (plain, shifted, offset) in enumerate(_ROWS):
        for col, ch in enumerate(plain):
            positions[ch] = (row_index, offset + col)
        for col, ch in enumerate(shifted):
            positions[ch] = (row_index, offset + col)
    return positions


def _adjacent(a: str, b: str) -> bool:
    """True if ``a`` and ``b`` sit on neighbouring keys (and not the same key)."""
    positions = _key_positions()
    pos_a, pos_b = positions.get(a), positions.get(b)
    if pos_a is None or pos_b is None:
        return False
    row_delta = abs(pos_a[0] - pos_b[0])
    x_delta = abs(pos_a[1] - pos_b[1])
    if row_delta > 1:
        return False
    if row_delta == 0:
        return abs(x_delta - 1.0) < 1e-9
    return x_delta <= 1.0


# --------------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------------- #


def find_repeats(password: str) -> list[Finding]:
    """Find repeated single characters (``aaa``) and repeated blocks (``abcabc``)."""
    findings: list[Finding] = []

    for match in re.finditer(r"(.)\1{%d,}" % (MIN_RUN - 1), password):
        findings.append(
            Finding(
                kind="repeated_char",
                start=match.start(),
                end=match.end(),
                token=match.group(),
                detail=f"{match.end() - match.start()} copies of the same character",
                predictability=0.95,
            )
        )

    # Repeated block: a unit of 2+ characters repeated at least twice.
    for match in re.finditer(r"(.{2,}?)\1+", password):
        unit = match.group(1)
        if len(set(unit)) == 1:
            continue  # already covered by repeated_char
        repeats = len(match.group()) // len(unit)
        findings.append(
            Finding(
                kind="repeated_block",
                start=match.start(),
                end=match.end(),
                token=match.group(),
                detail=f"a {len(unit)}-character block repeated {repeats} times",
                predictability=0.9,
            )
        )

    return findings


_ALPHABETS: tuple[tuple[str, str], ...] = (
    ("abcdefghijklmnopqrstuvwxyz", "letters"),
    ("0123456789", "digits"),
)


def find_sequences(password: str) -> list[Finding]:
    """Find ascending or descending runs such as ``abcde``, ``987``, ``wxyz``."""
    lowered = password.lower()
    findings: list[Finding] = []

    for alphabet, label in _ALPHABETS:
        index = {ch: i for i, ch in enumerate(alphabet)}
        start = 0
        while start < len(lowered):
            if lowered[start] not in index:
                start += 1
                continue
            best_end, best_step = start + 1, 0
            for step in (1, -1):
                end = start + 1
                while (
                    end < len(lowered)
                    and lowered[end] in index
                    and index[lowered[end]] - index[lowered[end - 1]] == step
                ):
                    end += 1
                if end > best_end:
                    best_end, best_step = end, step
            if best_end - start >= MIN_RUN:
                direction = "ascending" if best_step == 1 else "descending"
                findings.append(
                    Finding(
                        kind="sequence",
                        start=start,
                        end=best_end,
                        token=password[start:best_end],
                        detail=f"{direction} run of {best_end - start} {label}",
                        predictability=0.92,
                    )
                )
                start = best_end
            else:
                start += 1

    return findings


def find_keyboard_walks(password: str) -> list[Finding]:
    """Find runs of physically adjacent keys such as ``qwerty`` or ``1qaz``."""
    findings: list[Finding] = []
    start = 0
    while start < len(password) - 1:
        end = start + 1
        while end < len(password) and _adjacent(password[end - 1], password[end]):
            end += 1
        if end - start >= MIN_RUN:
            findings.append(
                Finding(
                    kind="keyboard_walk",
                    start=start,
                    end=end,
                    token=password[start:end],
                    detail=f"{end - start} keys walked across the keyboard",
                    predictability=0.88,
                )
            )
            start = end
        else:
            start += 1
    return findings


def find_dictionary_words(password: str) -> list[Finding]:
    """Find list words in the password, seeing through case, leet and reversal."""
    words = load_wordlist()
    max_word = max(len(w) for w in words)
    raw_matches: list[Finding] = []

    for variant in leet_variants(password):
        leetish = variant != password.lower()
        for start in range(len(variant)):
            upper_bound = min(len(variant), start + max_word)
            for end in range(upper_bound, start + MIN_WORD - 1, -1):
                chunk = variant[start:end]
                if chunk in words:
                    notes = ["common word or password base"]
                    if leetish:
                        notes.append("leetspeak substitutions do not hide it")
                    raw_matches.append(
                        Finding(
                            kind="dictionary_word",
                            start=start,
                            end=end,
                            token=password[start:end],
                            detail="; ".join(notes),
                            predictability=0.85,
                        )
                    )
                    break  # the longest match at this start is enough
                if chunk[::-1] in words:
                    raw_matches.append(
                        Finding(
                            kind="reversed_word",
                            start=start,
                            end=end,
                            token=password[start:end],
                            detail="a common word spelled backwards",
                            predictability=0.8,
                        )
                    )
                    break

    return _keep_longest_non_overlapping(raw_matches)


_YEAR_RE = re.compile(r"(?:19|20)\d{2}")
_DATE_RE = re.compile(
    r"(?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])[-/.](?:\d{2}|(?:19|20)\d{2})"
)


def find_dates(password: str) -> list[Finding]:
    """Find four-digit years and common numeric date formats."""
    findings: list[Finding] = []
    for match in _DATE_RE.finditer(password):
        findings.append(
            Finding(
                kind="date",
                start=match.start(),
                end=match.end(),
                token=match.group(),
                detail="looks like a calendar date",
                predictability=0.85,
            )
        )
    for match in _YEAR_RE.finditer(password):
        findings.append(
            Finding(
                kind="year",
                start=match.start(),
                end=match.end(),
                token=match.group(),
                detail="looks like a year, a very common suffix",
                predictability=0.85,
            )
        )
    return _keep_longest_non_overlapping(findings)


def _keep_longest_non_overlapping(findings: list[Finding]) -> list[Finding]:
    """Greedily keep the longest, left-most findings and drop overlapping ones."""
    kept: list[Finding] = []
    for finding in sorted(findings, key=lambda f: (-f.length, f.start)):
        if any(finding.start < k.end and k.start < finding.end for k in kept):
            continue
        kept.append(finding)
    return sorted(kept, key=lambda f: f.start)


DETECTORS = (
    find_dictionary_words,
    find_keyboard_walks,
    find_sequences,
    find_repeats,
    find_dates,
)


def analyze_patterns(password: str) -> list[Finding]:
    """Run every detector and resolve overlaps in favour of longer matches."""
    findings: list[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(password))
    return _keep_longest_non_overlapping(findings)
