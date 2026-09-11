"""Orchestration: combine offline scoring with the breach lookup and advise.

This module owns the one policy decision the tool makes: a password that
appears in a breach corpus is treated as compromised regardless of how strong
it looks, because attackers try known-breached passwords first.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from password_auditor.crack import plan_attack
from password_auditor.hibp import BreachResult, HibpError, check_password
from password_auditor.strength import StrengthResult, analyze, band_for_score

# A breached password cannot score above this, whatever its entropy suggests.
BREACH_SCORE_CAP = 5

# Length thresholds used for advice.
MIN_REASONABLE_LENGTH = 12
RECOMMENDED_LENGTH = 16

_PATTERN_ADVICE: dict[str, str] = {
    "dictionary_word": (
        "Drop the common word: wordlist attacks try dictionary bases with "
        "capitalisation, digit and symbol rules before anything else."
    ),
    "reversed_word": (
        "Reversing a common word is a standard cracking rule, not a disguise."
    ),
    "keyboard_walk": (
        "Avoid keyboard walks such as 'qwerty' or '1qaz' - cracking tools "
        "generate them from the keyboard layout."
    ),
    "sequence": "Avoid runs like 'abc' or '789'; they add length but almost no entropy.",
    "repeated_char": "Repeating a character pads the length without adding entropy.",
    "repeated_block": "Repeating a block ('abcabc') roughly halves the real entropy.",
    "year": "Trailing years are the single most common password suffix - leave them out.",
    "date": "Dates are guessable, especially ones connected to you.",
}

_GENERIC_ADVICE: tuple[str, ...] = (
    "Use a password manager to generate and store a long random password, "
    "unique to each account.",
    "Where a memorable secret is required, prefer a passphrase of 4-5 random, "
    "unrelated words.",
    "Turn on multi-factor authentication: it limits the damage if a password "
    "does leak.",
)


@dataclass
class AuditResult:
    """Everything the report needs, with no plaintext password retained."""

    strength: StrengthResult
    breach: BreachResult | None
    breach_error: str | None
    score: int
    band: str
    suggestions: list[str] = field(default_factory=list)

    @property
    def breached(self) -> bool:
        return self.breach is not None and self.breach.breached

    @property
    def breach_checked(self) -> bool:
        return self.breach is not None

    def to_dict(self) -> dict:
        """Serialise the audit for ``--json`` output. Contains no password."""
        return {
            "score": self.score,
            "band": self.band,
            "length": self.strength.length,
            "character_classes": {
                name: count for name, count in self.strength.classes.items() if count
            },
            "pool_size": self.strength.pool_size,
            "entropy_bits": {
                "raw": round(self.strength.raw_bits, 1),
                "effective": round(self.strength.effective_bits, 1),
            },
            "estimated_offline_crack_time": self.strength.crack_time_display,
            "shape": "".join(self.strength.shape),
            "attack_path": [
                {
                    "stage": step.label,
                    "kind": step.kind,
                    "guesses": step.guess_display,
                    "bypassed": step.bypassed,
                }
                for step in plan_attack(self.strength, self.breach).steps
            ],
            "patterns": [
                {
                    "kind": f.kind,
                    "start": f.start,
                    "end": f.end,
                    "detail": f.detail,
                }
                for f in self.strength.findings
            ],
            "breach": (
                {
                    "checked": True,
                    "found": self.breach.breached,
                    "count": self.breach.count,
                    "hash_prefix_sent": self.breach.prefix,
                    "anonymity_set_size": self.breach.candidates,
                }
                if self.breach is not None
                else {"checked": False, "error": self.breach_error}
            ),
            "suggestions": self.suggestions,
        }


def build_suggestions(strength: StrengthResult, breach: BreachResult | None) -> list[str]:
    """Produce ordered, de-duplicated remediation advice."""
    suggestions: list[str] = []

    if breach is not None and breach.breached:
        suggestions.append(
            f"Stop using this password now: it appears {breach.count:,} time(s) in "
            "known breach corpora, so it is already in attackers' wordlists."
        )
        suggestions.append(
            "Change it anywhere you have reused it, and check those accounts for "
            "unfamiliar sessions or recovery-address changes."
        )

    if strength.length < MIN_REASONABLE_LENGTH:
        suggestions.append(
            f"Make it longer: {strength.length} characters is short. Aim for at "
            f"least {RECOMMENDED_LENGTH}; length buys more strength than any "
            "substitution trick."
        )
    elif strength.length < RECOMMENDED_LENGTH:
        suggestions.append(
            f"Consider growing it from {strength.length} to {RECOMMENDED_LENGTH}+ "
            "characters."
        )

    missing = strength.missing_classes
    if missing and strength.length < 20:
        suggestions.append(
            "Widen the character set - nothing from: " + ", ".join(missing) + "."
        )

    seen_kinds: set[str] = set()
    for finding in strength.findings:
        if finding.kind in seen_kinds:
            continue
        seen_kinds.add(finding.kind)
        advice = _PATTERN_ADVICE.get(finding.kind)
        if advice:
            suggestions.append(advice)

    suggestions.extend(_GENERIC_ADVICE)

    deduped: list[str] = []
    for item in suggestions:
        if item not in deduped:
            deduped.append(item)
    return deduped


def audit(
    password: str,
    *,
    check_breach: bool = True,
    timeout: float | None = None,
) -> AuditResult:
    """Score ``password`` and, unless disabled, check it against Pwned Passwords.

    A failed breach lookup is not fatal: the offline score is still returned and
    the failure is reported in ``breach_error``.
    """
    strength = analyze(password)

    breach: BreachResult | None = None
    breach_error: str | None = None
    if check_breach:
        try:
            kwargs = {} if timeout is None else {"timeout": timeout}
            breach = check_password(password, **kwargs)
        except HibpError as exc:
            breach_error = str(exc)

    score = strength.score
    if breach is not None and breach.breached:
        score = min(score, BREACH_SCORE_CAP)

    return AuditResult(
        strength=strength,
        breach=breach,
        breach_error=breach_error,
        score=score,
        band=band_for_score(score),
        suggestions=build_suggestions(strength, breach),
    )
