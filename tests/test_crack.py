"""Tests for the reconstructed attack plan and the entropy heatmap."""

import math

from password_auditor.crack import character_bits, format_guesses, plan_attack
from password_auditor.hibp import BreachResult
from password_auditor.strength import analyze

STRONG = "7#kQm2!vTzR9pLwX"


def test_total_guesses_match_the_score():
    """The replay must agree with the score, not offer a rival estimate."""
    for password in ("password", "P@ssw0rd", STRONG, "Tr0ub4dor&3", "aaaaaaaa"):
        strength = analyze(password)
        plan = plan_attack(strength)
        assert math.isclose(
            math.log2(plan.total_guesses), strength.effective_bits, abs_tol=0.01
        ), password


def test_random_password_is_pure_brute_force():
    plan = plan_attack(analyze(STRONG))
    assert len(plan.steps) == 1
    assert plan.steps[0].kind == "brute"
    assert not plan.shortcut
    assert "brute force" in plan.headline.lower()


def test_dictionary_password_starts_with_the_wordlist():
    plan = plan_attack(analyze("password"))
    assert plan.steps[0].label == "Wordlist + mangling rules"
    assert plan.steps[0].kind == "pattern"


def test_stages_are_ordered_cheapest_first():
    plan = plan_attack(analyze("password1998xkqvmz"))
    guesses = [step.guesses for step in plan.steps]
    assert guesses == sorted(guesses)
    assert len(plan.steps) >= 2


def test_uncovered_characters_become_a_brute_force_stage():
    plan = plan_attack(analyze("passwordXQ7#"))
    kinds = [step.kind for step in plan.steps]
    assert "brute" in kinds
    brute = next(step for step in plan.steps if step.kind == "brute")
    assert "4 position(s)" in brute.detail


def test_breach_prepends_a_lookup_and_bypasses_everything():
    strength = analyze(STRONG)
    breach = BreachResult(prefix="ABCDE", count=5000, candidates=800)
    plan = plan_attack(strength, breach)

    assert plan.shortcut
    assert plan.steps[0].kind == "breach"
    assert plan.steps[0].guesses == 1.0
    assert "5,000" in plan.steps[0].detail
    assert all(step.bypassed for step in plan.steps[1:])
    assert "instantly" in plan.headline


def test_clean_breach_result_does_not_shortcut():
    breach = BreachResult(prefix="ABCDE", count=0, candidates=800)
    assert not plan_attack(analyze(STRONG), breach).shortcut


def test_empty_password_has_no_stages():
    plan = plan_attack(analyze(""))
    assert plan.steps == []
    assert plan.headline == "Nothing to attack."


def test_character_bits_are_flat_for_a_random_password():
    strength = analyze(STRONG)
    bits = character_bits(strength)
    assert len(bits) == strength.length
    assert len(set(round(b, 6) for b in bits)) == 1
    assert math.isclose(sum(bits), strength.effective_bits, rel_tol=1e-9)


def test_character_bits_collapse_inside_a_pattern():
    strength = analyze("passwordXQ7#")
    bits = character_bits(strength)
    # The dictionary word occupies the first eight positions.
    assert all(bits[i] < bits[9] for i in range(8))
    assert math.isclose(sum(bits), strength.effective_bits, rel_tol=1e-9)


def test_shape_shows_classes_not_characters():
    strength = analyze("P@ssw0rd")
    # P -> A, @ -> #, letters -> a, 0 -> 9: the shape, never the characters.
    assert "".join(strength.shape) == "A#aaa9aa"
    assert len(strength.shape) == strength.length


def test_format_guesses_is_readable():
    assert format_guesses(50) == "50"
    assert format_guesses(2.0**20).startswith("2^20")
    assert format_guesses(2.0**90) == "2^90"
