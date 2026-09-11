"""Tests for offline strength scoring."""

import math

from password_auditor.strength import (
    TARGET_BITS,
    analyze,
    band_for_score,
    classify_characters,
    humanize_seconds,
    pool_size,
    score_from_bits,
)


def test_character_classification():
    counts = classify_characters("aB3!")
    assert counts["lowercase"] == 1
    assert counts["uppercase"] == 1
    assert counts["digits"] == 1
    assert counts["symbols"] == 1
    assert counts["other"] == 0


def test_non_ascii_counts_as_other():
    assert classify_characters("é").get("other") == 1


def test_pool_grows_with_variety():
    assert pool_size(classify_characters("abc")) == 26
    assert pool_size(classify_characters("abcABC")) == 52
    assert pool_size(classify_characters("abcABC123")) == 62
    assert pool_size(classify_characters("abcABC123!")) > 62


def test_score_and_band_mapping():
    assert score_from_bits(0) == 0
    assert score_from_bits(TARGET_BITS) == 100
    assert score_from_bits(TARGET_BITS * 10) == 100
    assert band_for_score(0) == "Very Weak"
    assert band_for_score(30) == "Weak"
    assert band_for_score(50) == "Fair"
    assert band_for_score(70) == "Strong"
    assert band_for_score(100) == "Very Strong"


def test_common_password_scores_very_low():
    result = analyze("password")
    assert result.score < 20
    assert result.band == "Very Weak"
    assert any(f.kind == "dictionary_word" for f in result.findings)
    assert result.effective_bits < result.raw_bits


def test_leetspeak_does_not_rescue_a_common_word():
    plain = analyze("password")
    leet = analyze("P@ssw0rd")
    # More character classes raise the raw entropy, but the pattern penalty
    # keeps the surviving entropy in the same league.
    assert leet.raw_bits > plain.raw_bits
    assert leet.score < 40


def test_long_random_password_scores_high():
    result = analyze("7#kQm2!vTzR9pLwX")
    assert result.findings == []
    assert result.score >= 80
    assert result.band in {"Strong", "Very Strong"}


def test_length_beats_substitution():
    short_complex = analyze("P@s5!")
    long_random = analyze("xkqvmzrtplwnbdhs")
    assert long_random.score > short_complex.score


def test_missing_classes_reported():
    assert set(analyze("abcdefgh").missing_classes) == {
        "uppercase",
        "digits",
        "symbols",
    }
    assert analyze("aB3!xyzQ").missing_classes == []


def test_empty_password_is_zero():
    result = analyze("")
    assert result.score == 0
    assert result.effective_bits == 0.0


def test_crack_time_is_readable():
    assert humanize_seconds(0.001) == "instantly"
    assert humanize_seconds(1) == "1 second"
    assert humanize_seconds(90) == "2 minutes"
    assert "years" in humanize_seconds(60 * 60 * 24 * 365 * 5)
    assert humanize_seconds(1e30).startswith("~10^")


def test_guesses_track_effective_bits():
    result = analyze("correctH0rse!")
    assert math.isclose(math.log2(result.guesses), result.effective_bits, rel_tol=1e-9)
