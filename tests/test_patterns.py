"""Tests for the offline pattern detectors."""

from password_auditor.patterns import (
    analyze_patterns,
    find_dictionary_words,
    find_keyboard_walks,
    find_repeats,
    find_sequences,
    leet_variants,
    load_wordlist,
)


def kinds(findings):
    return {f.kind for f in findings}


def test_wordlist_loads_and_skips_comments():
    words = load_wordlist()
    assert "password" in words
    assert "qwerty" in words
    assert not any(w.startswith("#") for w in words)


def test_keyboard_walk_across_a_row():
    findings = find_keyboard_walks("qwerty")
    assert findings
    walk = max(findings, key=lambda f: f.length)
    assert walk.kind == "keyboard_walk"
    assert (walk.start, walk.end) == (0, 6)


def test_keyboard_walk_diagonal():
    # "1qaz" walks down the left edge of a US QWERTY board.
    assert any(f.length >= 4 for f in find_keyboard_walks("1qaz"))


def test_unrelated_characters_are_not_a_walk():
    assert find_keyboard_walks("q8m3") == []


def test_ascending_and_descending_sequences():
    ascending = find_sequences("abcdef")
    assert ascending and (ascending[0].start, ascending[0].end) == (0, 6)
    descending = find_sequences("98765")
    assert descending and descending[0].length == 5
    assert "descending" in descending[0].detail


def test_short_runs_are_ignored():
    assert find_sequences("ab-zz") == []


def test_repeated_characters_and_blocks():
    assert kinds(find_repeats("aaaa")) == {"repeated_char"}
    assert "repeated_block" in kinds(find_repeats("abcabcabc"))


def test_leet_variants_preserve_length_and_alignment():
    variants = leet_variants("P@ssw0rd")
    assert all(len(v) == len("P@ssw0rd") for v in variants)
    assert "password" in variants


def test_dictionary_word_seen_through_leetspeak():
    findings = find_dictionary_words("P@ssw0rd")
    assert findings
    assert findings[0].kind == "dictionary_word"
    assert (findings[0].start, findings[0].end) == (0, 8)
    assert "leetspeak" in findings[0].detail


def test_reversed_word_detected():
    assert "reversed_word" in kinds(find_dictionary_words("xxdrowssapxx"))


def test_findings_never_overlap():
    findings = analyze_patterns("Password123qwerty!!!")
    spans = [(f.start, f.end) for f in sorted(findings, key=lambda f: f.start)]
    for (a_start, a_end), (b_start, b_end) in zip(spans, spans[1:]):
        assert a_end <= b_start, f"{spans} contains overlapping findings"


def test_random_password_has_no_findings():
    assert analyze_patterns("7#kQm2!vTzR9pLwX") == []
