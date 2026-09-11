"""Tests for orchestration, the breach score cap, and remediation advice."""

import password_auditor.auditor as auditor_module
from password_auditor.auditor import BREACH_SCORE_CAP, audit, build_suggestions
from password_auditor.hibp import BreachResult, HibpError
from password_auditor.strength import analyze

STRONG = "7#kQm2!vTzR9pLwX"


def fake_lookup(result=None, error=None):
    def _lookup(password, **kwargs):
        if error is not None:
            raise error
        return result

    return _lookup


def test_offline_mode_skips_the_lookup(monkeypatch):
    def explode(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("breach lookup ran despite check_breach=False")

    monkeypatch.setattr(auditor_module, "check_password", explode)
    result = audit("password", check_breach=False)
    assert not result.breach_checked
    assert result.breach is None
    assert result.breach_error is None


def test_breach_caps_an_otherwise_strong_score(monkeypatch):
    breach = BreachResult(prefix="ABCDE", count=1234, candidates=800)
    monkeypatch.setattr(auditor_module, "check_password", fake_lookup(breach))
    result = audit(STRONG)
    assert result.strength.score >= 80  # strong on offline metrics alone
    assert result.breached
    assert result.score <= BREACH_SCORE_CAP
    assert result.band == "Very Weak"


def test_clean_lookup_leaves_the_score_alone(monkeypatch):
    breach = BreachResult(prefix="ABCDE", count=0, candidates=800)
    monkeypatch.setattr(auditor_module, "check_password", fake_lookup(breach))
    result = audit(STRONG)
    assert not result.breached
    assert result.score == result.strength.score


def test_lookup_failure_is_not_fatal(monkeypatch):
    monkeypatch.setattr(
        auditor_module, "check_password", fake_lookup(error=HibpError("offline"))
    )
    result = audit("password")
    assert result.breach is None
    assert result.breach_error == "offline"
    assert result.score == result.strength.score  # offline score still reported


def test_suggestions_lead_with_the_breach():
    breach = BreachResult(prefix="ABCDE", count=42, candidates=800)
    suggestions = build_suggestions(analyze(STRONG), breach)
    assert "Stop using this password now" in suggestions[0]
    assert "42" in suggestions[0]


def test_suggestions_cover_length_variety_and_patterns():
    # "tyuiop" is a keyboard walk that is not also a word-list entry, so the
    # walk survives overlap resolution and its advice appears.
    suggestions = build_suggestions(analyze("tyuiop"), None)
    blob = " ".join(suggestions).lower()
    assert "longer" in blob
    assert "uppercase" in blob and "digits" in blob
    assert "keyboard walk" in blob


def test_suggestions_are_deduplicated_and_always_actionable():
    suggestions = build_suggestions(analyze("abcabcabc123123"), None)
    assert len(suggestions) == len(set(suggestions))
    assert any("password manager" in s for s in suggestions)


def test_to_dict_is_json_safe_and_holds_no_password(monkeypatch):
    breach = BreachResult(prefix="5BAA6", count=7, candidates=800)
    monkeypatch.setattr(auditor_module, "check_password", fake_lookup(breach))
    payload = audit("P@ssw0rd").to_dict()

    assert payload["breach"] == {
        "checked": True,
        "found": True,
        "count": 7,
        "hash_prefix_sent": "5BAA6",
        "anonymity_set_size": 800,
    }
    assert payload["length"] == 8
    assert payload["patterns"][0]["kind"] == "dictionary_word"
    assert "P@ssw0rd" not in repr(payload)


def test_to_dict_records_a_skipped_lookup():
    payload = audit(STRONG, check_breach=False).to_dict()
    assert payload["breach"] == {"checked": False, "error": None}
