"""End-to-end CLI tests, all offline (``--offline`` never touches the network)."""

import io
import json

import pytest

from password_auditor.cli import (
    EXIT_BREACHED,
    EXIT_OK,
    EXIT_USAGE,
    EXIT_WEAK,
    build_parser,
    main,
    read_password,
    use_color,
)

STRONG = "7#kQm2!vTzR9pLwX"


class FakeTTY(io.StringIO):
    """A stdin stand-in that claims to be a terminal, so getpass is used."""

    def isatty(self):
        return True


def feed(monkeypatch, text):
    monkeypatch.setattr("sys.stdin", io.StringIO(text))


def test_parser_has_no_password_argument():
    """The password must never be accepted via argv."""
    parser = build_parser()
    options = {action.dest for action in parser._actions}
    assert "password" not in options
    with pytest.raises(SystemExit):
        parser.parse_args(["hunter2"])


def test_read_password_from_stdin_preserves_trailing_spaces(monkeypatch):
    feed(monkeypatch, "  pa ss  \n")
    assert read_password(from_stdin=True, confirm=False) == "  pa ss  "


def test_read_password_rejects_mismatched_confirmation(monkeypatch):
    answers = iter(["abc", "abd"])
    monkeypatch.setattr("sys.stdin", FakeTTY(""))
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    with pytest.raises(ValueError):
        read_password(from_stdin=False, confirm=True)


def test_read_password_uses_getpass_on_a_terminal(monkeypatch):
    monkeypatch.setattr("sys.stdin", FakeTTY(""))
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "s3cret")
    assert read_password(from_stdin=False, confirm=False) == "s3cret"


def test_weak_password_exits_weak(monkeypatch, capsys):
    feed(monkeypatch, "password\n")
    assert main(["--offline", "--stdin"]) == EXIT_WEAK
    out = capsys.readouterr().out
    assert "PASSWORD AUDIT REPORT" in out
    assert "VERY WEAK" in out
    assert "dictionary word" in out
    assert "not checked" in out


def test_strong_password_exits_ok_and_is_not_echoed(monkeypatch, capsys):
    feed(monkeypatch, STRONG + "\n")
    assert main(["--offline", "--stdin"]) == EXIT_OK
    out = capsys.readouterr().out
    assert STRONG not in out
    assert "none detected" in out


def test_empty_input_is_a_usage_error(monkeypatch, capsys):
    feed(monkeypatch, "\n")
    assert main(["--offline", "--stdin"]) == EXIT_USAGE
    assert "no password provided" in capsys.readouterr().err


def test_json_output_is_parseable(monkeypatch, capsys):
    feed(monkeypatch, STRONG + "\n")
    main(["--offline", "--stdin", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["length"] == len(STRONG)
    assert payload["breach"]["checked"] is False
    assert payload["score"] >= 80
    assert STRONG not in json.dumps(payload)


def test_breached_password_exits_breached(monkeypatch, capsys):
    import password_auditor.auditor as auditor_module
    from password_auditor.hibp import BreachResult

    monkeypatch.setattr(
        auditor_module,
        "check_password",
        lambda password, **kwargs: BreachResult(prefix="5BAA6", count=9, candidates=800),
    )
    feed(monkeypatch, STRONG + "\n")
    assert main(["--stdin"]) == EXIT_BREACHED
    out = capsys.readouterr().out
    assert "FOUND in breach data" in out
    assert "5BAA6" in out  # the prefix we sent is disclosed for transparency


def test_no_color_flag_and_env(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert use_color(True) is False
    monkeypatch.setenv("NO_COLOR", "1")
    assert use_color(False) is False
