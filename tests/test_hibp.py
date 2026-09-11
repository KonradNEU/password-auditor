"""Tests for the k-anonymity breach lookup.

These never touch the network: a fake session stands in for ``requests``.
"""

import pytest
import requests

from password_auditor.hibp import (
    PREFIX_LENGTH,
    BreachResult,
    HibpError,
    check_password,
    fetch_range,
    parse_range,
    sha1_hex,
    split_hash,
)

# Published SHA-1 of "password"; useful precisely because it is not a secret.
PASSWORD_SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


class FakeResponse:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code


class FakeSession:
    """Records the outgoing request so the test can assert on what was sent."""

    def __init__(self, response=None, raises=None):
        self.response = response or FakeResponse()
        self.raises = raises
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append({"url": url, "headers": headers or {}, "timeout": timeout})
        if self.raises is not None:
            raise self.raises
        return self.response


def test_sha1_matches_published_digest():
    assert sha1_hex("password") == PASSWORD_SHA1
    assert sha1_hex("password").isupper()


def test_split_hash_sends_only_five_characters():
    prefix, suffix = split_hash(PASSWORD_SHA1)
    assert prefix == "5BAA6"
    assert len(prefix) == PREFIX_LENGTH
    assert suffix == PASSWORD_SHA1[PREFIX_LENGTH:]
    assert prefix + suffix == PASSWORD_SHA1


def test_parse_range_finds_the_suffix():
    body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\nAAAAAAAAAA:12\r\n"
    count, candidates = parse_range(body, PASSWORD_SHA1[PREFIX_LENGTH:])
    assert count == 9659365
    assert candidates == 2


def test_parse_range_is_case_insensitive():
    body = "1e4c9b93f3f0682250b6cf8331b7ee68fd8:5\r\n"
    count, _ = parse_range(body, PASSWORD_SHA1[PREFIX_LENGTH:])
    assert count == 5


def test_parse_range_absent_suffix():
    count, candidates = parse_range("ABCDEF:3\r\nFEDCBA:1\r\n", "0" * 35)
    assert count == 0
    assert candidates == 2


def test_parse_range_ignores_padding_and_junk():
    body = "AAAA:0\r\nBBBB:0\r\nCCCC:7\r\nnot-a-line\r\n\r\nDDDD:notanumber\r\n"
    count, candidates = parse_range(body, "CCCC")
    assert count == 7
    assert candidates == 1  # zero-count padding records are not candidates


def test_fetch_range_sends_prefix_only_and_requests_padding():
    session = FakeSession(FakeResponse("AAAA:1\r\n"))
    fetch_range("5BAA6", session=session)
    call = session.calls[0]
    assert call["url"].endswith("/range/5BAA6")
    assert PASSWORD_SHA1 not in call["url"]
    assert "password" not in call["url"]
    assert call["headers"]["Add-Padding"] == "true"
    assert "User-Agent" in call["headers"]


def test_fetch_range_raises_on_http_error():
    session = FakeSession(FakeResponse("nope", status_code=503))
    with pytest.raises(HibpError):
        fetch_range("5BAA6", session=session)


def test_fetch_range_raises_on_transport_error():
    session = FakeSession(raises=requests.ConnectionError("dns failure"))
    with pytest.raises(HibpError):
        fetch_range("5BAA6", session=session)


def test_check_password_reports_a_breach():
    body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\nAAAA:0\r\n"
    session = FakeSession(FakeResponse(body))
    result = check_password("password", session=session)
    assert isinstance(result, BreachResult)
    assert result.breached
    assert result.count == 9659365
    assert result.prefix == "5BAA6"
    # The plaintext password never appears in the outgoing request.
    assert "password" not in session.calls[0]["url"]


def test_check_password_reports_a_clean_password():
    session = FakeSession(FakeResponse("0000000000000000000000000000000000A:4\r\n"))
    result = check_password("password", session=session)
    assert not result.breached
    assert result.count == 0
    assert result.candidates == 1
