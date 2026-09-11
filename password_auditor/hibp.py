"""Have I Been Pwned "Pwned Passwords" lookup using the k-anonymity model.

What leaves this machine, and nothing else:

* The password is hashed locally with SHA-1.
* Only the **first 5 hex characters** of that hash (20 bits) are put in the
  request URL.
* The API replies with every known hash **suffix** sharing that prefix, along
  with how many times each appeared in a breach corpus. As of writing, a prefix
  matches on the order of 800 hashes, so the server learns only that your
  password is one of ~800 candidates.
* The suffix comparison happens locally, in
  :func:`check_password`.

The plaintext password, the full hash, and the answer never leave the process.
The request is also sent with ``Add-Padding: true``, which makes the API return
a randomised number of zero-count filler records so that an observer who can
see the encrypted response size cannot infer how many real hashes the prefix
had. Filler records are dropped locally because a genuine breach entry always
has a count of at least 1.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - import only for type checkers
    import requests

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
PREFIX_LENGTH = 5
USER_AGENT = "password-auditor/1.0 (+https://github.com/; local CLI password audit)"
DEFAULT_TIMEOUT = 10.0


class HibpError(RuntimeError):
    """The breach lookup could not be completed (network, DNS, HTTP error)."""


def _load_requests():
    """Import ``requests`` on demand so offline scoring needs no dependencies.

    Raises:
        HibpError: if the package is not installed.
    """
    try:
        import requests
    except ModuleNotFoundError as exc:  # pragma: no cover - environment issue
        raise HibpError(
            "the 'requests' package is not installed - run "
            "'py -m pip install requests', or pass --offline to skip this check"
        ) from exc
    return requests


@dataclass(frozen=True)
class BreachResult:
    """Outcome of a k-anonymity breach lookup.

    Attributes:
        prefix: The 5-character hash prefix that was sent. Safe to display.
        count: Times the password appears in the breach corpus (0 if absent).
        candidates: How many real hash suffixes the prefix bucket returned;
            this is the size of the anonymity set the server saw.
    """

    prefix: str
    count: int
    candidates: int

    @property
    def breached(self) -> bool:
        return self.count > 0


def sha1_hex(password: str) -> str:
    """Return the uppercase SHA-1 hex digest of ``password``.

    SHA-1 is used because that is the digest the Pwned Passwords corpus is
    keyed by. It is a lookup key here, not password storage.
    """
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def split_hash(digest: str) -> tuple[str, str]:
    """Split a hex digest into the prefix that is sent and the suffix kept local."""
    return digest[:PREFIX_LENGTH], digest[PREFIX_LENGTH:]


def fetch_range(
    prefix: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    session: requests.Session | None = None,
) -> str:
    """Fetch the raw ``suffix:count`` body for a hash ``prefix``.

    Raises:
        HibpError: on any transport or HTTP failure.
    """
    headers = {
        "User-Agent": USER_AGENT,
        # Ask for filler records so response size does not leak bucket size.
        "Add-Padding": "true",
    }
    requests = _load_requests()
    get = session.get if session is not None else requests.get
    try:
        response = get(API_URL.format(prefix=prefix), headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        raise HibpError(f"could not reach the Pwned Passwords API: {exc}") from exc

    if response.status_code != 200:
        raise HibpError(
            f"Pwned Passwords API returned HTTP {response.status_code} for prefix {prefix}"
        )
    return response.text


def parse_range(body: str, suffix: str) -> tuple[int, int]:
    """Find ``suffix`` in an API range response.

    Returns:
        ``(count, candidates)`` where ``count`` is 0 if the suffix is absent and
        ``candidates`` counts the real (non-padding) suffixes in the bucket.
    """
    count = 0
    candidates = 0
    target = suffix.upper()
    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        found_suffix, _, found_count = line.partition(":")
        try:
            occurrences = int(found_count.replace(",", ""))
        except ValueError:
            continue
        if occurrences <= 0:
            continue  # padding record added by Add-Padding
        candidates += 1
        if found_suffix.upper() == target:
            count = occurrences
    return count, candidates


def check_password(
    password: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    session: requests.Session | None = None,
) -> BreachResult:
    """Check ``password`` against Pwned Passwords without disclosing it.

    Raises:
        HibpError: if the lookup could not be completed.
    """
    prefix, suffix = split_hash(sha1_hex(password))
    body = fetch_range(prefix, timeout=timeout, session=session)
    count, candidates = parse_range(body, suffix)
    return BreachResult(prefix=prefix, count=count, candidates=candidates)
