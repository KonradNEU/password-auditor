"""Command-line interface for Password Auditor.

The password is read with :func:`getpass.getpass` (or from stdin when piped),
never from ``argv``, so it does not end up in shell history, in ``ps`` output,
or in a terminal scrollback.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from password_auditor import __version__
from password_auditor.auditor import audit
from password_auditor.report import render_json, render_text

# Exit codes, so the tool is usable in scripts and CI.
EXIT_OK = 0
EXIT_WEAK = 1
EXIT_BREACHED = 2
EXIT_USAGE = 3
EXIT_INTERRUPTED = 130

PASS_THRESHOLD = 60  # "Strong" or better


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-auditor",
        description=(
            "Audit a password's strength offline and check it against the Have I "
            "Been Pwned corpus using k-anonymity (only the first 5 characters of "
            "its SHA-1 hash are ever sent)."
        ),
        epilog=(
            "The password is never accepted as a command-line argument, so it "
            "cannot leak through shell history or the process list."
        ),
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="skip the breach lookup entirely; score locally only",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="read the password from stdin instead of prompting (for pipelines)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a JSON report instead of the text report",
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="prompt twice and require both entries to match",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="HTTP timeout for the breach lookup (default: 10)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colour in the text report",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"password-auditor {__version__}",
    )
    return parser


def read_password(*, from_stdin: bool, confirm: bool) -> str:
    """Obtain the password without exposing it to argv or the terminal."""
    if from_stdin:
        # rstrip only the trailing newline: trailing spaces can be meaningful.
        return sys.stdin.readline().rstrip("\r\n")

    if sys.stdin.isatty():
        password = getpass.getpass("Password (input hidden): ")
        if confirm:
            again = getpass.getpass("Confirm password: ")
            if password != again:
                raise ValueError("the two entries did not match")
        return password

    # Not a terminal: an IDE run window, or piped input. getpass cannot hide
    # input here, so prompt visibly and say why, rather than sitting silent on
    # a blank line and looking like a hang.
    print(
        "Note: this console cannot hide input, so what you type will be visible.\n"
        "      For a hidden prompt, run from a real terminal, or tick 'Emulate\n"
        "      terminal in output console' in your run configuration.",
        file=sys.stderr,
    )
    print("Password (visible): ", end="", file=sys.stderr, flush=True)
    line = sys.stdin.readline()
    if not line:
        raise EOFError("no input received")
    return line.rstrip("\r\n")


def use_color(no_color_flag: bool) -> bool:
    """Colour unless disabled, not a tty, or NO_COLOR is set."""
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        password = read_password(from_stdin=args.stdin, confirm=args.confirm)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return EXIT_INTERRUPTED
    except (ValueError, EOFError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if not password:
        print("error: no password provided", file=sys.stderr)
        return EXIT_USAGE

    try:
        result = audit(
            password,
            check_breach=not args.offline,
            timeout=args.timeout,
        )
    finally:
        # Drop the only reference we hold; CPython cannot guarantee the bytes
        # are scrubbed from memory, but we do not keep them alive ourselves.
        del password

    if args.json:
        print(render_json(result))
    else:
        print(render_text(result, color=use_color(args.no_color)))

    if result.breached:
        return EXIT_BREACHED
    if result.score < PASS_THRESHOLD:
        return EXIT_WEAK
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
