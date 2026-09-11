"""Click-to-run entry point: opens the Password Auditor desktop window.

PyCharm's green arrow runs this file. The terminal version is still there:

    py -m password_auditor            # hidden prompt, text report
    py -m password_auditor --json     # machine-readable
    py main.py --cli                  # same, from this file

Requires Tkinter, which ships with the standard Windows and macOS Python
installers. On Linux, install it with your package manager (for example
``apt install python3-tk``).
"""

from __future__ import annotations

import sys


def main() -> int:
    if "--cli" in sys.argv[1:]:
        from password_auditor.cli import main as cli_main

        return cli_main([arg for arg in sys.argv[1:] if arg != "--cli"])

    try:
        from password_auditor.gui import run
    except ImportError as exc:  # Tkinter missing
        print(f"Could not start the window ({exc}).", file=sys.stderr)
        print("Falling back to the terminal version.\n", file=sys.stderr)
        from password_auditor.cli import main as cli_main

        return cli_main(sys.argv[1:])

    return run()


if __name__ == "__main__":
    raise SystemExit(main())
