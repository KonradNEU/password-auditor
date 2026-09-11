"""Allow `python -m password_auditor`."""

from password_auditor.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
