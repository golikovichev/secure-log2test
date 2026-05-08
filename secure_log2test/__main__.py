"""Allow `python -m secure_log2test` invocation."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
