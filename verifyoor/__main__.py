"""`python -m verifyoor` entry point. The CLI implementation lives in cli.py so the
console-script entry point (verifyoor.cli:main) doesn't collide with __main__."""
import sys

if __package__:
    from .cli import main
else:  # run as a loose script (some `uv run <name>` paths) — restore the import root
    import os

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from verifyoor.cli import main

if __name__ == "__main__":
    sys.exit(main())
