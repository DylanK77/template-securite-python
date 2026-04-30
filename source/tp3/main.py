"""Compatibility entrypoint for `python -m source.tp3.main`."""

from src.tp3.main import main


if __name__ == "__main__":
    raise SystemExit(main())
