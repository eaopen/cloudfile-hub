"""Explicit worker entry point; importing the application starts no worker."""

from .runtime import main

if __name__ == "__main__":
    raise SystemExit(main())
