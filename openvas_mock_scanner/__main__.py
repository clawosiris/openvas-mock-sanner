"""Command-line entry point."""

from __future__ import annotations

import sys

from .config import ConfigError, load_config
from .server import serve


def main() -> int:
    try:
        config = load_config()
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    serve(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
