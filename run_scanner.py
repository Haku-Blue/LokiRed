"""Compatibility wrapper for the LokiRed scanner CLI."""

from __future__ import annotations

import sys

from lokired import main, scan_folder


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "scan":
        sys.argv.insert(1, "scan")

    raise SystemExit(main())
