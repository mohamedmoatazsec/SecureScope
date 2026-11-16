"""Backwards-compatible entry point: `python cli.py <url>` still works.

The CLI now lives in `securescope/cli.py`; installing the package gives you
a `securescope` command instead.
"""

import sys

from securescope.cli import main

if __name__ == "__main__":
    sys.exit(main())
