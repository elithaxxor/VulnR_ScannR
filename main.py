#!/usr/bin/env python3
"""Legacy entry point kept for ``python main.py``; delegates to the vulnr_scannr CLI.

The previous contents of this file were a corrupted concatenation of several
script versions that did not compile; see git history (commit ffa8ff8) and
docs/MIGRATION.md.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from vulnr_scannr.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
