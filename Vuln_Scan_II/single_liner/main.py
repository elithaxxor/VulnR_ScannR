#!/usr/bin/env python3
"""Legacy launcher kept for path compatibility; delegates to the vulnr_scannr CLI.

The original implementation lives in git history (commit ffa8ff8); see
docs/MIGRATION.md for how its options map to the new subcommands.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from vulnr_scannr.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
