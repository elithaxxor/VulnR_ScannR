#!/usr/bin/env python3
"""Isolated-lab validation helpers. See docs/LAB_TESTING.md.

python scripts/lab_validate.py flags              # offline
python scripts/lab_validate.py replay tests/fixtures   # offline
python scripts/lab_validate.py capture 192.168.56.10 --authorized   # lab only
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vulnr_scannr.lab import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
