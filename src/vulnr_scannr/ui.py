"""Tiny terminal styling helpers (stdlib only).

Colour is used only when the stream is a TTY, ``NO_COLOR`` is unset and
``TERM`` is not ``dumb`` (see https://no-color.org/). ``FORCE_COLOR`` forces it
on. Output to pipes/files therefore never contains escape sequences.
"""

from __future__ import annotations

import os
import re
import sys
from typing import TextIO

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

_CODES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
}


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences (e.g. colour codes in captured tool output)."""
    return _ANSI_RE.sub("", text)


def color_enabled(stream: TextIO | None = None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    isatty = getattr(stream, "isatty", None)
    try:
        return bool(isatty and isatty())
    except (ValueError, OSError):
        return False


class Style:
    """Applies colours only when enabled for the given stream."""

    def __init__(self, stream: TextIO | None = None, enabled: bool | None = None) -> None:
        self.stream = stream or sys.stdout
        self.enabled = color_enabled(self.stream) if enabled is None else enabled

    def paint(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles:
            return text
        codes = ";".join(_CODES[s] for s in styles)
        return f"\x1b[{codes}m{text}\x1b[0m"

    # semantic helpers -------------------------------------------------
    def header(self, text: str) -> str:
        return self.paint(text, "bold", "cyan")

    def ok(self, text: str) -> str:
        return self.paint(text, "green")

    def warn(self, text: str) -> str:
        return self.paint(text, "yellow")

    def error(self, text: str) -> str:
        return self.paint(text, "bold", "red")

    def dim(self, text: str) -> str:
        return self.paint(text, "dim")

    def risk(self, category: str) -> str:
        colour = {"Low": "green", "Medium": "yellow", "High": "magenta", "Critical": "red"}.get(category)
        return self.paint(category, "bold", colour) if colour else category


def phase(step: int, total: int, label: str) -> str:
    """Plain-text phase marker such as ``[2/4] Enumerating SMB hosts``."""
    return f"[{step}/{total}] {label}"
