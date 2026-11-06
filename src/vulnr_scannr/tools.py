"""Safe wrapper around external command-line tools.

* Commands are argument lists; ``shell=True`` is never used.
* Every call has an explicit timeout.
* Missing tools raise :class:`ToolNotFoundError` instead of being installed.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass

log = logging.getLogger("vulnr_scannr")

DEFAULT_TIMEOUT = 300

#: External tools the scanner can use, mapped to alternative executable names.
KNOWN_TOOLS: dict[str, tuple[str, ...]] = {
    "nmap": ("nmap",),
    "smbclient": ("smbclient",),
    "rpcclient": ("rpcclient",),
    "enum4linux": ("enum4linux-ng", "enum4linux"),
    # CrackMapExec is archived upstream; NetExec (nxc) is its maintained successor.
    "netexec": ("nxc", "netexec", "crackmapexec"),
    "lookupsid": ("impacket-lookupsid", "lookupsid.py"),
    "msfconsole": ("msfconsole",),
}


class ToolNotFoundError(RuntimeError):
    """An external tool is not installed / not on PATH."""


@dataclass
class ToolResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def resolve_tool(name: str) -> str:
    """Return the path of the first available executable for ``name``."""
    for candidate in KNOWN_TOOLS.get(name, (name,)):
        path = shutil.which(candidate)
        if path:
            return path
    raise ToolNotFoundError(
        f"required tool '{name}' not found on PATH (looked for: "
        f"{', '.join(KNOWN_TOOLS.get(name, (name,)))}). Install it with your OS package manager."
    )


def tool_status() -> dict[str, str | None]:
    """Map each known tool to its resolved path (or None)."""
    status: dict[str, str | None] = {}
    for name in KNOWN_TOOLS:
        try:
            status[name] = resolve_tool(name)
        except ToolNotFoundError:
            status[name] = None
    return status


def run_tool(argv: Sequence[str], timeout: float = DEFAULT_TIMEOUT) -> ToolResult:
    """Run ``argv`` without a shell, capturing output, with a timeout."""
    argv = [str(a) for a in argv]
    if not argv:
        raise ValueError("empty command")
    log.debug("running: %s", " ".join(argv))
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, no shell, validated inputs
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise ToolNotFoundError(f"executable not found: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:

        def _s(v: object) -> str:
            return v.decode(errors="replace") if isinstance(v, bytes) else (v or "")  # type: ignore[return-value]

        return ToolResult(argv, -1, _s(exc.stdout), _s(exc.stderr), timed_out=True)
    return ToolResult(argv, proc.returncode, proc.stdout or "", proc.stderr or "")
