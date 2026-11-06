"""User-initiated Metasploit *auxiliary scanner* runs.

Restricted to an allowlist of read-only auxiliary scanner modules. Login /
brute-force modules from the legacy menu and arbitrary ``set`` options were
removed. Nothing here runs automatically; the CLI requires an explicit
subcommand plus ``--authorized``.
"""

from __future__ import annotations

import logging

from vulnr_scannr.db import Database
from vulnr_scannr.tools import resolve_tool, run_tool
from vulnr_scannr.validation import ValidationError, validate_target

log = logging.getLogger("vulnr_scannr")

#: Paths verified to exist in rapid7/metasploit-framework at commit
#: 6962ae62c99a202f2775d977ab8ab7b44121e858 (2026-11-06); see
#: tests/fixtures/upstream/metasploit.json. ``ftp/anonymous`` from the legacy
#: menu does not exist there; the module file is ``ftp/ftp_anonymous.rb``.
ALLOWED_MODULES: dict[str, str] = {
    "smb_version": "auxiliary/scanner/smb/smb_version",
    "smb_ms17_010": "auxiliary/scanner/smb/smb_ms17_010",
    "ftp_anonymous": "auxiliary/scanner/ftp/ftp_anonymous",
    "ssh_version": "auxiliary/scanner/ssh/ssh_version",
    "http_version": "auxiliary/scanner/http/http_version",
    "mysql_version": "auxiliary/scanner/mysql/mysql_version",
    "mssql_ping": "auxiliary/scanner/mssql/mssql_ping",
    "rdp_scanner": "auxiliary/scanner/rdp/rdp_scanner",
}

MSF_TIMEOUT = 900


def resolve_module(name: str) -> str:
    if name in ALLOWED_MODULES:
        return ALLOWED_MODULES[name]
    if name in ALLOWED_MODULES.values():
        return name
    raise ValidationError(f"module not allowed: {name!r} (allowed: {', '.join(ALLOWED_MODULES)})")


def build_msf_command(target: str, module: str, msfconsole: str = "msfconsole") -> list[str]:
    target = validate_target(target)
    module_path = resolve_module(module)
    script = f"use {module_path}; set RHOSTS {target}; run; exit"
    return [msfconsole, "-q", "-n", "-x", script]


def run_module(target: str, module: str, db: Database | None = None, timeout: float = MSF_TIMEOUT) -> str:
    cmd = build_msf_command(target, module, resolve_tool("msfconsole"))
    log.info("[metasploit] %s against %s", resolve_module(module), target)
    res = run_tool(cmd, timeout=timeout)
    output = res.stdout if res.ok else f"exit={res.returncode} timed_out={res.timed_out}\n{res.stdout}\n{res.stderr}"
    if not res.ok:
        log.warning("[metasploit] run did not complete cleanly (exit %s)", res.returncode)
    log.info("[metasploit] output:\n%s", output[:4000])
    if db is not None:
        db.add_metasploit_run(validate_target(target), resolve_module(module), output)
    return output
