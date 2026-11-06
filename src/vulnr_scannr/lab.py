"""Helpers for validating tool integrations in an isolated lab.

Three modes (also exposed via ``scripts/lab_validate.py``):

``flags``
    Offline. Runs each *installed* tool's local help (no network) and checks
    that every flag VulnR_ScannR passes to it is still documented.
``replay``
    Offline. Feeds saved tool output (fixtures or real lab captures) through
    the project parsers and compares with ``*.expected.json`` files.
``capture``
    Sends traffic. Requires ``--authorized`` and a single private/loopback
    lab host. Runs the same read-only commands the scanner uses and saves
    redacted output plus provenance metadata for later ``replay``.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulnr_scannr import __version__
from vulnr_scannr.logging_setup import redact
from vulnr_scannr.tools import ToolNotFoundError, resolve_tool, run_tool
from vulnr_scannr.ui import Style, strip_ansi
from vulnr_scannr.validation import ValidationError, validate_host

HELP_TIMEOUT = 120


@dataclass(frozen=True)
class FlagContract:
    """Flags VulnR_ScannR relies on for one tool, and how to print its help."""

    tool: str
    help_args: tuple[str, ...]
    required: tuple[str, ...]
    source: str


#: Every flag below is used by the scanner and was checked against the cited
#: public source on 2026-11-06. ``flags`` mode re-checks them against the
#: locally installed version.
FLAG_CONTRACTS: tuple[FlagContract, ...] = (
    FlagContract(
        "nmap",
        ("--help",),
        ("-sV", "-p", "-oX", "-oG", "--open", "-n", "-T", "--script"),
        "https://nmap.org/book/man-briefoptions.html",
    ),
    FlagContract(
        "smbclient",
        ("--help",),
        ("-L", "-N", "-g"),
        "https://www.samba.org/samba/docs/current/man-html/smbclient.1.html",
    ),
    FlagContract(
        "rpcclient",
        ("--help",),
        ("-U", "-N", "-c"),
        "https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html",
    ),
    FlagContract(
        "enum4linux",
        ("-h",),
        ("-U",),
        "https://github.com/cddmp/enum4linux-ng/blob/288826fd9ee89b61d846e59f17b77bae4fb671ee/README.md",
    ),
    FlagContract("lookupsid", ("-h",), ("-no-pass",), "impacket 0.13.1 examples/lookupsid.py (installed copy)"),
    FlagContract(
        "netexec",
        ("smb", "--help"),
        ("smb",),
        "https://github.com/Pennyw0rth/NetExec/blob/841d7fe22297a9c5789558708661430eca032766/nxc/protocols/smb.py",
    ),
    FlagContract(
        "msfconsole",
        ("-h",),
        ("-q", "-n", "-x"),
        "https://github.com/rapid7/metasploit-framework/blob/6962ae62c99a202f2775d977ab8ab7b44121e858/lib/metasploit/framework/parsed_options/",
    ),
)


@dataclass
class FlagResult:
    tool: str
    status: str  # ok | missing-flags | not-installed | help-failed
    path: str | None = None
    missing: list[str] = field(default_factory=list)
    detail: str = ""


def flag_present(help_text: str, flag: str) -> bool:
    """True if ``flag`` appears as a whole token in help output."""
    import re

    text = strip_ansi(help_text)
    return re.search(rf"(?<![\w-]){re.escape(flag)}(?![\w-])", text) is not None


def check_flags(contracts: Sequence[FlagContract] = FLAG_CONTRACTS) -> list[FlagResult]:
    results = []
    for c in contracts:
        try:
            exe = resolve_tool(c.tool)
        except ToolNotFoundError:
            results.append(FlagResult(c.tool, "not-installed"))
            continue
        res = run_tool([exe, *c.help_args], timeout=HELP_TIMEOUT)
        text = res.stdout + "\n" + res.stderr
        if res.timed_out or not text.strip():
            results.append(FlagResult(c.tool, "help-failed", exe, detail=f"exit={res.returncode}"))
            continue
        missing = [f for f in c.required if not flag_present(text, f)]
        results.append(FlagResult(c.tool, "missing-flags" if missing else "ok", exe, missing))
    return results


# --------------------------------------------------------------------------- replay
def _parse_one(kind: str, text: str) -> Any:
    from vulnr_scannr import nmap, smb

    if kind == "netexec":
        return smb.parse_netexec_info(text)
    if kind == "smbclient":
        return smb.parse_smbclient_shares(text)
    if kind == "nmap-grepable":
        return nmap.parse_grepable_smb_hosts(text)
    if kind == "nmap-xml":
        return nmap.parse_nmap_xml(text)
    raise ValueError(f"unknown fixture kind: {kind}")


KIND_BY_SUFFIX = {".nxc.txt": "netexec", ".smbclient.txt": "smbclient", ".gnmap": "nmap-grepable", ".xml": "nmap-xml"}


def fixture_kind(path: Path) -> str | None:
    for suffix, kind in KIND_BY_SUFFIX.items():
        if path.name.endswith(suffix):
            return kind
    return None


def replay(directory: Path) -> list[dict[str, Any]]:
    """Parse every recognised fixture under ``directory``; compare with ``.expected.json``."""
    out = []
    for path in sorted(directory.rglob("*")):
        kind = fixture_kind(path)
        if not kind or not path.is_file():
            continue
        parsed = _parse_one(kind, path.read_text(encoding="utf-8"))
        expected_path = path.with_name(path.name + ".expected.json")
        status = "parsed"
        if expected_path.exists():
            expected = json.loads(expected_path.read_text(encoding="utf-8"))
            status = "match" if json.loads(json.dumps(parsed)) == expected else "MISMATCH"
        out.append({"file": str(path), "kind": kind, "status": status, "parsed": parsed})
    return out


# --------------------------------------------------------------------------- capture
def validate_lab_host(value: str) -> str:
    """Accept only a single private, loopback or link-local IP address."""
    host = validate_host(value)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValidationError("lab capture needs a literal IP address, not a hostname") from exc
    if not (ip.is_private or ip.is_loopback or ip.is_link_local) or ip.is_multicast or ip.is_unspecified:
        raise ValidationError(f"{ip} is not a private/loopback lab address; refusing to capture")
    return str(ip)


def capture(host: str, out_dir: Path, with_msf: bool = False, timeout: float = 300) -> list[Path]:
    """Run read-only scanner commands against one lab host and save redacted output."""
    from vulnr_scannr import metasploit, nmap, smb

    host = validate_lab_host(host)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    jobs: dict[str, tuple[list[str], str]] = {}
    for name, argv in smb.build_anonymous_commands(host).items():
        suffix = {"netexec": ".nxc.txt", "smbclient": ".smbclient.txt"}.get(name, f".{name}.txt")
        jobs[name] = (argv, suffix)
    try:
        exe = resolve_tool("nmap")
        xml = str(out_dir / f"{stamp}_{host}.xml")
        jobs["nmap"] = (nmap.build_scan_command(host, xml, "default,safe", nmap=exe), "")
    except ToolNotFoundError:
        pass
    if with_msf:
        try:
            exe = resolve_tool("msfconsole")
            jobs["msfconsole"] = (metasploit.build_msf_command(host, "smb_version", exe), ".msf.txt")
        except ToolNotFoundError:
            pass
    written: list[Path] = []
    meta: dict[str, Any] = {
        "vulnr_scannr": __version__,
        "captured_utc": stamp,
        "host": host,
        "provenance": "real lab capture (redacted)",
        "commands": {},
    }
    for name, (argv, suffix) in jobs.items():
        res = run_tool(argv, timeout=timeout)
        meta["commands"][name] = {"argv": [redact(a) for a in argv], "exit": res.returncode, "timed_out": res.timed_out}
        if suffix:
            p = out_dir / f"{stamp}_{host}{suffix}"
            p.write_text(redact(strip_ansi(res.stdout)), encoding="utf-8")
            written.append(p)
    mp = out_dir / f"{stamp}_{host}.meta.json"
    mp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    written.append(mp)
    return written


# --------------------------------------------------------------------------- CLI
def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="lab_validate", description="Isolated-lab validation helpers for VulnR_ScannR.")
    sub = p.add_subparsers(dest="mode", required=True)
    sub.add_parser("flags", help="offline: check installed tools still accept the flags we use")
    r = sub.add_parser("replay", help="offline: parse saved outputs and compare with .expected.json")
    r.add_argument("directory", nargs="?", default="tests/fixtures")
    c = sub.add_parser("capture", help="NETWORK: capture read-only tool output from ONE private lab host")
    c.add_argument("host", help="single private/loopback IP of a lab VM you control")
    c.add_argument("--authorized", action="store_true", help="required: you own/are authorized to test the host")
    c.add_argument("--out", default="tests/fixtures/lab_captured")
    c.add_argument("--with-msf", action="store_true", help="also run auxiliary/scanner/smb/smb_version")
    args = p.parse_args(argv)
    st = Style(sys.stdout)

    if args.mode == "flags":
        results = check_flags()
        bad = 0
        for r_ in results:
            if r_.status == "ok":
                print(f"{st.ok('OK  ')} {r_.tool:<11} {r_.path}")
            elif r_.status == "not-installed":
                print(f"{st.dim('SKIP')} {r_.tool:<11} not installed")
            else:
                bad += 1
                print(f"{st.error('FAIL')} {r_.tool:<11} {r_.status} {' '.join(r_.missing)} {r_.detail}")
        return 1 if bad else 0
    if args.mode == "replay":
        results = replay(Path(args.directory))
        mismatches = 0
        for item in results:
            mark = {"match": st.ok("MATCH"), "MISMATCH": st.error("DIFF "), "parsed": st.dim("PARSE")}[item["status"]]
            mismatches += item["status"] == "MISMATCH"
            print(f"{mark} {item['kind']:<14} {item['file']}")
        print(f"{len(results)} file(s), {mismatches} mismatch(es)")
        return 1 if mismatches else 0
    if not args.authorized:
        print("capture sends network traffic; re-run with --authorized for a lab host you control.", file=sys.stderr)
        return 2
    try:
        files = capture(args.host, Path(args.out), args.with_msf)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for f in files:
        print(f)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
