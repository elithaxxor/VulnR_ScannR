"""Command line interface for VulnR_ScannR.

Nothing touches the network unless a network subcommand is given **and**
``--authorized`` is passed. ``--help``/``--version``/import never scan.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from vulnr_scannr import __version__
from vulnr_scannr.db import DEFAULT_DB, EXPORT_TABLES
from vulnr_scannr.tools import KNOWN_TOOLS, ToolNotFoundError
from vulnr_scannr.ui import Style, phase
from vulnr_scannr.validation import DEFAULT_MAX_ADDRESSES, ValidationError

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_MISSING_TOOL = 0, 1, 2, 3
NETWORK_COMMANDS = {"discover", "enumerate", "smb-intensity", "nmap", "metasploit", "scan", "schedule"}

AUTH_NOTICE = (
    "Refusing to send network traffic without --authorized. Only scan systems you own "
    "or have written permission to test."
)

log = logging.getLogger("vulnr_scannr")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnr-scannr",
        description="Authorized SMB/network exposure assessment: discovery, enumeration, "
        "nmap service checks, scoring, remediation advice and reporting.",
        epilog="Example: vulnr-scannr --authorized scan 192.168.56.0/24 --report",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-d", "--db", default=DEFAULT_DB, help=f"SQLite database path (default: {DEFAULT_DB})")
    p.add_argument("-v", "--verbose", action="store_true", help="debug output")
    p.add_argument("-q", "--quiet", action="store_true", help="only warnings and errors")
    p.add_argument(
        "--authorized",
        action="store_true",
        help="confirm you are authorized to scan the targets (required for network commands)",
    )
    p.add_argument(
        "--max-addresses",
        type=int,
        default=DEFAULT_MAX_ADDRESSES,
        help=f"largest CIDR (address count) accepted (default: {DEFAULT_MAX_ADDRESSES})",
    )
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("check-deps", help="show which optional tools/libraries are available")

    s = sub.add_parser("discover", help="find SMB hosts (139/445) in a CIDR with nmap")
    s.add_argument("network")
    s.add_argument("--enumerate", action="store_true", help="also run anonymous enumeration on found hosts")
    s.add_argument("-o", "--output", help="write findings JSON (usable with `score`)")

    s = sub.add_parser("enumerate", help="anonymous/null-session SMB enumeration of hosts")
    s.add_argument("targets", nargs="+")
    s.add_argument("-o", "--output", help="write findings JSON")

    s = sub.add_parser("smb-intensity", help="impacket enumeration at intensity 1-3 (needs [smb] extra)")
    s.add_argument("target")
    s.add_argument("--level", type=int, choices=[1, 2, 3], default=1, help="1=shares 2=+users 3=+sessions/access")
    s.add_argument("--username", default="", help="optional user (password is prompted, or VULNR_SMB_PASSWORD)")
    s.add_argument("--domain", default="", help="optional SMB domain/workgroup")

    s = sub.add_parser("nmap", help="nmap service/version scan with optional safe NSE categories")
    s.add_argument("targets", nargs="+", help="hosts/CIDRs (space or comma separated)")
    s.add_argument("--scripts", help="NSE categories: default,safe,discovery,version,vuln")
    s.add_argument("--ports", default=None, help="port list (default: common service ports)")
    s.add_argument("--workers", type=int, default=4, help="parallel nmap processes (1-16, default 4)")
    s.add_argument("--output-dir", default="nmap_results", help="directory for nmap XML files")
    s.add_argument("-o", "--output", help="write findings JSON")

    s = sub.add_parser("metasploit", help="run one allowlisted Metasploit auxiliary scanner module")
    s.add_argument("target")
    s.add_argument("--module", required=True, help="module key (see the `list-modules` command)")

    sub.add_parser("list-modules", help="list allowlisted Metasploit auxiliary modules")

    s = sub.add_parser("score", help="score findings JSON and store results")
    s.add_argument("findings", help="JSON object: {host: {vulnerabilities, open_ports, ...}}")
    s.add_argument("--no-cvss", action="store_true", help="legacy modular scoring without CVSS weighting")
    s.add_argument("--nvd", action="store_true", help="look up CVE ids via the NVD 2.0 API (network)")

    s = sub.add_parser("export", help="export DB tables to CSV/JSON/XML")
    s.add_argument("--out-dir", default="exports", help="output directory (default: exports)")
    s.add_argument(
        "--format", action="append", choices=["csv", "json", "xml"], dest="formats", help="repeatable; default: all"
    )
    s.add_argument(
        "--table", action="append", choices=list(EXPORT_TABLES), dest="tables", help="repeatable; default: all"
    )

    s = sub.add_parser("report", help="render HTML report (and optional PNG chart)")
    s.add_argument("--html", default="reports/report.html", help="HTML output path")
    s.add_argument("--plot", action="store_true", help="also write a PNG chart (needs [plot] extra)")

    s = sub.add_parser("scan", help="full workflow: discover, enumerate, nmap, score, export")
    _add_scan_args(s)

    s = sub.add_parser("schedule", help="run the full workflow daily/weekly (foreground)")
    _add_scan_args(s, "accepted for compatibility; scheduled runs always write exports and the HTML report")
    s.add_argument("--frequency", choices=["daily", "weekly"], required=True)
    s.add_argument("--time", default="03:00", help="HH:MM (default 03:00; weekly runs Monday)")

    sub.add_parser("menu", help="interactive menu (legacy UI)")
    return p


def _add_scan_args(
    s: argparse.ArgumentParser, report_help: str = "write exports/ and reports/report.html when done"
) -> None:
    s.add_argument("network")
    s.add_argument("--scripts", default="default,safe", help="NSE categories (default: default,safe)")
    s.add_argument("--no-cvss", action="store_true", help="legacy scoring without CVSS weighting")
    s.add_argument("--report", action="store_true", help=report_help)


# --------------------------------------------------------------------------- helpers
def _write_json(path: str | None, data: Any) -> None:
    if path:
        Path(path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        log.info("Findings written to %s", path)


def _merge(into: dict[str, dict[str, Any]], new: dict[str, dict[str, Any]]) -> None:
    for host, data in new.items():
        cur = into.setdefault(
            host, {"host": host, "vulnerabilities": [], "open_ports": [], "plaintext_creds": 0, "missing_patches": 0}
        )
        for v in data.get("vulnerabilities", []):
            if v not in cur["vulnerabilities"]:
                cur["vulnerabilities"].append(v)
        cur["open_ports"] = sorted(set(cur["open_ports"]) | set(data.get("open_ports", [])))
        cur["plaintext_creds"] = max(cur["plaintext_creds"], data.get("plaintext_creds", 0))
        cur["missing_patches"] = max(cur["missing_patches"], data.get("missing_patches", 0))
        for k in ("shares", "services"):
            if k in data:
                cur[k] = data[k]


def check_deps() -> dict[str, Any]:
    from vulnr_scannr.smb import impacket_available
    from vulnr_scannr.tools import tool_status

    status: dict[str, Any] = {"tools": tool_status()}
    try:
        import matplotlib  # noqa: F401

        plot = True
    except ImportError:
        plot = False
    status["python"] = {"impacket (smb extra)": impacket_available(), "matplotlib (plot extra)": plot}
    return status


def run_workflow(network: str, db: Any, scripts: str | None, use_cvss: bool, report: bool, max_addresses: int) -> dict:
    from vulnr_scannr import export, nmap, scoring, smb
    from vulnr_scannr.validation import validate_network

    network = validate_network(network, max_addresses)
    total = 5 if report else 4
    findings: dict[str, dict[str, Any]] = {}
    log.info(phase(1, total, f"Discovering SMB hosts in {network}"))
    hosts = nmap.discover_smb_hosts(network)
    if not hosts:
        log.warning("No SMB hosts discovered in %s.", network)
        return {}
    log.info(phase(2, total, f"Enumerating {len(hosts)} SMB host(s)"))
    _merge(findings, smb.enumerate_lan_hosts(hosts))
    log.info(phase(3, total, f"nmap service scan of {len(hosts)} host(s)"))
    _merge(findings, nmap.run_parallel_scans(hosts, db, scripts=scripts))
    log.info(phase(4, total, f"Scoring {len(findings)} host(s)"))
    summary = scoring.score_hosts(findings, db, use_cvss=use_cvss)
    if report:
        log.info(phase(5, total, "Writing exports and HTML report"))
        export.export_tables(db)
        export.render_html_report(db)
    return summary


def _print_summary(summary: dict[str, dict[str, Any]]) -> None:
    st = Style(sys.stdout)
    if not summary:
        print("No hosts scored.")
        return
    print(st.header(f"{'HOST':<40} {'SCORE':>5}  RISK"))
    for host, s in sorted(summary.items(), key=lambda kv: kv[1]["score"]):
        print(f"{host:<40} {s['score']:>5}  {st.risk(s['category'])}")


# --------------------------------------------------------------------------- main
def _err(msg: str) -> None:
    print(Style(sys.stderr).error("error: ") + msg, file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return EXIT_USAGE

    from vulnr_scannr.logging_setup import setup_logging

    if args.command in ("check-deps", "list-modules"):
        setup_logging(None, args.verbose, args.quiet)
        return _dispatch_offline(args)

    if args.command in NETWORK_COMMANDS and not args.authorized:
        print(AUTH_NOTICE, file=sys.stderr)
        return EXIT_USAGE

    from vulnr_scannr.db import Database

    try:
        db = Database(args.db)
    except Exception as exc:  # noqa: BLE001
        _err(f"cannot open database {args.db}: {exc}")
        return EXIT_ERROR
    setup_logging(db, args.verbose, args.quiet)
    try:
        return _dispatch(args, db)
    except ValidationError as exc:
        _err(str(exc))
        return EXIT_USAGE
    except ToolNotFoundError as exc:
        _err(f"{exc}\nRun `vulnr-scannr check-deps` to see which tools are available.")
        return EXIT_MISSING_TOOL
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        _err(str(exc))
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


def _dispatch_offline(args: argparse.Namespace) -> int:
    if args.command == "list-modules":
        from vulnr_scannr.metasploit import ALLOWED_MODULES

        for k, v in ALLOWED_MODULES.items():
            print(f"{k:<16} {v}")
        return EXIT_OK
    status = check_deps()
    st = Style(sys.stdout)
    print(st.header("External tools:"))
    for name, path in status["tools"].items():
        alts = "/".join(KNOWN_TOOLS[name])
        mark = st.ok("OK ") if path else st.warn("-- ")
        print(f"  {mark} {name:<12} {path or 'not found (' + alts + ')'}")
    print(st.header("Optional Python packages:"))
    for name, ok in status["python"].items():
        print(f"  {st.ok('OK ') if ok else st.warn('-- ')} {name}")
    return EXIT_OK


def _dispatch(args: argparse.Namespace, db: Any) -> int:  # noqa: C901 - flat command switch
    from vulnr_scannr import export, metasploit, nmap, scoring, smb
    from vulnr_scannr.validation import validate_host, validate_network, validate_targets

    cmd = args.command
    if cmd == "discover":
        net = validate_network(args.network, args.max_addresses)
        hosts = nmap.discover_smb_hosts(net)
        data: dict[str, Any] = {h: nmap.empty_host(h) for h in hosts}
        if args.enumerate and hosts:
            data = smb.enumerate_lan_hosts(hosts)
        for h in hosts:
            print(h)
        _write_json(args.output, data)
        return EXIT_OK
    if cmd == "enumerate":
        hosts = [validate_host(t) for t in args.targets]
        data = smb.enumerate_lan_hosts(hosts)
        _write_json(args.output, data)
        print(json.dumps(data, indent=2))
        return EXIT_OK
    if cmd == "smb-intensity":
        password = ""
        if args.username:
            password = os.environ.get("VULNR_SMB_PASSWORD") or getpass.getpass("SMB password: ")
        result = smb.enumerate_with_intensity(args.target, args.level, args.username, password, args.domain)
        print(json.dumps(result, indent=2, default=str))
        return EXIT_OK
    if cmd == "nmap":
        targets = validate_targets(",".join(args.targets), args.max_addresses)
        data = nmap.run_parallel_scans(
            targets,
            db,
            scripts=args.scripts,
            ports=args.ports or nmap.DEFAULT_PORTS,
            workers=args.workers,
            output_dir=args.output_dir,
        )
        _write_json(args.output, data)
        print(json.dumps(data, indent=2))
        return EXIT_OK
    if cmd == "metasploit":
        validate_targets(args.target, args.max_addresses)
        metasploit.run_module(args.target, args.module, db)
        return EXIT_OK
    if cmd == "score":
        findings = json.loads(Path(args.findings).read_text(encoding="utf-8"))
        lookup = None
        if args.nvd:
            from vulnr_scannr.nvd import lookup_cvss

            lookup = lookup_cvss
        summary = scoring.score_hosts(findings, db, use_cvss=not args.no_cvss, lookup=lookup)
        _print_summary(summary)
        return EXIT_OK
    if cmd == "export":
        files = export.export_tables(
            db, args.out_dir, tuple(args.formats or export.FORMATS), tuple(args.tables or EXPORT_TABLES)
        )
        for f in files:
            print(f)
        return EXIT_OK
    if cmd == "report":
        print(export.render_html_report(db, args.html))
        if args.plot:
            png = export.plot_scores(db)
            if png:
                print(png)
        return EXIT_OK
    if cmd == "scan":
        summary = run_workflow(args.network, db, args.scripts, not args.no_cvss, args.report, args.max_addresses)
        _print_summary(summary)
        return EXIT_OK
    if cmd == "schedule":
        from vulnr_scannr.scheduler import run_forever
        from vulnr_scannr.validation import validate_nse_categories, validate_time_of_day

        hh, mm = validate_time_of_day(args.time)
        net = validate_network(args.network, args.max_addresses)
        scripts = validate_nse_categories(args.scripts)
        run_forever(
            lambda: _print_summary(run_workflow(net, db, scripts, not args.no_cvss, True, args.max_addresses)),
            hh,
            mm,
            args.frequency,
        )
        return EXIT_OK
    if cmd == "menu":
        from vulnr_scannr.menu import run_menu

        return run_menu(db, authorized=args.authorized, max_addresses=args.max_addresses)
    raise AssertionError(f"unhandled command {cmd}")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
