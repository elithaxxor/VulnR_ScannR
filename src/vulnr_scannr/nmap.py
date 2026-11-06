"""Nmap orchestration and offline parsing of nmap output."""

from __future__ import annotations

import logging
import os
import re
import xml.etree.ElementTree as ET  # noqa: S405 - parses local nmap output only
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any

from vulnr_scannr.db import Database
from vulnr_scannr.tools import ToolNotFoundError, resolve_tool, run_tool
from vulnr_scannr.validation import (
    validate_host,
    validate_network,
    validate_nse_categories,
    validate_ports,
    validate_target,
)

log = logging.getLogger("vulnr_scannr")

#: Ports checked by the legacy "advanced" nmap scan.
DEFAULT_PORTS = "21,22,23,25,53,80,139,443,445,1433,3306,3389,5900,8080,8443"

#: nmap service names that are themselves considered findings (from legacy code).
EXPOSED_SERVICE_FINDINGS = {
    "ms-sql-s": "MS SQL Server Exposed",
    "mysql": "MySQL Exposed",
    "telnet": "Telnet (Cleartext) Exposed",
    "ftp": "FTP Service Exposed",
}

NMAP_TIMEOUT = 1800

_VULN_STATE_RE = re.compile(r"\bState:\s*(LIKELY\s+)?VULNERABLE\b")


def empty_host(host: str) -> dict[str, Any]:
    return {
        "host": host,
        "vulnerabilities": [],
        "open_ports": [],
        "services": {},
        "plaintext_creds": 0,
        "missing_patches": 0,
    }


# --------------------------------------------------------------------------- discovery
def build_discovery_command(network: str, nmap: str = "nmap") -> list[str]:
    network = validate_network(network)
    return [nmap, "-p", "139,445", "--open", "-n", "-T4", "-oG", "-", "--", network]


def parse_grepable_smb_hosts(output: str) -> list[str]:
    """Extract hosts with 139/445 open from ``nmap -oG`` output."""
    hosts: set[str] = set()
    for line in output.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        parts = line.split()
        ip = parts[1]
        ports = line.split("Ports:", 1)[1]
        if "445/open/" in ports or "139/open/" in ports:
            hosts.add(ip)
    return sorted(hosts, key=_ip_sort_key)


def _ip_sort_key(ip: str) -> tuple[int, ...] | tuple[str]:
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (ip,)


def discover_smb_hosts(network: str, timeout: float = NMAP_TIMEOUT) -> list[str]:
    """Find hosts with SMB (139/445) open in ``network`` using nmap.

    The legacy socket-sweep fallback was removed: it ignored the CIDR prefix
    (always swept x.y.z.1-254). Install nmap instead.
    """
    network = validate_network(network)
    nmap = resolve_tool("nmap")
    log.info("Discovering SMB hosts in %s ...", network)
    res = run_tool(build_discovery_command(network, nmap), timeout=timeout)
    if res.timed_out:
        log.error("nmap discovery timed out after %ss", timeout)
        return []
    if not res.ok:
        log.error("nmap discovery failed (exit %s): %s", res.returncode, res.stderr.strip()[:500])
        return []
    hosts = parse_grepable_smb_hosts(res.stdout)
    log.info("Found %d SMB host(s).", len(hosts))
    for h in hosts:
        log.info("  %s", h)
    return hosts


# --------------------------------------------------------------------------- service scan
def build_scan_command(
    target: str, xml_path: str, scripts: str | None = None, ports: str = DEFAULT_PORTS, nmap: str = "nmap"
) -> list[str]:
    target = validate_target(target)
    ports = validate_ports(ports)
    cmd = [nmap, "-sV", "-p", ports, "-oX", xml_path]
    scripts = validate_nse_categories(scripts)
    if scripts:
        cmd += ["--script", scripts]
    cmd += ["--", target]
    return cmd


def parse_nmap_xml(source: str | Path) -> dict[str, dict[str, Any]]:
    """Parse nmap XML (path or XML string) into per-host finding dicts."""
    text = Path(source).read_text(encoding="utf-8") if _is_path(source) else str(source)
    if "<!DOCTYPE" in text and "<!ENTITY" in text:
        raise ValueError("refusing to parse XML containing entity declarations")
    root = ET.fromstring(text)  # noqa: S314  # nosec B314
    results: dict[str, dict[str, Any]] = {}
    for host_el in root.findall("host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address")
        if addr_el is None:
            continue
        host = addr_el.get("addr", "")
        data = results.setdefault(host, empty_host(host))
        for port in host_el.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port.get("portid", "0"))
            if portid not in data["open_ports"]:
                data["open_ports"].append(portid)
            svc = port.find("service")
            name = svc.get("name", "") if svc is not None else ""
            data["services"][str(portid)] = name
            finding = EXPOSED_SERVICE_FINDINGS.get(name)
            if finding and finding not in data["vulnerabilities"]:
                data["vulnerabilities"].append(finding)
        for script in host_el.findall(".//script"):
            sid = script.get("id", "")
            out = script.get("output", "")
            if _VULN_STATE_RE.search(out) or ("VULNERABLE" in out and "NOT VULNERABLE" not in out):
                name = sid.removeprefix("vuln-").upper()
                if name not in data["vulnerabilities"]:
                    data["vulnerabilities"].append(name)
            low = out.lower()
            if sid == "smb2-security-mode" and "not required" in low:
                _add(data, "SMB Signing Disabled")
            if sid == "smb-protocols" and ("nt lm 0.12" in low or "smbv1" in low):
                _add(data, "SMBv1 Enabled")
            if "default credential" in low or "default password" in low:
                data["plaintext_creds"] += 1
                _add(data, "Default Credentials")
            if sid == "ftp-anon" and "anonymous ftp login allowed" in low:
                _add(data, "Anonymous FTP Access")
    for d in results.values():
        d["open_ports"].sort()
    return results


def _add(data: dict[str, Any], finding: str) -> None:
    if finding not in data["vulnerabilities"]:
        data["vulnerabilities"].append(finding)


def _is_path(source: str | Path) -> bool:
    if isinstance(source, Path):
        return True
    return not source.lstrip().startswith("<")


def run_scan(
    target: str,
    db: Database | None,
    scripts: str | None = None,
    ports: str = DEFAULT_PORTS,
    output_dir: str | Path = "nmap_results",
    timeout: float = NMAP_TIMEOUT,
) -> dict[str, dict[str, Any]]:
    target = validate_target(target)
    nmap = resolve_tool("nmap")
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = target.replace("/", "_").replace(":", "_")
    xml_path = str(out_dir / f"nmap_{stamp}_{safe}.xml")
    cmd = build_scan_command(target, xml_path, scripts, ports, nmap)
    log.info("[nmap] scanning %s (scripts=%s)", target, scripts or "none")
    res = run_tool(cmd, timeout=timeout)
    if db is not None:
        db.add_nmap_scan(target, " ".join(cmd[1:]), os.path.abspath(xml_path))
    if res.timed_out:
        log.error("[nmap] %s timed out after %ss", target, timeout)
        return {}
    if not res.ok:
        log.error("[nmap] %s failed (exit %s): %s", target, res.returncode, res.stderr.strip()[:500])
        return {}
    try:
        return parse_nmap_xml(Path(xml_path))
    except (OSError, ET.ParseError, ValueError) as exc:
        log.error("[nmap] could not parse %s: %s", xml_path, exc)
        return {}


def run_parallel_scans(
    targets: list[str],
    db: Database | None,
    scripts: str | None = None,
    ports: str = DEFAULT_PORTS,
    workers: int = 4,
    output_dir: str | Path = "nmap_results",
    timeout: float = NMAP_TIMEOUT,
) -> dict[str, dict[str, Any]]:
    targets = [validate_target(t) for t in targets]
    resolve_tool("nmap")  # fail fast before spawning threads
    merged: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 16))) as pool:
        futures = [pool.submit(run_scan, t, db, scripts, ports, output_dir, timeout) for t in targets]
        for fut in futures:
            merged.update(fut.result())
    return merged


__all__ = [
    "DEFAULT_PORTS",
    "ToolNotFoundError",
    "build_discovery_command",
    "build_scan_command",
    "discover_smb_hosts",
    "empty_host",
    "parse_grepable_smb_hosts",
    "parse_nmap_xml",
    "run_parallel_scans",
    "run_scan",
    "validate_host",
]
