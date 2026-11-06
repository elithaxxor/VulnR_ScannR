"""Vulnerability scoring, CVSS weighting and remediation recommendations.

Algorithm preserved from the legacy "enhanced" scorer: start at 100 and
subtract weighted penalties, clamp at 0, then bucket into a risk category.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from vulnr_scannr.db import Database

log = logging.getLogger("vulnr_scannr")

VULN_PENALTY = 15
PORT_PENALTY = 5
CREDS_PENALTY = 10
PATCH_PENALTY = 5
HIGH_RISK_PENALTY = 3
CRITICAL_VULN_PENALTY = 20
CVSS_PENALTY_FACTOR = 1
UNKNOWN_CVSS = 5.0

HIGH_RISK_PORTS = frozenset({21, 22, 23, 25, 53, 139, 445, 1433, 3306, 3389, 5900})

#: Static CVSS estimates used by the legacy tool for named findings.
VULN_CVSS_MAP: dict[str, float] = {
    "MS17-010": 9.8,
    "SMBv1 Enabled": 7.5,
    "EOL OS": 8.0,
    "Anonymous FTP Access": 5.0,
    "Default Credentials": 7.0,
    "SMB Signing Disabled": 5.8,
    "Writable Share": 6.0,
}

REMEDIATIONS: dict[str, dict[str, str]] = {
    "SMBv1 Enabled": {
        "severity": "HIGH",
        "finding": "SMBv1 Protocol Enabled",
        "remediation": "Disable SMBv1 via Group Policy, PowerShell or registry settings.",
        "reference": "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
    },
    "MS17-010": {
        "severity": "CRITICAL",
        "finding": "MS17-010 (EternalBlue) Vulnerability",
        "remediation": "Apply Microsoft security update MS17-010 immediately and disable SMBv1.",
        "reference": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
    },
    "SMB Signing Disabled": {
        "severity": "MEDIUM",
        "finding": "SMB Signing Not Required",
        "remediation": "Require SMB signing via Group Policy.",
        "reference": "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview",
    },
    "Anonymous FTP Access": {
        "severity": "HIGH",
        "finding": "Anonymous FTP Access",
        "remediation": "Disable anonymous FTP access or restrict it to read-only public data.",
        "reference": "https://cwe.mitre.org/data/definitions/284.html",
    },
    "Default Credentials": {
        "severity": "CRITICAL",
        "finding": "Default Credentials in Use",
        "remediation": "Change all default passwords and enforce a strong password policy.",
        "reference": "https://cwe.mitre.org/data/definitions/1392.html",
    },
    "EOL OS": {
        "severity": "CRITICAL",
        "finding": "End-of-Life Operating System",
        "remediation": "Upgrade to a supported operating system version.",
        "reference": "https://cwe.mitre.org/data/definitions/1104.html",
    },
    "Writable Share": {
        "severity": "HIGH",
        "finding": "Insecure File Share Permissions",
        "remediation": "Restrict share and NTFS permissions to authorized users only.",
        "reference": "https://cwe.mitre.org/data/definitions/732.html",
    },
    "Telnet (Cleartext) Exposed": {
        "severity": "HIGH",
        "finding": "Telnet Service Exposed",
        "remediation": "Disable Telnet and use SSH instead.",
        "reference": "https://cwe.mitre.org/data/definitions/319.html",
    },
}


def risk_category(score: float) -> str:
    if score >= 80:
        return "Low"
    if score >= 50:
        return "Medium"
    if score >= 20:
        return "High"
    return "Critical"


def cvss_for_findings(vulns: list[str], lookup: Callable[[str], float | None] | None = None) -> tuple[float, int]:
    """Return (total_cvss, critical_count). ``lookup`` resolves CVE ids (opt-in)."""
    import re

    total = 0.0
    critical = 0
    for v in vulns:
        base = next((k for k in VULN_CVSS_MAP if k in v), None)
        score: float | None = VULN_CVSS_MAP[base] if base else None
        if score is None and lookup is not None:
            m = re.search(r"CVE-\d{4}-\d{4,7}", v)
            if m:
                score = lookup(m.group(0))
        if score is None:
            score = UNKNOWN_CVSS
        total += score
        if score >= 9.0:
            critical += 1
    return total, critical


def calculate_score(
    host_data: dict[str, Any], use_cvss: bool = True, lookup: Callable[[str], float | None] | None = None
) -> tuple[int, str, dict[str, Any]]:
    vulns = list(host_data.get("vulnerabilities", []))
    ports = [int(p) for p in host_data.get("open_ports", [])]
    creds = int(host_data.get("plaintext_creds", 0) or 0)
    patches = int(host_data.get("missing_patches", 0) or 0)
    if use_cvss:
        cvss, critical = cvss_for_findings(vulns, lookup)
    else:
        cvss, critical = 0.0, 0
    high_risk = sum(1 for p in ports if p in HIGH_RISK_PORTS)
    score = 100.0
    score -= len(vulns) * VULN_PENALTY
    score -= len(ports) * PORT_PENALTY
    score -= creds * CREDS_PENALTY
    score -= patches * PATCH_PENALTY
    score -= critical * CRITICAL_VULN_PENALTY
    score -= cvss * CVSS_PENALTY_FACTOR
    score -= high_risk * HIGH_RISK_PENALTY
    final = max(int(round(score)), 0)
    details = {
        "vuln_count": len(vulns),
        "open_port_count": len(ports),
        "plaintext_creds": creds,
        "missing_patches": patches,
        "high_risk_count": high_risk,
        "cvss_score": round(cvss, 1),
        "critical_vulns": critical,
    }
    return final, risk_category(final), details


def recommendations_for(host_data: dict[str, Any]) -> list[dict[str, str]]:
    recs = []
    seen = set()
    for v in host_data.get("vulnerabilities", []):
        for key, rec in REMEDIATIONS.items():
            if key in v and key not in seen:
                seen.add(key)
                recs.append(dict(rec))
    return recs


def score_hosts(
    discovered: dict[str, dict[str, Any]],
    db: Database | None = None,
    use_cvss: bool = True,
    lookup: Callable[[str], float | None] | None = None,
) -> dict[str, dict[str, Any]]:
    """Score every host, persist results and recommendations, return a summary."""
    if not isinstance(discovered, dict):
        raise ValueError("scoring input must be a JSON object mapping host -> findings")
    summary: dict[str, dict[str, Any]] = {}
    for host, data in discovered.items():
        if not isinstance(data, dict):
            raise ValueError(f"findings for {host!r} must be an object")
        final, cat, details = calculate_score(data, use_cvss, lookup)
        recs = recommendations_for(data)
        log.info("[score] %s score=%s category=%s", host, final, cat)
        if db is not None:
            db.add_score(host, details, final, cat)
            if recs:
                db.add_recommendations(host, recs)
            db.add_host_findings(host, data)
        summary[host] = {"score": final, "category": cat, **details, "recommendations": recs}
    return summary
