"""SQLite persistence (schema compatible with the legacy ``smb_enum.db``)."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

DEFAULT_DB = "smb_enum.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT, level TEXT, message TEXT
);
CREATE TABLE IF NOT EXISTS nmap_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT, target TEXT, command TEXT, xml_path TEXT
);
CREATE TABLE IF NOT EXISTS metasploit_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT, target TEXT, module TEXT, output TEXT
);
CREATE TABLE IF NOT EXISTS vulnerability_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT, host TEXT, open_ports INT, vulnerabilities INT,
    high_risk_ports INT, plaintext_creds INT, missing_patches INT,
    final_score INT, risk_category TEXT,
    cvss_score REAL DEFAULT 0, critical_vulns INT DEFAULT 0
);
CREATE TABLE IF NOT EXISTS remediation_recommendations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT, host TEXT, severity TEXT, finding TEXT,
    remediation TEXT, reference TEXT
);
CREATE TABLE IF NOT EXISTS host_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT, host TEXT, data TEXT
);
"""

#: Tables that may be exported (also used as an allowlist for SQL identifiers).
EXPORT_TABLES = (
    "vulnerability_scores",
    "remediation_recommendations",
    "nmap_scans",
    "metasploit_runs",
    "host_findings",
    "logs",
)


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Database:
    def __init__(self, path: str | Path = DEFAULT_DB) -> None:
        self.path = str(path)
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate(conn)

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Add columns introduced after the legacy schema to old databases."""
        cols = {r[1] for r in conn.execute("PRAGMA table_info(vulnerability_scores)")}
        if "cvss_score" not in cols:
            conn.execute("ALTER TABLE vulnerability_scores ADD COLUMN cvss_score REAL DEFAULT 0")
        if "critical_vulns" not in cols:
            conn.execute("ALTER TABLE vulnerability_scores ADD COLUMN critical_vulns INT DEFAULT 0")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # -- writers -----------------------------------------------------------
    def log(self, level: str, message: str) -> None:
        with self.connect() as c:
            c.execute("INSERT INTO logs (timestamp, level, message) VALUES (?,?,?)", (now(), level, message))

    def add_nmap_scan(self, target: str, command: str, xml_path: str) -> None:
        with self.connect() as c:
            c.execute(
                "INSERT INTO nmap_scans (timestamp, target, command, xml_path) VALUES (?,?,?,?)",
                (now(), target, command, xml_path),
            )

    def add_metasploit_run(self, target: str, module: str, output: str) -> None:
        with self.connect() as c:
            c.execute(
                "INSERT INTO metasploit_runs (timestamp, target, module, output) VALUES (?,?,?,?)",
                (now(), target, module, output),
            )

    def add_score(self, host: str, details: dict[str, Any], final_score: int, category: str) -> None:
        with self.connect() as c:
            c.execute(
                "INSERT INTO vulnerability_scores (timestamp, host, open_ports, vulnerabilities,"
                " high_risk_ports, plaintext_creds, missing_patches, final_score, risk_category,"
                " cvss_score, critical_vulns) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    now(),
                    host,
                    details["open_port_count"],
                    details["vuln_count"],
                    details["high_risk_count"],
                    details["plaintext_creds"],
                    details["missing_patches"],
                    final_score,
                    category,
                    details.get("cvss_score", 0),
                    details.get("critical_vulns", 0),
                ),
            )

    def add_recommendations(self, host: str, recs: list[dict[str, str]]) -> None:
        with self.connect() as c:
            c.executemany(
                "INSERT INTO remediation_recommendations (timestamp, host, severity, finding,"
                " remediation, reference) VALUES (?,?,?,?,?,?)",
                [(now(), host, r["severity"], r["finding"], r["remediation"], r["reference"]) for r in recs],
            )

    def add_host_findings(self, host: str, data: dict[str, Any]) -> None:
        with self.connect() as c:
            c.execute(
                "INSERT INTO host_findings (timestamp, host, data) VALUES (?,?,?)",
                (now(), host, json.dumps(data, sort_keys=True, default=str)),
            )

    # -- readers -----------------------------------------------------------
    def rows(self, table: str) -> list[dict[str, Any]]:
        if table not in EXPORT_TABLES:
            raise ValueError(f"unknown table: {table}")
        with self.connect() as c:
            return [dict(r) for r in c.execute(f"SELECT * FROM {table} ORDER BY id")]  # noqa: S608  # nosec B608

    def latest_scores(self) -> list[dict[str, Any]]:
        with self.connect() as c:
            q = (
                "SELECT * FROM vulnerability_scores WHERE id IN "
                "(SELECT MAX(id) FROM vulnerability_scores GROUP BY host) ORDER BY final_score ASC, host"
            )
            return [dict(r) for r in c.execute(q)]
