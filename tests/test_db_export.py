import csv
import json
import sqlite3
import xml.etree.ElementTree as ET

import pytest

from vulnr_scannr import export
from vulnr_scannr.db import Database


def _seed(db):
    db.add_score(
        "10.0.0.1",
        {"open_port_count": 1, "vuln_count": 1, "high_risk_count": 0, "plaintext_creds": 0, "missing_patches": 0},
        60,
        "Medium",
    )
    db.add_recommendations(
        "<script>alert(1)</script>",
        [{"severity": "HIGH", "finding": "=cmd|' /C calc'!A0", "remediation": "fix", "reference": "https://x"}],
    )


def test_migrates_legacy_schema(tmp_path):
    p = tmp_path / "legacy.db"
    c = sqlite3.connect(p)
    c.execute(
        "CREATE TABLE vulnerability_scores (id INTEGER PRIMARY KEY, timestamp TEXT, host TEXT, open_ports INT,"
        " vulnerabilities INT, high_risk_ports INT, plaintext_creds INT, missing_patches INT,"
        " final_score INT, risk_category TEXT)"
    )
    c.commit()
    c.close()
    db = Database(p)
    _seed(db)
    assert db.latest_scores()[0]["cvss_score"] == 0


def test_rows_rejects_unknown_table(db):
    with pytest.raises(ValueError):
        db.rows("sqlite_master; DROP TABLE logs")


def test_export_formats(db, tmp_path):
    _seed(db)
    files = export.export_tables(db, tmp_path / "ex")
    names = {f.name for f in files}
    assert {"vulnerability_scores.csv", "vulnerability_scores.json", "vulnerability_scores.xml"} <= names
    rows = list(csv.DictReader(open(tmp_path / "ex" / "remediation_recommendations.csv")))
    assert rows[0]["finding"].startswith("'=")  # formula injection neutralised
    assert json.loads((tmp_path / "ex" / "vulnerability_scores.json").read_text())[0]["host"] == "10.0.0.1"
    root = ET.parse(tmp_path / "ex" / "vulnerability_scores.xml").getroot()
    assert root.find("record/host").text == "10.0.0.1"


def test_html_report_escapes(db, tmp_path):
    _seed(db)
    p = export.render_html_report(db, tmp_path / "r.html")
    text = p.read_text()
    assert "<script>alert(1)</script>" not in text and "&lt;script&gt;" in text
    assert "10.0.0.1" in text


def test_plot(db, tmp_path):
    pytest.importorskip("matplotlib")
    assert export.plot_scores(db, tmp_path / "p.png") is None  # empty db
    _seed(db)
    p = export.plot_scores(db, tmp_path / "p.png")
    assert p and p.stat().st_size > 0
