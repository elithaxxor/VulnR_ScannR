import json

import pytest

from vulnr_scannr import scoring


def test_legacy_modular_scoring(fixtures):
    data = json.loads((fixtures / "findings.json").read_text())
    s, cat, d = scoring.calculate_score(data["192.168.56.10"], use_cvss=False)
    assert (s, cat) == (49, "High")
    assert d["high_risk_count"] == 2
    assert scoring.calculate_score(data["192.168.56.11"], use_cvss=False)[:2] == (92, "Low")


def test_enhanced_cvss_scoring(fixtures):
    data = json.loads((fixtures / "findings.json").read_text())
    s, cat, d = scoring.calculate_score(data["192.168.56.10"])
    assert d["cvss_score"] == 15.6 and d["critical_vulns"] == 1
    assert (s, cat) == (13, "Critical")


def test_score_clamped_and_categories():
    assert scoring.calculate_score({"vulnerabilities": ["x"] * 20})[0] == 0
    assert [scoring.risk_category(x) for x in (100, 80, 79, 50, 20, 19)] == [
        "Low",
        "Low",
        "Medium",
        "Medium",
        "High",
        "Critical",
    ]


def test_cve_lookup_hook():
    total, crit = scoring.cvss_for_findings(["CVE-2020-0796 SMBGhost", "Generic"], lookup=lambda c: 10.0)
    assert total == 15.0 and crit == 1


def test_recommendations():
    recs = scoring.recommendations_for({"vulnerabilities": ["SMB-VULN-MS17-010", "SMBv1 Enabled", "MS17-010"]})
    assert [r["severity"] for r in recs] == ["CRITICAL", "HIGH"]
    assert all(r["reference"].startswith("https://") for r in scoring.REMEDIATIONS.values())


def test_score_hosts_persists(db, fixtures):
    data = json.loads((fixtures / "findings.json").read_text())
    summary = scoring.score_hosts(data, db)
    assert summary["192.168.56.10"]["category"] == "Critical"
    assert len(db.rows("vulnerability_scores")) == 2
    assert db.rows("remediation_recommendations")
    assert db.latest_scores()[0]["host"] == "192.168.56.10"


def test_score_hosts_rejects_bad_input(db):
    with pytest.raises(ValueError):
        scoring.score_hosts(["not", "a", "dict"], db)
    with pytest.raises(ValueError):
        scoring.score_hosts({"h": 3}, db)
