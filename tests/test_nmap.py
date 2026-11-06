import pytest

from vulnr_scannr import nmap
from vulnr_scannr.tools import ToolResult
from vulnr_scannr.validation import ValidationError


def test_build_scan_command_is_argv_with_separator():
    cmd = nmap.build_scan_command("192.168.56.10", "out.xml", "safe,vuln")
    assert cmd == [
        "nmap",
        "-sV",
        "-p",
        nmap.DEFAULT_PORTS,
        "-oX",
        "out.xml",
        "--script",
        "safe,vuln",
        "--",
        "192.168.56.10",
    ]


@pytest.mark.parametrize("target", ["-iL /etc/passwd", "--script=exploit", "1.1.1.1;id"])
def test_build_scan_command_rejects_injection(target):
    with pytest.raises(ValidationError):
        nmap.build_scan_command(target, "o.xml")


def test_build_scan_command_rejects_intrusive_scripts():
    with pytest.raises(ValidationError):
        nmap.build_scan_command("10.0.0.1", "o.xml", "brute")


def test_discovery_command():
    assert nmap.build_discovery_command("192.168.56.0/24")[-2:] == ["--", "192.168.56.0/24"]


def test_parse_grepable(fixtures):
    out = (fixtures / "nmap_discovery.gnmap").read_text()
    assert nmap.parse_grepable_smb_hosts(out) == ["192.168.56.2", "192.168.56.10"]


def test_parse_xml(fixtures):
    res = nmap.parse_nmap_xml(fixtures / "nmap_sample.xml")
    h = res["192.168.56.10"]
    assert h["open_ports"] == [21, 445, 3306]
    assert "FTP Service Exposed" in h["vulnerabilities"]
    assert "MySQL Exposed" in h["vulnerabilities"]
    assert "Telnet (Cleartext) Exposed" not in h["vulnerabilities"]  # port closed
    assert "SMB-VULN-MS17-010" in h["vulnerabilities"]
    assert "SMB-VULN-MS10-054" not in h["vulnerabilities"]  # NOT VULNERABLE
    assert "SMB Signing Disabled" in h["vulnerabilities"]
    assert "Anonymous FTP Access" in h["vulnerabilities"]
    assert res["192.168.56.11"]["open_ports"] == [22]


def test_parse_xml_rejects_entities():
    evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>'
    with pytest.raises(ValueError):
        nmap.parse_nmap_xml(evil)


def test_discover_uses_mocked_nmap(monkeypatch, fixtures):
    calls = []
    monkeypatch.setattr(nmap, "resolve_tool", lambda n: "/usr/bin/nmap")

    def fake_run(argv, timeout):
        calls.append(argv)
        return ToolResult(argv, 0, (fixtures / "nmap_discovery.gnmap").read_text(), "")

    monkeypatch.setattr(nmap, "run_tool", fake_run)
    assert nmap.discover_smb_hosts("192.168.56.0/24") == ["192.168.56.2", "192.168.56.10"]
    assert calls[0][0] == "/usr/bin/nmap" and calls[0][-1] == "192.168.56.0/24"


def test_discover_handles_failure_and_timeout(monkeypatch):
    monkeypatch.setattr(nmap, "resolve_tool", lambda n: "nmap")
    monkeypatch.setattr(nmap, "run_tool", lambda argv, timeout: ToolResult(argv, 1, "", "boom"))
    assert nmap.discover_smb_hosts("10.0.0.0/30") == []
    monkeypatch.setattr(nmap, "run_tool", lambda argv, timeout: ToolResult(argv, -1, "", "", True))
    assert nmap.discover_smb_hosts("10.0.0.0/30") == []


def test_run_scan_logs_and_parses(monkeypatch, tmp_path, fixtures, db):
    monkeypatch.setattr(nmap, "resolve_tool", lambda n: "nmap")

    def fake_run(argv, timeout):
        xml = argv[argv.index("-oX") + 1]
        (tmp_path / "x").mkdir(exist_ok=True)
        open(xml, "w").write((fixtures / "nmap_sample.xml").read_text())
        return ToolResult(argv, 0, "", "")

    monkeypatch.setattr(nmap, "run_tool", fake_run)
    res = nmap.run_parallel_scans(["192.168.56.10"], db, scripts="vuln", output_dir=tmp_path / "out")
    assert "192.168.56.10" in res
    rows = db.rows("nmap_scans")
    assert rows and rows[0]["target"] == "192.168.56.10" and "--script vuln" in rows[0]["command"]


def test_missing_nmap_raises(monkeypatch):
    from vulnr_scannr.tools import ToolNotFoundError

    def missing(name):
        raise ToolNotFoundError("nmap missing")

    monkeypatch.setattr(nmap, "resolve_tool", missing)
    with pytest.raises(ToolNotFoundError):
        nmap.discover_smb_hosts("10.0.0.0/30")
