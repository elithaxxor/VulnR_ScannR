import json
import subprocess
import sys
from pathlib import Path

import pytest

from vulnr_scannr import __version__, cli

ROOT = Path(__file__).resolve().parents[1]


def test_help_and_version(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0 and __version__ in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert cli.main([]) == cli.EXIT_USAGE


@pytest.mark.parametrize(
    "cmd",
    [
        ["discover", "10.0.0.0/30"],
        ["enumerate", "10.0.0.1"],
        ["nmap", "10.0.0.1"],
        ["metasploit", "10.0.0.1", "--module", "smb_version"],
        ["scan", "10.0.0.0/30"],
        ["smb-intensity", "10.0.0.1"],
    ],
)
def test_network_commands_require_authorization(cmd, tmp_path, capsys):
    assert cli.main(["--db", str(tmp_path / "x.db"), *cmd]) == cli.EXIT_USAGE
    assert "--authorized" in capsys.readouterr().err
    assert not (tmp_path / "x.db").exists()


def test_invalid_target_exit_code(tmp_path, capsys):
    rc = cli.main(["--db", str(tmp_path / "x.db"), "--authorized", "nmap", "10.0.0.1;id"])
    assert rc == cli.EXIT_USAGE and "forbidden" in capsys.readouterr().err


def test_missing_tool_exit_code(tmp_path, monkeypatch):
    from vulnr_scannr import tools

    monkeypatch.setattr(tools.shutil, "which", lambda n: None)
    assert cli.main(["--db", str(tmp_path / "x.db"), "--authorized", "discover", "10.0.0.0/30"]) == 3


def test_offline_score_export_report(tmp_path, fixtures, capsys):
    dbp = str(tmp_path / "s.db")
    assert cli.main(["-q", "--db", dbp, "score", str(fixtures / "findings.json")]) == 0
    out = capsys.readouterr().out
    assert "192.168.56.10" in out and "Critical" in out
    assert cli.main(["-q", "--db", dbp, "export", "--out-dir", str(tmp_path / "e"), "--format", "csv"]) == 0
    assert (tmp_path / "e" / "vulnerability_scores.csv").exists()
    assert cli.main(["-q", "--db", dbp, "report", "--html", str(tmp_path / "r.html")]) == 0
    assert "VulnR_ScannR report" in (tmp_path / "r.html").read_text()


def test_score_bad_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    assert cli.main(["-q", "--db", str(tmp_path / "s.db"), "score", str(bad)]) == cli.EXIT_ERROR


def test_check_deps_and_list_modules(capsys):
    assert cli.main(["check-deps"]) == 0
    assert "External tools" in capsys.readouterr().out
    assert cli.main(["list-modules"]) == 0
    assert "smb_version" in capsys.readouterr().out


def test_full_scan_workflow_mocked(tmp_path, monkeypatch, fixtures, capsys):
    from vulnr_scannr import nmap, smb

    monkeypatch.setattr(nmap, "discover_smb_hosts", lambda net: ["192.168.56.10"])
    monkeypatch.setattr(
        smb,
        "enumerate_lan_hosts",
        lambda hosts: {"192.168.56.10": {"vulnerabilities": ["SMBv1 Enabled"], "open_ports": [445]}},
    )
    monkeypatch.setattr(
        nmap, "run_parallel_scans", lambda hosts, db, scripts=None: nmap.parse_nmap_xml(fixtures / "nmap_sample.xml")
    )
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["-q", "--db", "w.db", "--authorized", "scan", "192.168.56.0/24", "--report"])
    assert rc == 0
    assert "192.168.56.10" in capsys.readouterr().out
    assert (tmp_path / "reports" / "report.html").exists() and (tmp_path / "exports").is_dir()


def test_discover_writes_json(tmp_path, monkeypatch):
    from vulnr_scannr import nmap

    monkeypatch.setattr(nmap, "discover_smb_hosts", lambda net: ["10.0.0.2"])
    out = tmp_path / "f.json"
    assert (
        cli.main(["-q", "--db", str(tmp_path / "d.db"), "--authorized", "discover", "10.0.0.0/29", "-o", str(out)]) == 0
    )
    assert "10.0.0.2" in json.loads(out.read_text())


def test_smb_intensity_password_from_env(tmp_path, monkeypatch, capsys):
    from vulnr_scannr import smb

    seen = {}

    def fake(target, level, user, pw, domain):
        seen.update(user=user, pw=pw)
        return {"host": target}

    monkeypatch.setattr(smb, "enumerate_with_intensity", fake)
    monkeypatch.setenv("VULNR_SMB_PASSWORD", "pw-from-env")
    assert (
        cli.main(
            [
                "-q",
                "--db",
                str(tmp_path / "d.db"),
                "--authorized",
                "smb-intensity",
                "10.0.0.1",
                "--level",
                "2",
                "--username",
                "bob",
            ]
        )
        == 0
    )
    assert seen == {"user": "bob", "pw": "pw-from-env"}
    assert "pw-from-env" not in capsys.readouterr().out


def test_menu_flow(db, monkeypatch):
    from vulnr_scannr.menu import run_menu

    answers = iter(["3", "no", "5", "f.json", "8", "9", "0"])
    calls = []
    rc = run_menu(db, input_fn=lambda prompt: next(answers), runner=lambda argv: calls.append(argv) or 0)
    assert rc == 0
    assert calls[0][-2:] == ["score", "f.json"] and calls[1] == ["check-deps"]
    assert not any("nmap" in c for c in calls)  # declined authorization


@pytest.mark.parametrize(
    "script", ["main.py", "Vuln_Scan_II/modular_version/main.py", "Vuln_Scan_II/single_liner/main.py"]
)
def test_legacy_launchers_smoke(script, tmp_path):
    r = subprocess.run(
        [sys.executable, str(ROOT / script), "--version"], capture_output=True, text=True, timeout=60, cwd=tmp_path
    )
    assert r.returncode == 0 and __version__ in r.stdout
    r = subprocess.run(
        [sys.executable, str(ROOT / script), "--help"], capture_output=True, text=True, timeout=60, cwd=tmp_path
    )
    assert r.returncode == 0 and "--authorized" in r.stdout
    assert list(tmp_path.iterdir()) == []  # no DB or output created


def test_module_entrypoint_and_import_side_effects(tmp_path):
    r = subprocess.run(
        [sys.executable, "-m", "vulnr_scannr", "--version"], capture_output=True, text=True, timeout=60, cwd=tmp_path
    )
    assert r.returncode == 0
    code = "import vulnr_scannr.cli, vulnr_scannr.menu, vulnr_scannr.smb, vulnr_scannr.nmap, vulnr_scannr.export"
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert r.returncode == 0 and r.stdout == "" and list(tmp_path.iterdir()) == []
