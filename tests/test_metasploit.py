import pytest

from vulnr_scannr import metasploit
from vulnr_scannr.tools import ToolResult
from vulnr_scannr.validation import ValidationError


def test_build_command_allowlisted():
    cmd = metasploit.build_msf_command("10.0.0.0/30", "smb_version")
    assert cmd[:4] == ["msfconsole", "-q", "-n", "-x"]
    assert cmd[4] == "use auxiliary/scanner/smb/smb_version; set RHOSTS 10.0.0.0/30; run; exit"


@pytest.mark.parametrize(
    "module",
    ["exploit/windows/smb/ms17_010_eternalblue", "auxiliary/scanner/smb/smb_login", "smb_version; exit", "../../x"],
)
def test_disallowed_modules(module):
    with pytest.raises(ValidationError):
        metasploit.build_msf_command("10.0.0.1", module)


@pytest.mark.parametrize("target", ["10.0.0.1; use exploit/x", "10.0.0.1\nrun", "-h"])
def test_target_injection_rejected(target):
    with pytest.raises(ValidationError):
        metasploit.build_msf_command(target, "smb_version")


def test_run_module_logged(monkeypatch, db):
    monkeypatch.setattr(metasploit, "resolve_tool", lambda n: "msfconsole")
    monkeypatch.setattr(metasploit, "run_tool", lambda argv, timeout: ToolResult(argv, 0, "[+] SMB 3.1.1", ""))
    out = metasploit.run_module("10.0.0.1", "smb_version", db)
    assert "SMB 3.1.1" in out
    assert db.rows("metasploit_runs")[0]["module"] == "auxiliary/scanner/smb/smb_version"
