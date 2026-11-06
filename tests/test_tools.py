import ast
import sys

import pytest

from vulnr_scannr import tools


def test_run_tool_captures_output():
    r = tools.run_tool([sys.executable, "-c", "print('hi')"], timeout=30)
    assert r.ok and r.stdout.strip() == "hi"


def test_run_tool_never_uses_shell():
    # A shell metacharacter is passed literally as an argument, not interpreted.
    r = tools.run_tool([sys.executable, "-c", "import sys;print(sys.argv[1])", "$(echo pwned);id"], timeout=30)
    assert r.stdout.strip() == "$(echo pwned);id"


def test_run_tool_timeout():
    r = tools.run_tool([sys.executable, "-c", "import time;time.sleep(5)"], timeout=0.5)
    assert r.timed_out and not r.ok


def test_run_tool_missing_executable():
    with pytest.raises(tools.ToolNotFoundError):
        tools.run_tool(["definitely-not-a-real-tool-xyz"])


def test_resolve_tool_prefers_first_alternative(monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda n: f"/usr/bin/{n}" if n in ("nxc", "crackmapexec") else None)
    assert tools.resolve_tool("netexec") == "/usr/bin/nxc"
    with pytest.raises(tools.ToolNotFoundError, match="nmap"):
        tools.resolve_tool("nmap")
    status = tools.tool_status()
    assert status["netexec"] == "/usr/bin/nxc" and status["nmap"] is None


def test_source_has_no_shell_true():
    from pathlib import Path

    src = Path(tools.__file__).parent
    for f in src.glob("*.py"):
        text = f.read_text()
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                raise AssertionError(f"shell= keyword used in {f}")
        assert "os.system(" not in text, f
        assert '"pip"' not in text and "apt-get" not in text, f  # no runtime installs
