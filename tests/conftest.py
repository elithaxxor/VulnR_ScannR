from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def db(tmp_path):
    from vulnr_scannr.db import Database

    return Database(tmp_path / "test.db")


@pytest.fixture(autouse=True)
def _no_real_subprocess(monkeypatch):
    """Guard: tests must never launch real scanning tools."""
    import subprocess

    real_run = subprocess.run

    def guarded(argv, *a, **kw):
        exe = Path(str(argv[0])).name if isinstance(argv, (list, tuple)) else str(argv)
        if exe in {
            "nmap",
            "msfconsole",
            "smbclient",
            "rpcclient",
            "nxc",
            "netexec",
            "crackmapexec",
            "enum4linux",
            "enum4linux-ng",
            "lookupsid.py",
            "impacket-lookupsid",
        }:
            raise AssertionError(f"test attempted to run real tool: {argv}")
        return real_run(argv, *a, **kw)

    monkeypatch.setattr(subprocess, "run", guarded)
