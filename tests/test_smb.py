import sys
import types

import pytest

from vulnr_scannr import smb
from vulnr_scannr.tools import ToolNotFoundError, ToolResult


def _all_tools(monkeypatch):
    monkeypatch.setattr(smb, "resolve_tool", lambda name: f"/bin/{name}")


def test_anonymous_commands_are_readonly(monkeypatch):
    _all_tools(monkeypatch)
    cmds = smb.build_anonymous_commands("192.168.56.10")
    flat = " ".join(" ".join(c) for c in cmds.values())
    assert "--sam" not in flat and "-p" not in cmds["netexec"]
    assert cmds["smbclient"] == ["/bin/smbclient", "-L", "//192.168.56.10/", "-N", "-g"]
    assert cmds["lookupsid"][-1] == "@192.168.56.10"


def test_anonymous_commands_reject_injection():
    with pytest.raises(Exception):
        smb.build_anonymous_commands("1.2.3.4;id")


def test_parsers():
    assert smb.parse_smbclient_shares("Disk|public|x\nIPC|IPC$|ipc\nWorkgroup|WG|") == ["public", "IPC$"]
    flags = smb.parse_netexec_info("SMB 10.0.0.1 445 DC [*] Windows (signing:False) (SMBv1:True)")
    assert flags["signing_disabled"] is True and flags["smbv1"] is True


def test_enumerate_host_with_mocks(monkeypatch):
    _all_tools(monkeypatch)
    outputs = {
        "/bin/smbclient": "Disk|public|\n",
        "/bin/netexec": "SMB 10.0.0.1 445 X [*] (signing:False) (SMBv1:True)",
    }
    monkeypatch.setattr(smb, "run_tool", lambda argv, timeout: ToolResult(argv, 0, outputs.get(argv[0], ""), ""))
    data = smb.enumerate_host("10.0.0.1")
    assert data["shares"] == ["public"]
    assert {"SMB Signing Disabled", "SMBv1 Enabled"} <= set(data["vulnerabilities"])
    assert 445 in data["open_ports"]


def test_enumerate_host_without_tools(monkeypatch):
    def missing(name):
        raise ToolNotFoundError(name)

    monkeypatch.setattr(smb, "resolve_tool", missing)
    assert smb.enumerate_host("10.0.0.1")["vulnerabilities"] == []


class FakeConn:
    def __init__(self, *a, **kw):
        self.logged_in = None
        self.closed = False

    def login(self, user, pw, domain):
        self.logged_in = (user, pw, domain)

    def listShares(self):
        return [{"shi1_netname": "ADMIN$\x00"}, {"shi1_netname": "public\x00"}, {"shi1_netname": "secret\x00"}]

    def listPath(self, share, pattern):
        if share == "secret":
            raise PermissionError

    def close(self):
        self.closed = True


def test_intensity_with_fake_impacket(monkeypatch, caplog):
    mod = types.ModuleType("impacket.smbconnection")
    mod.SMBConnection = FakeConn
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", mod)
    monkeypatch.setattr(smb, "impacket_available", lambda: True)
    monkeypatch.setattr(smb, "_wkst_users", lambda c: ["alice"])
    monkeypatch.setattr(smb, "_sessions", lambda c: [])
    with caplog.at_level("DEBUG", logger="vulnr_scannr"):
        res = smb.enumerate_with_intensity("10.0.0.5", 3, "bob", "S3cretPass!", "CORP")
    assert res["shares"] == ["ADMIN$", "public", "secret"]
    assert res["accessible_shares"] == ["public"]
    assert res["logged_on_users"] == ["alice"]
    assert "S3cretPass!" not in caplog.text


def test_intensity_requires_impacket(monkeypatch):
    monkeypatch.setattr(smb, "impacket_available", lambda: False)
    with pytest.raises(ToolNotFoundError):
        smb.enumerate_with_intensity("10.0.0.5", 1)


def test_real_impacket_api_names_exist():
    pytest.importorskip("impacket")
    from impacket.dcerpc.v5 import srvs, transport, wkst
    from impacket.dcerpc.v5.dtypes import NULL  # noqa: F401
    from impacket.smbconnection import SMBConnection

    assert callable(wkst.hNetrWkstaUserEnum) and callable(srvs.hNetrSessionEnum)
    assert hasattr(SMBConnection, "getRemoteHost") and hasattr(transport, "SMBTransport")
