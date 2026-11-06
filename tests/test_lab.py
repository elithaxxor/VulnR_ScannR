import json

import pytest

from vulnr_scannr import lab, metasploit, smb
from vulnr_scannr.tools import ToolNotFoundError, ToolResult
from vulnr_scannr.validation import ValidationError


def test_flag_present_tokenises():
    help_text = "  -U  Get users\n  -Gm groups\n  --open  only open\n -T<0-5>: timing"
    assert lab.flag_present(help_text, "-U") and lab.flag_present(help_text, "--open")
    assert lab.flag_present(help_text, "-T")
    assert not lab.flag_present(help_text, "-G") and not lab.flag_present(help_text, "-o")


def test_check_flags_with_mocked_help(monkeypatch):
    helps = {
        "nmap": "-sV -p <port ranges> -oX -oG --open -n/-R -T<0-5> --script=<Lua scripts>",
        "smbclient": "-L|--list -N|--no-pass -g|--grepable",
        "enum4linux": "-A -U -G",
        "msfconsole": "-q, --quiet  -x, --execute-command",  # -n deliberately missing
    }

    def resolve(name):
        if name not in helps:
            raise ToolNotFoundError(name)
        return name

    monkeypatch.setattr(lab, "resolve_tool", resolve)
    monkeypatch.setattr(lab, "run_tool", lambda argv, timeout: ToolResult(argv, 0, helps[argv[0]], ""))
    res = {r.tool: r for r in lab.check_flags()}
    assert res["nmap"].status == "ok" and res["smbclient"].status == "ok"
    assert res["msfconsole"].status == "missing-flags" and res["msfconsole"].missing == ["-n"]
    assert res["netexec"].status == "not-installed"


def test_contracts_match_commands_actually_built(monkeypatch):
    """Every flag the scanner passes must be listed in FLAG_CONTRACTS (catches drift)."""
    monkeypatch.setattr(smb, "resolve_tool", lambda name: name)
    contracts = {c.tool: set(c.required) for c in lab.FLAG_CONTRACTS}
    for tool, argv in smb.build_anonymous_commands("192.168.56.10").items():
        used = {a for a in argv[1:] if a.startswith("-")}
        assert used <= contracts[tool], (tool, used - contracts[tool])
    from vulnr_scannr import nmap

    used = {
        a for a in nmap.build_scan_command("10.0.0.1", "o.xml", "safe") if a.startswith("-") and a not in ("--", "-")
    }
    used |= {a for a in nmap.build_discovery_command("10.0.0.0/30") if a.startswith("-") and a not in ("--", "-")}
    used = {"-T" if a.startswith("-T") else a for a in used}
    assert used <= contracts["nmap"]
    msf = metasploit.build_msf_command("10.0.0.1", "smb_version")
    assert {a for a in msf if a.startswith("-")} <= contracts["msfconsole"]


def test_metasploit_allowlist_matches_verified_upstream(fixtures):
    data = json.loads((fixtures / "upstream" / "metasploit.json").read_text())
    verified = {p.removeprefix("modules/").removesuffix(".rb") for p in data["module_files_found"]}
    assert set(metasploit.ALLOWED_MODULES.values()) <= verified
    missing = {p.removeprefix("modules/").removesuffix(".rb") for p in data["module_files_not_found"]}
    assert not set(metasploit.ALLOWED_MODULES.values()) & missing
    assert set(data["msfconsole_flags"]) >= {"-q", "-n", "-x"}


def test_replay_synthetic_fixtures(fixtures):
    results = lab.replay(fixtures)
    assert results and all(r["status"] != "MISMATCH" for r in results)
    assert sum(r["status"] == "match" for r in results) >= 3


def test_replay_detects_mismatch(tmp_path):
    (tmp_path / "x.nxc.txt").write_text("(signing:True) (SMBv1:False)")
    (tmp_path / "x.nxc.txt.expected.json").write_text('{"signing_required": false}')
    assert lab.replay(tmp_path)[0]["status"] == "MISMATCH"
    assert lab.main(["replay", str(tmp_path)]) == 1


@pytest.mark.parametrize("host", ["8.8.8.8", "lab.example", "10.0.0.0/24", "224.0.0.1", "0.0.0.0", "1.1.1.1;id"])
def test_capture_refuses_non_lab_targets(host):
    with pytest.raises(ValidationError):
        lab.validate_lab_host(host)


def test_capture_requires_authorized(capsys):
    assert lab.main(["capture", "192.168.56.10"]) == 2
    assert "--authorized" in capsys.readouterr().err


def test_capture_with_mocks_redacts_and_records(monkeypatch, tmp_path):
    monkeypatch.setattr(
        smb,
        "resolve_tool",
        lambda name: f"/bin/{name}" if name == "netexec" else (_ for _ in ()).throw(ToolNotFoundError(name)),
    )
    monkeypatch.setattr(lab, "resolve_tool", lambda name: (_ for _ in ()).throw(ToolNotFoundError(name)))
    out = "SMB 192.168.56.10 445 X [*] W (signing:False) (SMBv1:True) password=Hunter2"
    monkeypatch.setattr(lab, "run_tool", lambda argv, timeout: ToolResult(argv, 0, "\x1b[1m" + out, ""))
    files = lab.capture("192.168.56.10", tmp_path)
    nxc = next(f for f in files if f.name.endswith(".nxc.txt"))
    text = nxc.read_text()
    assert "Hunter2" not in text and "\x1b" not in text
    meta = json.loads(next(f for f in files if f.name.endswith(".meta.json")).read_text())
    assert meta["provenance"].startswith("real lab capture") and "netexec" in meta["commands"]


def test_flags_cli_offline(monkeypatch, capsys):
    monkeypatch.setattr(lab, "resolve_tool", lambda name: (_ for _ in ()).throw(ToolNotFoundError(name)))
    assert lab.main(["flags"]) == 0
    assert "SKIP" in capsys.readouterr().out


# ---------------------------------------------------------------- impacket contract (real installed library)
def test_impacket_rpc_contract():
    """Check the exact call signatures and response field paths used in smb.py against installed impacket."""
    pytest.importorskip("impacket")
    import inspect

    from impacket.dcerpc.v5 import srvs, transport, wkst
    from impacket.dcerpc.v5.dtypes import NULL

    inspect.signature(wkst.hNetrWkstaUserEnum).bind(object(), 1)
    inspect.signature(srvs.hNetrSessionEnum).bind(object(), "\x00", NULL, 10)
    inspect.signature(transport.SMBTransport).bind("host", filename=r"\srvsvc", smb_connection=object())
    assert "UserInfo" in dict(wkst.NetrWkstaUserEnumResponse.structure)
    assert "WkstaUserInfo" in dict(wkst.WKSTA_USER_ENUM_STRUCT.structure)
    assert wkst.WKSTA_USER_ENUM_UNION.union[1][0] == "Level1"
    assert "Buffer" in dict(wkst.WKSTA_USER_INFO_1_CONTAINER.structure)
    assert "wkui1_username" in dict(wkst.WKSTA_USER_INFO_1.structure)
    assert "InfoStruct" in dict(srvs.NetrSessionEnumResponse.structure)
    assert "SessionInfo" in dict(srvs.SESSION_ENUM_STRUCT.structure)
    assert srvs.SESSION_ENUM_UNION.union[10][0] == "Level10"
    assert {"sesi10_username", "sesi10_cname", "sesi10_time"} <= set(dict(srvs.SESSION_INFO_10.structure))


def test_impacket_session_parsing_with_real_ndr_structures(monkeypatch):
    """Build a real impacket NetrSessionEnum response and feed it through smb._sessions."""
    pytest.importorskip("impacket")
    from impacket.dcerpc.v5 import srvs, transport

    resp = srvs.NetrSessionEnumResponse()
    resp["InfoStruct"]["Level"] = 10
    resp["InfoStruct"]["SessionInfo"]["tag"] = 10
    entry = srvs.SESSION_INFO_10()
    entry["sesi10_cname"] = "\\\\192.168.56.1\x00"
    entry["sesi10_username"] = "labuser\x00"
    entry["sesi10_time"] = 42
    entry["sesi10_idle_time"] = 0
    resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"].append(entry)

    class FakeDCE:
        def connect(self):
            pass

        def bind(self, uuid):
            pass

        def disconnect(self):
            pass

    class FakeRPC:
        def __init__(self, *a, **kw):
            pass

        def get_dce_rpc(self):
            return FakeDCE()

    class Conn:
        def getRemoteHost(self):
            return "192.168.56.10"

    monkeypatch.setattr(transport, "SMBTransport", FakeRPC)
    monkeypatch.setattr(srvs, "hNetrSessionEnum", lambda dce, c, u, lvl: resp)
    assert smb._sessions(Conn()) == [{"user": "labuser", "client": "\\\\192.168.56.1", "time": 42}]
