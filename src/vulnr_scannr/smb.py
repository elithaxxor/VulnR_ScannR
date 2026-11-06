"""SMB enumeration using standard external tools and (optionally) impacket.

Only *read-only, anonymous / null-session* enumeration is performed by the
LAN-wide workflow. The legacy ``crackmapexec --sam`` hash dump was removed
(credential harvesting is out of scope for a grading tool).
"""

from __future__ import annotations

import enum
import logging
from typing import Any

from vulnr_scannr.nmap import empty_host
from vulnr_scannr.tools import ToolNotFoundError, resolve_tool, run_tool
from vulnr_scannr.validation import validate_host

log = logging.getLogger("vulnr_scannr")

TOOL_TIMEOUT = 120


class IntensityLevel(enum.IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


def build_anonymous_commands(ip: str) -> dict[str, list[str]]:
    """Return the read-only commands used for one host (tools resolved lazily)."""
    ip = validate_host(ip)
    cmds: dict[str, list[str]] = {}
    specs = {
        "netexec": lambda exe: [exe, "smb", ip],
        "smbclient": lambda exe: [exe, "-L", f"//{ip}/", "-N", "-g"],
        "lookupsid": lambda exe: [exe, "-no-pass", f"@{ip}"],
        "enum4linux": lambda exe: [exe, "-U", ip],
        "rpcclient": lambda exe: [exe, "-U", "", "-N", "-c", "lsaquery", ip],
    }
    for name, build in specs.items():
        try:
            cmds[name] = build(resolve_tool(name))
        except ToolNotFoundError:
            log.debug("tool %s not installed; skipping", name)
    return cmds


def parse_smbclient_shares(output: str) -> list[str]:
    """Parse ``smbclient -L -g`` grepable output (``Disk|NAME|comment``)."""
    shares = []
    for line in output.splitlines():
        parts = line.split("|")
        if len(parts) >= 2 and parts[0] in {"Disk", "IPC", "Printer"}:
            shares.append(parts[1])
    return shares


def parse_netexec_info(output: str) -> dict[str, Any]:
    """Pull signing/SMBv1 flags from a netexec/crackmapexec banner line."""
    info: dict[str, Any] = {}
    low = output.lower()
    if "signing:false" in low.replace(" ", ""):
        info["signing_disabled"] = True
    if "smbv1:true" in low.replace(" ", ""):
        info["smbv1"] = True
    return info


def enumerate_host(ip: str, timeout: float = TOOL_TIMEOUT) -> dict[str, Any]:
    """Run the available anonymous enumeration tools against one host."""
    ip = validate_host(ip)
    data = empty_host(ip)
    data["shares"] = []
    cmds = build_anonymous_commands(ip)
    if not cmds:
        log.warning("No SMB enumeration tools installed (see `vulnr-scannr check-deps`).")
        return data
    log.info("[*] Enumerating %s with: %s", ip, ", ".join(cmds))
    for name, argv in cmds.items():
        res = run_tool(argv, timeout=timeout)
        if res.timed_out:
            log.warning("[%s] %s timed out", name, ip)
            continue
        out = res.stdout.strip()
        if name == "smbclient":
            data["shares"] = parse_smbclient_shares(out)
            if data["shares"]:
                log.info("[%s] anonymous shares on %s: %s", name, ip, ", ".join(data["shares"]))
        elif name == "netexec":
            flags = parse_netexec_info(out)
            if flags.get("signing_disabled"):
                _add(data, "SMB Signing Disabled")
            if flags.get("smbv1"):
                _add(data, "SMBv1 Enabled")
            log.info("[%s] %s", name, out[:2000])
        else:
            log.info("[%s] %s:\n%s", name, ip, out[:4000])
    if 445 not in data["open_ports"]:
        data["open_ports"].append(445)
    return data


def _add(data: dict[str, Any], finding: str) -> None:
    if finding not in data["vulnerabilities"]:
        data["vulnerabilities"].append(finding)


def enumerate_lan_hosts(hosts: list[str]) -> dict[str, dict[str, Any]]:
    return {h: enumerate_host(h) for h in hosts}


# --------------------------------------------------------------------------- impacket
def impacket_available() -> bool:
    try:
        import impacket.smbconnection  # noqa: F401
    except ImportError:
        return False
    return True


def enumerate_with_intensity(
    target: str,
    intensity: IntensityLevel | int,
    username: str = "",
    password: str = "",
    domain: str = "",
    timeout: int = 30,
) -> dict[str, Any]:  # noqa: S107
    """Impacket based enumeration (requires the ``smb`` extra).

    LOW: list shares. MEDIUM: + logged-on users (NetrWkstaUserEnum).
    HIGH: + sessions, share readability, server info.
    Credentials are used only for the SMB login and are never logged.
    """
    target = validate_host(target)
    level = IntensityLevel(int(intensity))
    if not impacket_available():
        raise ToolNotFoundError("impacket is not installed; install with: pip install 'vulnr-scannr[smb]'")
    from impacket.smbconnection import SMBConnection

    result: dict[str, Any] = {
        "host": target,
        "intensity": level.name,
        "shares": [],
        "logged_on_users": [],
        "sessions": [],
        "accessible_shares": [],
    }
    log.info("[impacket] %s intensity=%s (authenticated=%s)", target, level.name, bool(username))
    conn = SMBConnection(target, target, timeout=timeout)
    try:
        conn.login(username, password, domain)
        shares = [s["shi1_netname"].rstrip("\x00") for s in conn.listShares()]
        result["shares"] = shares
        log.info("[impacket] shares: %s", ", ".join(shares) or "(none)")
        if level >= IntensityLevel.MEDIUM:
            result["logged_on_users"] = _wkst_users(conn)
        if level >= IntensityLevel.HIGH:
            result["sessions"] = _sessions(conn)
            for share in shares:
                if share.endswith("$"):
                    continue
                try:
                    conn.listPath(share, "*")
                    result["accessible_shares"].append(share)
                except Exception:  # noqa: BLE001,S112 - share not readable
                    continue
            log.info("[impacket] readable shares: %s", ", ".join(result["accessible_shares"]) or "(none)")
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            log.debug("error closing SMB connection", exc_info=True)
    return result


def _wkst_users(conn: Any) -> list[str]:
    from impacket.dcerpc.v5 import transport, wkst

    try:
        rpc = transport.SMBTransport(conn.getRemoteHost(), filename=r"\wkssvc", smb_connection=conn)
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(wkst.MSRPC_UUID_WKST)
        resp = wkst.hNetrWkstaUserEnum(dce, 1)
        users = [u["wkui1_username"].rstrip("\x00") for u in resp["UserInfo"]["WkstaUserInfo"]["Level1"]["Buffer"]]
        dce.disconnect()
    except Exception as exc:  # noqa: BLE001
        log.warning("[impacket] logged-on user enumeration failed: %s", exc)
        return []
    log.info("[impacket] logged-on users: %s", ", ".join(users) or "(none)")
    return users


def _sessions(conn: Any) -> list[dict[str, Any]]:
    from impacket.dcerpc.v5 import srvs, transport
    from impacket.dcerpc.v5.dtypes import NULL

    try:
        rpc = transport.SMBTransport(conn.getRemoteHost(), filename=r"\srvsvc", smb_connection=conn)
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrSessionEnum(dce, "\x00", NULL, 10)
        out = [
            {"user": s["sesi10_username"][:-1], "client": s["sesi10_cname"][:-1], "time": s["sesi10_time"]}
            for s in resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]
        ]
        dce.disconnect()
    except Exception as exc:  # noqa: BLE001
        log.warning("[impacket] session enumeration failed: %s", exc)
        return []
    log.info("[impacket] %d active session(s)", len(out))
    return out
