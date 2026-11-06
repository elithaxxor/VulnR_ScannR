"""Interactive menu preserving the legacy menu-driven UI.

Each option collects input and then calls the same validated CLI code path.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

MENU = """
=== VulnR_ScannR MAIN MENU ===
1) Discover and enumerate SMB hosts
2) Intensity-based SMB enumeration (impacket)
3) Nmap service scan
4) Metasploit auxiliary scanner module
5) Score findings JSON
6) Export data (CSV/JSON/XML)
7) HTML report
8) Check dependencies
0) Exit
"""

NETWORK_CHOICES = {"1", "2", "3", "4"}


def run_menu(
    db: Any,
    authorized: bool = False,
    max_addresses: int = 4096,
    input_fn: Callable[[str], str] = input,
    runner: Callable[[list[str]], int] | None = None,
) -> int:
    from vulnr_scannr import cli

    run = runner or cli.main
    base = ["--db", db.path, "--max-addresses", str(max_addresses)]
    while True:
        print(MENU)
        try:
            choice = input_fn("Select an option (0-8): ").strip()
        except EOFError:
            return 0
        if choice == "0":
            return 0
        if choice in NETWORK_CHOICES and not authorized:
            ans = input_fn("Do you have permission to scan these targets? Type 'yes' to continue: ")
            if ans.strip().lower() != "yes":
                print("Skipped.")
                continue
            authorized = True
        auth = ["--authorized"] if authorized else []
        argv: list[str] | None = None
        if choice == "1":
            net = input_fn("Network CIDR (e.g. 192.168.56.0/24): ").strip()
            argv = [*base, *auth, "discover", net, "--enumerate"]
        elif choice == "2":
            tgt = input_fn("Target IP: ").strip()
            lvl = input_fn("Intensity 1-3 [1]: ").strip() or "1"
            user = input_fn("Username (blank = anonymous): ").strip()
            argv = [*base, *auth, "smb-intensity", tgt, "--level", lvl]
            if user:
                argv += ["--username", user, "--domain", input_fn("Domain: ").strip()]
        elif choice == "3":
            tgts = input_fn("Targets (comma separated): ").strip()
            scripts = input_fn("NSE categories (default,safe,discovery,version,vuln) or blank: ").strip()
            argv = [*base, *auth, "nmap", tgts] + (["--scripts", scripts] if scripts else [])
        elif choice == "4":
            run([*base, "list-modules"])
            mod = input_fn("Module key: ").strip()
            tgt = input_fn("Target IP/CIDR: ").strip()
            argv = [*base, *auth, "metasploit", tgt, "--module", mod]
        elif choice == "5":
            argv = [*base, "score", input_fn("Findings JSON path: ").strip()]
        elif choice == "6":
            argv = [*base, "export"]
        elif choice == "7":
            argv = [*base, "report"]
        elif choice == "8":
            argv = ["check-deps"]
        else:
            print("Invalid option.")
            continue
        rc = run(argv)
        if rc:
            print(f"(command exited with status {rc})")
