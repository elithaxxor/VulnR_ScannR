"""Interactive menu preserving the legacy menu-driven UI.

Each option collects and validates input, then calls the same CLI code path
(``cli.main``), so authorization, validation and redaction rules are shared.
Ctrl+C or EOF at a sub-prompt returns to the menu; at the main prompt it exits.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from vulnr_scannr import __version__
from vulnr_scannr.ui import Style
from vulnr_scannr.validation import ValidationError, validate_host, validate_network, validate_targets

MAX_ATTEMPTS = 3


@dataclass(frozen=True)
class Option:
    key: str
    label: str
    network: bool = False
    tool: str | None = None  # external tool that must be installed
    python_extra: str | None = None  # optional Python extra that must be installed


OPTIONS: tuple[Option, ...] = (
    Option("1", "Discover and enumerate SMB hosts", network=True, tool="nmap"),
    Option("2", "Intensity-based SMB enumeration (impacket)", network=True, python_extra="smb"),
    Option("3", "Nmap service scan", network=True, tool="nmap"),
    Option("4", "Metasploit auxiliary scanner module", network=True, tool="msfconsole"),
    Option("5", "Score findings JSON"),
    Option("6", "Export data (CSV/JSON/XML)"),
    Option("7", "HTML report"),
    Option("8", "Check dependencies"),
    Option("0", "Exit"),
)
NETWORK_CHOICES = {o.key for o in OPTIONS if o.network}

RESULT_MESSAGES = {
    1: "The command failed; see the error above.",
    2: "Input or authorization problem; nothing was scanned.",
    3: "A required tool is missing; choose 8 to see what is installed.",
    130: "Cancelled.",
}


class _Cancel(Exception):
    """User pressed Ctrl+C / sent EOF at a sub-prompt."""


def _default_tool_available(name: str) -> bool:
    from vulnr_scannr.tools import ToolNotFoundError, resolve_tool

    try:
        resolve_tool(name)
    except ToolNotFoundError:
        return False
    return True


def _default_extra_available(name: str) -> bool:
    if name == "smb":
        from vulnr_scannr.smb import impacket_available

        return impacket_available()
    return True


class Menu:
    def __init__(
        self,
        db: Any,
        authorized: bool = False,
        max_addresses: int = 4096,
        input_fn: Callable[[str], str] | None = None,
        runner: Callable[[list[str]], int] | None = None,
        out: TextIO | None = None,
        tool_available: Callable[[str], bool] = _default_tool_available,
        extra_available: Callable[[str], bool] = _default_extra_available,
    ) -> None:
        self.db = db
        self.authorized = authorized
        self.max_addresses = max_addresses
        self.input_fn = input_fn or (lambda prompt: input(prompt))
        self.out = out or sys.stdout
        self.st = Style(self.out)
        self.tool_available = tool_available
        self.extra_available = extra_available
        if runner is None:
            from vulnr_scannr import cli

            runner = cli.main
        self.runner = runner
        self.base = ["--db", db.path, "--max-addresses", str(max_addresses)]

    # -- output helpers ------------------------------------------------
    def say(self, text: str = "") -> None:
        print(text, file=self.out)

    def banner(self) -> None:
        st = self.st
        self.say(st.header(f"=== VulnR_ScannR {__version__} - interactive menu ==="))
        auth = st.ok("yes (--authorized)") if self.authorized else st.warn("will ask before any network action")
        self.say(f"Database: {self.db.path}    Authorized: {auth}")
        self.say(st.dim("Only scan systems you own or have written permission to test. Ctrl+C returns to the menu."))

    def show_menu(self) -> None:
        self.say()
        self.say(self.st.header("MAIN MENU"))
        for o in OPTIONS:
            note = ""
            if o.tool and not self.tool_available(o.tool):
                note = self.st.warn(f"  (needs {o.tool} - not installed)")
            elif o.python_extra and not self.extra_available(o.python_extra):
                note = self.st.warn(f"  (needs pip install 'vulnr-scannr[{o.python_extra}]')")
            self.say(f"  {o.key}) {o.label}{note}")

    # -- input helpers -------------------------------------------------
    def ask(self, prompt: str, validate: Callable[[str], Any] | None = None, default: str | None = None) -> str:
        """Prompt with optional validation; raises _Cancel on Ctrl+C/EOF or too many bad tries."""
        suffix = f" [{default}]" if default else ""
        for _ in range(MAX_ATTEMPTS):
            try:
                raw = self.input_fn(f"{prompt}{suffix}: ").strip()
            except (EOFError, KeyboardInterrupt):
                self.say()
                raise _Cancel from None
            value = raw or (default or "")
            if not value:
                self.say(self.st.warn("  A value is required."))
                continue
            if validate is None:
                return value
            try:
                validate(value)
            except (ValidationError, ValueError) as exc:
                self.say(self.st.error("  Invalid: ") + str(exc))
                continue
            return value
        self.say(self.st.warn("  Too many invalid attempts; back to the menu."))
        raise _Cancel

    def confirm_authorized(self) -> bool:
        if self.authorized:
            return True
        ans = self.ask("Do you have permission to scan these targets? Type 'yes' to continue", default="no")
        if ans.lower() != "yes":
            self.say(self.st.warn("Skipped: authorization not confirmed. Nothing was scanned."))
            return False
        self.authorized = True
        return True

    # -- option handlers -----------------------------------------------
    def build_argv(self, choice: str) -> list[str] | None:
        auth = ["--authorized"] if self.authorized else []
        base = self.base
        if choice == "1":
            net = self.ask("Network CIDR (e.g. 192.168.56.0/24)", lambda v: validate_network(v, self.max_addresses))
            return [*base, *auth, "discover", net, "--enumerate"]
        if choice == "2":
            tgt = self.ask("Target IP or hostname", validate_host)
            lvl = self.ask("Intensity 1=shares 2=+users 3=+sessions", _validate_level, default="1")
            user = self.input_optional("Username (blank = anonymous)")
            argv = [*base, *auth, "smb-intensity", tgt, "--level", lvl]
            if user:
                argv += ["--username", user, "--domain", self.input_optional("Domain (optional)")]
            return argv
        if choice == "3":
            tgts = self.ask("Targets (comma separated IPs/CIDRs)", lambda v: validate_targets(v, self.max_addresses))
            scripts = self.input_optional("NSE categories (default,safe,discovery,version,vuln; blank = none)")
            if scripts:
                from vulnr_scannr.validation import validate_nse_categories

                validate_nse_categories(scripts)
            return [*base, *auth, "nmap", tgts] + (["--scripts", scripts] if scripts else [])
        if choice == "4":
            from vulnr_scannr.metasploit import ALLOWED_MODULES, resolve_module

            for k, v in ALLOWED_MODULES.items():
                self.say(f"    {k:<16} {self.st.dim(v)}")
            mod = self.ask("Module key", resolve_module, default="smb_version")
            tgt = self.ask("Target IP/CIDR", lambda v: validate_targets(v, self.max_addresses))
            return [*base, *auth, "metasploit", tgt, "--module", mod]
        if choice == "5":
            return [*base, "score", self.ask("Findings JSON path", _validate_existing_file)]
        if choice == "6":
            return [*base, "export"]
        if choice == "7":
            return [*base, "report"]
        if choice == "8":
            return ["check-deps"]
        return None

    def input_optional(self, prompt: str) -> str:
        try:
            return self.input_fn(f"{prompt}: ").strip()
        except (EOFError, KeyboardInterrupt):
            self.say()
            raise _Cancel from None

    def run_choice(self, choice: str) -> int | None:
        option = next((o for o in OPTIONS if o.key == choice), None)
        if option is None:
            self.say(self.st.error("Invalid option: ") + repr(choice) + " - enter a number from the menu.")
            return None
        if option.tool and not self.tool_available(option.tool):
            self.say(
                self.st.warn(
                    f"'{option.tool}' is not installed. Install it with your OS package manager, "
                    "then try again (option 8 lists all tools)."
                )
            )
            return None
        if option.python_extra and not self.extra_available(option.python_extra):
            self.say(self.st.warn(f"This option needs: pip install 'vulnr-scannr[{option.python_extra}]'"))
            return None
        try:
            if option.network and not self.confirm_authorized():
                return None
            argv = self.build_argv(choice)
        except _Cancel:
            self.say(self.st.dim("Cancelled; back to the menu."))
            return None
        except ValidationError as exc:
            self.say(self.st.error("Invalid: ") + str(exc))
            return None
        if argv is None:
            return None
        self.say(self.st.dim(f"-> {option.label} ..."))
        try:
            rc = self.runner(argv)
        except KeyboardInterrupt:
            rc = 130
        if rc == 0:
            self.say(self.st.ok("Done."))
        else:
            self.say(self.st.warn(RESULT_MESSAGES.get(rc, f"Command exited with status {rc}.")))
        return rc

    def loop(self) -> int:
        self.banner()
        while True:
            self.show_menu()
            try:
                choice = self.input_fn("Select an option (0-8): ").strip()
            except (EOFError, KeyboardInterrupt):
                self.say()
                self.say("Goodbye.")
                return 0
            if choice == "0":
                self.say("Goodbye.")
                return 0
            self.run_choice(choice)


def _validate_level(v: str) -> None:
    if v not in {"1", "2", "3"}:
        raise ValidationError("intensity must be 1, 2 or 3")


def _validate_existing_file(v: str) -> None:
    if not Path(v).is_file():
        raise ValidationError(f"file not found: {v}")


def run_menu(
    db: Any,
    authorized: bool = False,
    max_addresses: int = 4096,
    input_fn: Callable[[str], str] | None = None,
    runner: Callable[[list[str]], int] | None = None,
    **kwargs: Any,
) -> int:
    return Menu(db, authorized, max_addresses, input_fn, runner, **kwargs).loop()
