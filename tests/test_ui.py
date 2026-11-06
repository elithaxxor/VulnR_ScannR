import io

from vulnr_scannr import ui


class TTY(io.StringIO):
    def isatty(self):
        return True


def test_no_color_for_pipes(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    st = ui.Style(io.StringIO())
    assert st.error("x") == "x" and "\x1b" not in st.risk("Critical")


def test_color_on_tty_and_no_color_env(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    assert ui.Style(TTY()).ok("y").startswith("\x1b[")
    monkeypatch.setenv("NO_COLOR", "1")
    assert ui.Style(TTY()).ok("y") == "y"
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    assert ui.Style(TTY()).ok("y") == "y"


def test_force_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert "\x1b[" in ui.Style(io.StringIO()).warn("w")


def test_strip_ansi_and_phase():
    assert ui.strip_ansi("\x1b[1m\x1b[32msigning:True\x1b[0m") == "signing:True"
    assert ui.phase(2, 5, "Enumerating") == "[2/5] Enumerating"


def test_cli_output_has_no_escape_codes_when_piped(capsys, monkeypatch, tmp_path, fixtures):
    from vulnr_scannr import cli

    monkeypatch.delenv("FORCE_COLOR", raising=False)
    assert cli.main(["-q", "--db", str(tmp_path / "a.db"), "score", str(fixtures / "findings.json")]) == 0
    assert cli.main(["check-deps"]) == 0
    assert cli.main(["--db", str(tmp_path / "a.db"), "--authorized", "nmap", "1.1.1.1;id"]) == 2
    out, err = capsys.readouterr()
    assert "\x1b" not in out and "\x1b" not in err
