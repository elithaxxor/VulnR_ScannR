import io

import pytest

from vulnr_scannr.menu import Menu, run_menu


def make(db, answers, authorized=False, tools=True, extra=True, rc=0):
    it = iter(answers)
    calls = []
    out = io.StringIO()

    def fake_input(prompt):
        out.write(prompt)
        v = next(it)
        if isinstance(v, BaseException):
            raise v
        return v

    def runner(argv):
        calls.append(argv)
        return rc

    m = Menu(
        db,
        authorized=authorized,
        input_fn=fake_input,
        runner=runner,
        out=out,
        tool_available=lambda n: tools,
        extra_available=lambda n: extra,
    )
    return m, calls, out


def test_declined_authorization_runs_nothing(db):
    m, calls, out = make(db, ["3", "no", "0"])
    assert m.loop() == 0
    assert calls == [] and "Nothing was scanned" in out.getvalue()


def test_confirmed_authorization_passes_flag(db):
    m, calls, out = make(db, ["3", "yes", "192.168.56.10", "safe", "0"])
    assert m.loop() == 0
    assert calls[0][-4:] == ["nmap", "192.168.56.10", "--scripts", "safe"]
    assert "--authorized" in calls[0]


def test_invalid_input_reprompts_then_cancels(db):
    m, calls, out = make(db, ["1", "yes", "1.2.3.4;id", "-x", "10.0.0.0/8", "0"])
    assert m.loop() == 0
    text = out.getvalue()
    assert text.count("Invalid:") == 3 and "Too many invalid attempts" in text and calls == []


def test_invalid_menu_choice_and_missing_tool(db):
    m, calls, out = make(db, ["42", "1", "0"], tools=False)
    assert m.loop() == 0
    text = out.getvalue()
    assert "Invalid option" in text and "not installed" in text and calls == []


def test_missing_python_extra(db):
    m, calls, out = make(db, ["2", "0"], extra=False)
    m.loop()
    assert "vulnr-scannr[smb]" in out.getvalue() and calls == []


def test_ctrl_c_and_eof(db):
    m, calls, out = make(db, ["5", KeyboardInterrupt(), EOFError()])
    assert m.loop() == 0
    assert "Cancelled" in out.getvalue() and "Goodbye" in out.getvalue()


def test_score_requires_existing_file(db, fixtures):
    m, calls, out = make(db, ["5", "missing.json", str(fixtures / "findings.json"), "8", "0"])
    m.loop()
    assert "file not found" in out.getvalue()
    assert calls[0][-2:] == ["score", str(fixtures / "findings.json")] and calls[1] == ["check-deps"]


def test_result_messages(db):
    m, calls, out = make(db, ["6", "0"], rc=3)
    m.loop()
    assert "required tool is missing" in out.getvalue()


def test_metasploit_validates_module(db):
    m, calls, out = make(db, ["4", "nope", "smb_version", "10.0.0.5", "0"], authorized=True)
    m.loop()
    assert "not allowed" in out.getvalue()
    assert calls[0][-4:] == ["metasploit", "10.0.0.5", "--module", "smb_version"]


def test_menu_output_plain_when_not_tty(db, monkeypatch):
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    m, calls, out = make(db, ["0"])
    m.loop()
    assert "\x1b" not in out.getvalue() and "MAIN MENU" in out.getvalue()


def test_run_menu_wrapper_and_cli_menu_eof(db, tmp_path, monkeypatch):
    assert run_menu(db, input_fn=lambda p: (_ for _ in ()).throw(EOFError())) == 0
    from vulnr_scannr import cli

    monkeypatch.setattr("builtins.input", lambda p="": (_ for _ in ()).throw(EOFError()))
    assert cli.main(["--db", str(tmp_path / "m.db"), "menu"]) == 0


@pytest.mark.parametrize("choice", ["1", "2", "3", "4"])
def test_network_options_always_gated(db, choice):
    m, calls, out = make(db, [choice, "", "0"])
    m.loop()
    assert calls == []
