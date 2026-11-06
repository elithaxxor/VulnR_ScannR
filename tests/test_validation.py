import pytest

from vulnr_scannr.validation import (
    ValidationError,
    validate_host,
    validate_network,
    validate_nse_categories,
    validate_ports,
    validate_target,
    validate_targets,
    validate_time_of_day,
)


@pytest.mark.parametrize("v", ["192.168.1.10", "::1", "fileserver", "dc01.corp.example", "10.0.0.1 "])
def test_valid_hosts(v):
    assert validate_host(v) == v.strip()


@pytest.mark.parametrize(
    "v",
    [
        "",
        "-oX",
        "--script=exploit",
        "1.2.3.4; rm -rf /",
        "a b",
        "$(id)",
        "`id`",
        "host|nc",
        "x&y",
        "999.1.1.1",
        "bad_host!",
        "-",
        "h\nx",
        "'a'",
    ],
)
def test_invalid_hosts(v):
    with pytest.raises(ValidationError):
        validate_host(v)


def test_network_normalised_and_bounded():
    assert validate_network("192.168.1.7/24") == "192.168.1.0/24"
    with pytest.raises(ValidationError):
        validate_network("10.0.0.0/8")
    assert validate_network("10.0.0.0/8", max_addresses=2**24) == "10.0.0.0/8"
    with pytest.raises(ValidationError):
        validate_network("not/a/net")


def test_targets_list():
    assert validate_targets("10.0.0.1, 10.0.0.1,10.0.0.0/30") == ["10.0.0.1", "10.0.0.0/30"]
    assert validate_target("10.0.0.5") == "10.0.0.5"
    with pytest.raises(ValidationError):
        validate_targets(" , ")


def test_nse_allowlist():
    assert validate_nse_categories("safe, vuln,safe") == "safe,vuln"
    assert validate_nse_categories("") is None
    for bad in ("exploit", "brute", "dos", "intrusive", "safe,malware", "smb-brute"):
        with pytest.raises(ValidationError):
            validate_nse_categories(bad)


def test_ports():
    assert validate_ports("22,80,8000-8100") == "22,80,8000-8100"
    for bad in ("0", "70000", "80-20", "22;id", "-p-", "a"):
        with pytest.raises(ValidationError):
            validate_ports(bad)


def test_time_of_day():
    assert validate_time_of_day("03:00") == (3, 0)
    for bad in ("24:00", "3", "12:60", "aa:bb"):
        with pytest.raises(ValidationError):
            validate_time_of_day(bad)
