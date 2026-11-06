"""Input validation for anything that ends up on a subprocess command line.

Every value passed to an external tool goes through these helpers first.
Commands are always built as argument lists (never ``shell=True``), and the
validators additionally reject values that an external tool could interpret
as an option (leading ``-``) or that contain whitespace/control characters.
"""

from __future__ import annotations

import ipaddress
import re

#: Largest network (number of addresses) accepted for discovery by default.
DEFAULT_MAX_ADDRESSES = 4096

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")

#: Nmap NSE categories/scripts the tool will pass through. Intrusive,
#: brute-force, DoS, exploit and malware categories are deliberately excluded.
ALLOWED_NSE_CATEGORIES = frozenset({"default", "safe", "discovery", "version", "vuln"})

_PORT_LIST_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


class ValidationError(ValueError):
    """Raised when user supplied input is rejected."""


def _basic_checks(value: str, what: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{what} must be a string")
    value = value.strip()
    if not value:
        raise ValidationError(f"{what} must not be empty")
    if value.startswith("-"):
        raise ValidationError(f"{what} must not start with '-': {value!r}")
    if any(ch.isspace() or ord(ch) < 32 or ch in ";|&$`<>\"'\\" for ch in value):
        raise ValidationError(f"{what} contains forbidden characters: {value!r}")
    return value


def validate_host(value: str) -> str:
    """Validate a single IPv4/IPv6 address or DNS hostname."""
    value = _basic_checks(value, "target")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if _HOSTNAME_RE.match(value) and not value.replace(".", "").isdigit():
        return value
    raise ValidationError(f"not a valid IP address or hostname: {value!r}")


def validate_network(value: str, max_addresses: int = DEFAULT_MAX_ADDRESSES) -> str:
    """Validate a CIDR network (``192.168.1.0/24``), bounded in size."""
    value = _basic_checks(value, "network")
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValidationError(f"not a valid CIDR network: {value!r}") from exc
    if net.num_addresses > max_addresses:
        raise ValidationError(
            f"network {net} has {net.num_addresses} addresses; the limit is "
            f"{max_addresses} (raise it with --max-addresses if you are authorized)"
        )
    return str(net)


def validate_target(value: str, max_addresses: int = DEFAULT_MAX_ADDRESSES) -> str:
    """Validate a host *or* a CIDR network."""
    if "/" in value:
        return validate_network(value, max_addresses)
    return validate_host(value)


def validate_targets(values: list[str] | str, max_addresses: int = DEFAULT_MAX_ADDRESSES) -> list[str]:
    """Validate a list (or comma separated string) of targets, de-duplicated in order."""
    if isinstance(values, str):
        values = [v for v in values.split(",")]
    out: list[str] = []
    for raw in values:
        if not raw.strip():
            continue
        t = validate_target(raw, max_addresses)
        if t not in out:
            out.append(t)
    if not out:
        raise ValidationError("no targets given")
    return out


def validate_nse_categories(value: str | None) -> str | None:
    """Validate a comma separated list of allowed NSE categories."""
    if value is None or not value.strip():
        return None
    parts = [p.strip().lower() for p in value.split(",") if p.strip()]
    bad = [p for p in parts if p not in ALLOWED_NSE_CATEGORIES]
    if bad:
        raise ValidationError(
            f"NSE categories not allowed: {', '.join(bad)} (allowed: {', '.join(sorted(ALLOWED_NSE_CATEGORIES))})"
        )
    return ",".join(dict.fromkeys(parts))


def validate_ports(value: str) -> str:
    """Validate an nmap style port list such as ``22,80,8000-8100``."""
    value = _basic_checks(value, "ports")
    if not _PORT_LIST_RE.match(value):
        raise ValidationError(f"invalid port list: {value!r}")
    for chunk in value.split(","):
        bounds = [int(x) for x in chunk.split("-")]
        if any(not 1 <= b <= 65535 for b in bounds) or (len(bounds) == 2 and bounds[0] > bounds[1]):
            raise ValidationError(f"invalid port range: {chunk!r}")
    return value


def validate_time_of_day(value: str) -> tuple[int, int]:
    """Parse ``HH:MM`` (24h)."""
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", value.strip())
    if not m:
        raise ValidationError(f"time must be HH:MM, got {value!r}")
    hh, mm = int(m.group(1)), int(m.group(2))
    if hh > 23 or mm > 59:
        raise ValidationError(f"time out of range: {value!r}")
    return hh, mm
