"""Small validators shared by source modules."""

from __future__ import annotations

import ipaddress
import re

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_EMAIL = re.compile(r"^[a-z0-9._%+'-]+@[a-z0-9.-]+\.[a-z]{2,}$")


def is_valid_hostname(name: str) -> bool:
    """True for a syntactically valid, lower-case, multi-label hostname."""
    if len(name) > 253 or any(ch in name for ch in " @/"):
        return False
    labels = name.rstrip(".").split(".")
    return len(labels) >= 2 and all(_LABEL.match(label) for label in labels)


def is_valid_email(value: str) -> bool:
    value = value.strip().lower()
    return len(value) <= 254 and bool(_EMAIL.match(value))


def normalize_ip(value: str) -> str | None:
    """Canonical text form of an IP address, or None if it isn't one."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None
