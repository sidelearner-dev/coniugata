"""Small validators shared by source modules."""

from __future__ import annotations

import ipaddress
import re

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_EMAIL_LOCAL = re.compile(r"^[a-z0-9._%+'-]+$")


def is_valid_hostname(name: str) -> bool:
    """True for a syntactically valid, lower-case, multi-label hostname."""
    if not name or len(name) > 253 or any(ch in name for ch in " @/"):
        return False
    if normalize_ip(name) is not None:  # an IP literal is not a hostname
        return False
    labels = name.rstrip(".").split(".")
    return len(labels) >= 2 and all(_LABEL.match(label) for label in labels)


def is_valid_email(value: str) -> bool:
    value = value.strip().lower()
    if len(value) > 254 or value.count("@") != 1:
        return False
    local, _, domain = value.partition("@")
    if (
        not local
        or len(local) > 64
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or not _EMAIL_LOCAL.match(local)
    ):
        return False
    return is_valid_hostname(domain)


def normalize_ip(value: object) -> str | None:
    """Canonical text form of an IP address, or None if it isn't one."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None
