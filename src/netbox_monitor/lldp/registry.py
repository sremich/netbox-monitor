"""Driver registry: pick an LLDP driver by platform/vendor and collect neighbors
through one unified call.
"""

from __future__ import annotations

import re

import structlog

from netbox_monitor.lldp import (
    LldpNeighbor,
    arista_ssh_driver,
    aruba_ssh_driver,
    cisco_ssh_driver,
    mikrotik_ssh_driver,
    snmp_driver,
    unifi_ssh_driver,
)

log = structlog.get_logger(__name__)

# driver name -> whether it authenticates via SSH (username/password) or SNMP (community)
SSH_DRIVERS = {"cisco", "arista", "aruba", "mikrotik", "unifi"}
SNMP_DRIVERS = {"snmp"}
ALL_DRIVERS = SSH_DRIVERS | SNMP_DRIVERS

# platform-slug / sys_descr substring -> driver
_VENDOR_DRIVER = [
    (re.compile(r"mikrotik|routeros", re.I), "mikrotik"),
    (re.compile(r"arista", re.I), "arista"),
    (re.compile(r"aruba|procurve|hpe?\b|hewlett", re.I), "aruba"),
    (re.compile(r"cisco|nx-?os|ios", re.I), "cisco"),
    (re.compile(r"ubiquiti|unifi|edgeswitch|edgerouter", re.I), "unifi"),
]


def select_driver(platform_slug: str | None, sys_descr: str | None = None) -> str | None:
    """Best-guess driver from a NetBox platform slug or an LLDP system description.
    Returns None when nothing matches (caller should try the ``auto`` order)."""
    text = f"{platform_slug or ''} {sys_descr or ''}"
    for pattern, driver in _VENDOR_DRIVER:
        if pattern.search(text):
            return driver
    return None


# order tried when the driver is "auto" and no vendor hint matched
AUTO_ORDER = ["mikrotik", "cisco", "arista", "aruba", "unifi", "snmp"]


async def collect(
    driver: str,
    host: str,
    *,
    username: str = "",
    password: str = "",
    snmp_community: str = "",
) -> list[LldpNeighbor]:
    """Collect neighbors from ``host`` using the named driver."""
    if driver in SSH_DRIVERS:
        if not username or not password:
            raise ValueError(f"driver '{driver}' needs an SSH username/password")
        module = {
            "cisco": cisco_ssh_driver,
            "arista": arista_ssh_driver,
            "aruba": aruba_ssh_driver,
            "mikrotik": mikrotik_ssh_driver,
            "unifi": unifi_ssh_driver,
        }[driver]
        return await module.collect(host, username, password)
    if driver == "snmp":
        if not snmp_community:
            raise ValueError("driver 'snmp' needs a community string")
        return await snmp_driver.collect(host, snmp_community)
    raise ValueError(f"unknown LLDP driver '{driver}'")
