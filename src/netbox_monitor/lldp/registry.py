"""Driver registry: pick an LLDP driver by platform/vendor and collect neighbors
through one unified call.
"""

from __future__ import annotations

import asyncio
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


_SSH_MODULES = {
    "cisco": cisco_ssh_driver,
    "arista": arista_ssh_driver,
    "aruba": aruba_ssh_driver,
    "mikrotik": mikrotik_ssh_driver,
    "unifi": unifi_ssh_driver,
}


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
        return await _SSH_MODULES[driver].collect(host, username, password)
    if driver == "snmp":
        if not snmp_community:
            raise ValueError("driver 'snmp' needs a community string")
        return await snmp_driver.collect(host, snmp_community)
    raise ValueError(f"unknown LLDP driver '{driver}'")


async def collect_local_macs(
    driver: str,
    host: str,
    *,
    username: str = "",
    password: str = "",
    snmp_community: str = "",
) -> dict[str, str | None]:
    """The polled switch's OWN MAC addresses (chassis/bridge/interface), mapped to
    an interface name where the driver knows one.

    LLDP neighbor tables only carry *remote* chassis ids, so a directly-polled
    switch never learns its own — which is what lets the same physical box get
    documented twice under two management IPs. Best-effort by design: an
    unsupported driver or any failure returns {} and the crawl carries on.
    """
    try:
        if driver in SSH_DRIVERS:
            fn = getattr(_SSH_MODULES[driver], "collect_local_macs", None)
            if fn is None:
                return {}
            return await asyncio.wait_for(fn(host, username, password), timeout=25)
        if driver == "snmp":
            return await asyncio.wait_for(
                snmp_driver.collect_local_macs(host, snmp_community), timeout=25
            )
    except Exception as exc:
        log.debug("local MAC collection failed", host=host, driver=driver, error=str(exc))
    return {}
