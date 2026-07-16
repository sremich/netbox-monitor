"""LLDP collection drivers and the neighbor model."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# sys_descr / platform substrings that identify a device as a real switch worth
# crawling. Deliberately excludes generic Linux (Proxmox nodes advertise LLDP
# "bridge" capability but are not switches).
SWITCH_VENDOR_RE = re.compile(
    r"cisco|arista|aruba|procurve|hpe?\s|hewlett|mikrotik|routeros|ubiquiti|unifi|"
    r"edgeswitch|edgerouter|juniper|dell\s*(emc|networking)|fortiswitch|netgear|"
    r"brocade|extreme|force10|ruckus",
    re.IGNORECASE,
)


@dataclass
class LldpNeighbor:
    local_port: str  # interface name on the polled switch
    chassis_mac: str | None = None  # neighbor chassis id, when it is a MAC
    sysname: str | None = None  # neighbor system name
    remote_port: str | None = None  # neighbor port id (ifname or MAC string)
    remote_port_is_mac: bool = False
    mgmt_ip: str | None = None  # neighbor management IP (for crawling)
    capabilities: set[str] = field(default_factory=set)  # enabled caps, lowercased
    sys_descr: str | None = None  # system description (vendor identification)

    @property
    def is_bridge(self) -> bool:
        return "bridge" in self.capabilities

    def is_crawlable_switch(self) -> bool:
        """A neighbor worth authenticating to and crawling: advertises bridge
        capability AND its description matches a known switch vendor.

        The vendor gate is what stops the crawl from SSH-spraying Linux hosts
        (e.g. Proxmox nodes) that merely advertise ``bridge`` for their vmbr."""
        if not self.is_bridge or not self.mgmt_ip:
            return False
        text = f"{self.sys_descr or ''} {self.sysname or ''}"
        return bool(SWITCH_VENDOR_RE.search(text))
