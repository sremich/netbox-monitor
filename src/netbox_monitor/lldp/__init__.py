"""LLDP collection drivers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LldpNeighbor:
    local_port: str  # interface name on the polled switch
    chassis_mac: str | None  # neighbor chassis id, when it is a MAC
    sysname: str | None  # neighbor system name
    remote_port: str | None  # neighbor port id (ifname or MAC string)
    remote_port_is_mac: bool = False
