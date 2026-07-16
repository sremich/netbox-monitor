"""Cisco-style LLDP driver: SSH + ``show lldp neighbors detail``.

The per-neighbor detail block format is shared by Cisco IOS/IOS-XE/NX-OS and
ArubaOS-Switch (ProCurve), so this parser backs both vendors.

Sample block::

    Local Intf: Gi1/0/1
    Chassis id: aabb.ccdd.eeff
    Port id: GigabitEthernet0/1
    Port Description: uplink
    System Name: core-sw
    System Description:
    Cisco IOS Software, ...
    Time remaining: 99 seconds
    System Capabilities: B,R
    Enabled Capabilities: B,R
    Management Addresses:
        IP: 10.0.0.2
"""

from __future__ import annotations

import re

import structlog

from netbox_monitor.lldp import LldpNeighbor
from netbox_monitor.lldp.ssh_common import legacy_connect, run_command
from netbox_monitor.oui import normalize_mac

log = structlog.get_logger(__name__)

_CAP_MAP = {
    "b": "bridge",
    "r": "router",
    "w": "wlan-ap",
    "t": "telephone",
    "c": "docsis",
    "s": "station",
    "p": "repeater",
    "o": "other",
}
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _field(block: str, label: str) -> str:
    m = re.search(rf"(?im)^\s*{re.escape(label)}\s*:\s*(.*)$", block)
    return m.group(1).strip() if m else ""


def _caps(block: str) -> set[str]:
    raw = _field(block, "Enabled Capabilities") or _field(block, "System Capabilities")
    caps: set[str] = set()
    for token in re.split(r"[,\s]+", raw):
        token = token.strip().lower()
        if token in _CAP_MAP:
            caps.add(_CAP_MAP[token])
        elif token in _CAP_MAP.values():
            caps.add(token)
    return caps


def _mgmt_ip(block: str) -> str | None:
    # "Management Addresses:" section, or an inline "IP: x.x.x.x"
    m = re.search(r"(?is)Management Address(?:es)?\s*:\s*(.*?)(?:\n\s*\n|\Z)", block)
    region = m.group(1) if m else block
    ip = _IPV4.search(region)
    return ip.group(1) if ip else None


def parse_lldp_detail(output: str) -> list[LldpNeighbor]:
    # split into per-neighbor blocks, keeping the "Local Intf" anchor via lookahead
    parts = re.split(r"(?im)^(?=\s*Local In(?:tf|terface)\s*:)", output)
    neighbors: list[LldpNeighbor] = []
    for block in parts:
        if "Chassis id" not in block and "Port id" not in block:
            continue
        local = _field(block, "Local Intf") or _field(block, "Local Interface")
        chassis = _field(block, "Chassis id")
        port_id = _field(block, "Port id")
        sysname = _field(block, "System Name")
        descr_m = re.search(
            r"(?is)System Description\s*:\s*\n?(.*?)(?:\n\s*(?:Time remaining|System Capabilities|"
            r"Management Address|Local In|Chassis id)\b)",
            block,
        )
        sys_descr = (descr_m.group(1).strip() if descr_m else "") or None
        if not local and not chassis:
            continue
        neighbors.append(
            LldpNeighbor(
                local_port=local,
                chassis_mac=normalize_mac(chassis),
                sysname=sysname or None,
                remote_port=port_id or None,
                remote_port_is_mac=bool(normalize_mac(port_id)),
                mgmt_ip=_mgmt_ip(block),
                capabilities=_caps(block),
                sys_descr=sys_descr,
            )
        )
    return neighbors


async def collect(host: str, username: str, password: str) -> list[LldpNeighbor]:
    async with await legacy_connect(host, username, password) as conn:
        # disable paging where the exec channel honors it; harmless otherwise
        try:
            await run_command(conn, "terminal length 0", timeout=8)
        except Exception:
            pass
        output = await run_command(conn, "show lldp neighbors detail")
    neighbors = parse_lldp_detail(output)
    log.info("cisco-style lldp neighbors collected", host=host, count=len(neighbors))
    return neighbors
