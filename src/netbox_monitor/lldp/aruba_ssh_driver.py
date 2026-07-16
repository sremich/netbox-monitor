"""Aruba LLDP driver.

- ArubaOS-CX: ``show lldp neighbor-info detail`` (its own labelled format).
- ArubaOS-Switch / ProCurve: ``show lldp info remote-device`` uses the same
  Cisco-style detail block, so we reuse that parser.

We try the CX command first and fall back to the Cisco-style parser.
"""

from __future__ import annotations

import re

import structlog

from netbox_monitor.lldp import LldpNeighbor
from netbox_monitor.lldp.cisco_ssh_driver import parse_lldp_detail
from netbox_monitor.lldp.ssh_common import legacy_connect, run_command
from netbox_monitor.oui import normalize_mac

log = structlog.get_logger(__name__)

_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _cx_field(block: str, label: str) -> str:
    m = re.search(rf"(?im)^\s*{re.escape(label)}\s*:\s*(.*)$", block)
    return m.group(1).strip() if m else ""


def parse_cx_detail(output: str) -> list[LldpNeighbor]:
    """Parse ArubaOS-CX ``show lldp neighbor-info detail`` blocks."""
    parts = re.split(r"(?im)^(?=\s*(?:Port|Local Port)\s*:)", output)
    neighbors: list[LldpNeighbor] = []
    for block in parts:
        if "Chassis-ID" not in block and "Chassis ID" not in block:
            continue
        local = _cx_field(block, "Port") or _cx_field(block, "Local Port")
        chassis = _cx_field(block, "Chassis-ID") or _cx_field(block, "Chassis ID")
        port_id = _cx_field(block, "Port-ID") or _cx_field(block, "Port ID")
        sysname = _cx_field(block, "System-Name") or _cx_field(block, "System Name")
        caps_raw = (
            _cx_field(block, "System-Capabilities-Enabled")
            or _cx_field(block, "Enabled-Capabilities")
        ).lower()
        caps = {c.strip() for c in re.split(r"[,\s]+", caps_raw) if c.strip()}
        mgmt = _IPV4.search(
            _cx_field(block, "Management-Address") or _cx_field(block, "Mgmt-IP-Address")
        )
        neighbors.append(
            LldpNeighbor(
                local_port=local,
                chassis_mac=normalize_mac(chassis),
                sysname=sysname or None,
                remote_port=port_id or None,
                remote_port_is_mac=bool(normalize_mac(port_id)),
                mgmt_ip=mgmt.group(1) if mgmt else None,
                capabilities={"bridge"} if "bridge" in caps else caps,
                sys_descr=_cx_field(block, "System-Description") or None,
            )
        )
    return neighbors


async def collect(host: str, username: str, password: str) -> list[LldpNeighbor]:
    async with await legacy_connect(host, username, password) as conn:
        try:
            await run_command(conn, "no page", timeout=8)
        except Exception:
            pass
        output = await run_command(conn, "show lldp neighbor-info detail")
        neighbors = parse_cx_detail(output)
        if not neighbors:
            text = await run_command(conn, "show lldp info remote-device")
            neighbors = parse_lldp_detail(text)
    log.info("aruba lldp neighbors collected", host=host, count=len(neighbors))
    return neighbors
