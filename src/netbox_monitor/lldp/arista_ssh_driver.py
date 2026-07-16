"""Arista EOS LLDP driver: SSH + ``show lldp neighbors detail | json``.

EOS emits structured JSON, so no text scraping. Falls back to the Cisco-style
text parser if JSON isn't available on the box.
"""

from __future__ import annotations

import json

import structlog

from netbox_monitor.lldp import LldpNeighbor
from netbox_monitor.lldp.cisco_ssh_driver import parse_lldp_detail
from netbox_monitor.lldp.ssh_common import legacy_connect, run_command
from netbox_monitor.oui import normalize_mac

log = structlog.get_logger(__name__)

_CAP_MAP = {
    "bridge": "bridge",
    "router": "router",
    "wlanAccessPoint": "wlan-ap",
    "telephone": "telephone",
}


def parse_lldp_json(payload: str) -> list[LldpNeighbor]:
    data = json.loads(payload)
    neighbors: list[LldpNeighbor] = []
    for local_port, info in (data.get("lldpNeighbors") or {}).items():
        for entry in info.get("lldpNeighborInfo", []):
            chassis = entry.get("chassisId", "")
            caps = {
                _CAP_MAP.get(k, k.lower())
                for k, v in (entry.get("systemCapabilities") or {}).items()
                if v
            }
            mgmt = None
            for addr in entry.get("managementAddresses", []) or []:
                if addr.get("addressType") in ("ipv4", "IPV4") or "." in str(
                    addr.get("address", "")
                ):
                    mgmt = addr.get("address")
                    break
            neighbors.append(
                LldpNeighbor(
                    local_port=local_port,
                    chassis_mac=normalize_mac(chassis),
                    sysname=entry.get("systemName") or None,
                    remote_port=entry.get("neighborInterfaceInfo", {}).get("interfaceId")
                    or entry.get("portId")
                    or None,
                    mgmt_ip=mgmt,
                    capabilities=caps,
                    sys_descr=entry.get("systemDescription") or None,
                )
            )
    return neighbors


async def collect(host: str, username: str, password: str) -> list[LldpNeighbor]:
    async with await legacy_connect(host, username, password) as conn:
        output = await run_command(conn, "show lldp neighbors detail | json")
        stripped = output.strip()
        if stripped.startswith("{"):
            neighbors = parse_lldp_json(stripped)
        else:
            # older EOS without JSON, or a Cisco-style box mis-tagged as arista
            text = await run_command(conn, "show lldp neighbors detail")
            neighbors = parse_lldp_detail(text)
    log.info("arista lldp neighbors collected", host=host, count=len(neighbors))
    return neighbors
