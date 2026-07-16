"""MikroTik RouterOS LLDP driver: SSH + ``/ip neighbor print detail``.

RouterOS reports LLDP/CDP/MNDP neighbors with management IP, MAC, identity,
capabilities and system description in one command — everything the crawl needs.
"""

from __future__ import annotations

import re

import structlog

from netbox_monitor.lldp import LldpNeighbor
from netbox_monitor.lldp.ssh_common import legacy_connect, run_command
from netbox_monitor.oui import normalize_mac

log = structlog.get_logger(__name__)

# `/ip neighbor print detail` prints numbered records; a new record starts with
# an integer index at the start of a line, fields are key=value (values may be
# quoted and wrap across lines).
_RECORD_SPLIT = re.compile(r"(?m)^\s*\d+\s+")
_KV = re.compile(r'(\S+?)=("(?:[^"]*)"|\S+)')


def _parse_record(blob: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key, value in _KV.findall(blob):
        fields[key] = value.strip('"')
    return fields


def parse_ip_neighbor(output: str) -> list[LldpNeighbor]:
    neighbors: list[LldpNeighbor] = []
    for chunk in _RECORD_SPLIT.split(output):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        fields = _parse_record(chunk.replace("\n", " "))
        discovered_by = fields.get("discovered-by", "")
        if "lldp" not in discovered_by and "cdp" not in discovered_by:
            continue  # skip pure MNDP (RouterOS-to-RouterOS proprietary) entries
        caps = {
            c.strip().lower() for c in fields.get("system-caps-enabled", "").split(",") if c.strip()
        }
        neighbors.append(
            LldpNeighbor(
                local_port=fields.get("interface", "").split(",")[0],
                chassis_mac=normalize_mac(fields.get("mac-address", "")),
                sysname=fields.get("identity") or None,
                remote_port=fields.get("interface-name") or None,
                mgmt_ip=fields.get("address4") or fields.get("address") or None,
                capabilities=caps,
                sys_descr=fields.get("system-description") or fields.get("platform") or None,
            )
        )
    return neighbors


async def collect(host: str, username: str, password: str) -> list[LldpNeighbor]:
    async with await legacy_connect(host, username, password) as conn:
        output = await run_command(conn, "/ip neighbor print detail")
    neighbors = parse_ip_neighbor(output)
    log.info("mikrotik lldp neighbors collected", host=host, count=len(neighbors))
    return neighbors
