"""UniFi SSH LLDP driver: UniFi switches run Linux with lldpd, so we SSH in and
parse ``lldpcli show neighbors -f json``.
"""

from __future__ import annotations

import json
import re
from typing import Any

import asyncssh
import structlog

from netbox_monitor.lldp import LldpNeighbor
from netbox_monitor.oui import normalize_mac

log = structlog.get_logger(__name__)

COMMANDS = [
    "lldpcli show neighbors details -f json",
    "lldpcli show neighbors -f json",
    "lldpctl -f json",
]


def _as_items(value: Any) -> list[tuple[str, dict]]:
    """lldpd JSON is inconsistent: dicts keyed by name, or lists of such dicts."""
    if isinstance(value, dict):
        return list(value.items())
    if isinstance(value, list):
        items: list[tuple[str, dict]] = []
        for entry in value:
            if isinstance(entry, dict):
                items.extend(entry.items())
        return items
    return []


def _first(value: Any) -> Any:
    return value[0] if isinstance(value, list) and value else value


def parse_lldpcli_json(payload: str) -> list[LldpNeighbor]:
    data = json.loads(payload)
    neighbors: list[LldpNeighbor] = []
    interfaces = (data.get("lldp") or {}).get("interface") or []
    for ifname, detail in _as_items(interfaces):
        if not isinstance(detail, dict):
            continue
        sysname = None
        chassis_mac = None
        mgmt_ip = None
        caps: set[str] = set()
        sys_descr = None
        chassis = detail.get("chassis") or {}
        if isinstance(chassis, dict):
            # either {"<sysname>": {...}} or a flat {"id": ..., "name": ...}
            if "id" in chassis or "name" in chassis:
                chassis_entries = [(chassis.get("name"), chassis)]
            else:
                chassis_entries = list(chassis.items())
            for name, body in chassis_entries:
                sysname = name if isinstance(name, str) else sysname
                if isinstance(body, dict):
                    cid = _first(body.get("id"))
                    if isinstance(cid, dict) and cid.get("type") == "mac":
                        chassis_mac = normalize_mac(str(cid.get("value", "")))
                    if not sysname and isinstance(body.get("name"), str):
                        sysname = body["name"]
                    descr = body.get("descr")
                    if isinstance(descr, str):
                        sys_descr = descr
                    mgmt = _first(body.get("mgmt-ip"))
                    if isinstance(mgmt, dict):
                        mgmt = mgmt.get("value")
                    if isinstance(mgmt, str) and "." in mgmt:
                        mgmt_ip = mgmt
                    for cap in body.get("capability") or []:
                        if isinstance(cap, dict) and cap.get("enabled") in (True, "on", "yes"):
                            ctype = str(cap.get("type", "")).lower()
                            caps.add("bridge" if ctype == "bridge" else ctype)
                break

        remote_port = None
        remote_port_is_mac = False
        port = detail.get("port") or {}
        if isinstance(port, dict):
            pid = _first(port.get("id"))
            if isinstance(pid, dict):
                remote_port = str(pid.get("value", "")) or None
                remote_port_is_mac = pid.get("type") == "mac"
            descr = port.get("descr")
            if remote_port_is_mac and isinstance(descr, str) and descr:
                # prefer the human-readable port description over a MAC when present
                remote_port, remote_port_is_mac = descr, False

        neighbors.append(
            LldpNeighbor(
                local_port=ifname,
                chassis_mac=chassis_mac,
                sysname=sysname,
                remote_port=remote_port,
                remote_port_is_mac=remote_port_is_mac,
                mgmt_ip=mgmt_ip,
                capabilities=caps,
                sys_descr=sys_descr,
            )
        )
    return neighbors


async def collect(host: str, username: str, password: str) -> list[LldpNeighbor]:
    async with asyncssh.connect(
        host,
        username=username,
        password=password,
        known_hosts=None,  # home-lab switches; host keys unmanaged
        connect_timeout=10,
    ) as conn:
        last_error = ""
        for command in COMMANDS:
            result = await conn.run(command, check=False)
            stdout = (result.stdout or "").strip()
            if result.exit_status == 0 and stdout.startswith("{"):
                neighbors = parse_lldpcli_json(stdout)
                log.info("unifi lldp neighbors collected", host=host, count=len(neighbors))
                return neighbors
            last_error = (result.stderr or stdout or "").strip()[:200]
        raise RuntimeError(f"no lldp output from {host}: {last_error}")


def parse_ip_link(output: str) -> dict[str, str | None]:
    """MAC -> interface name pairs from busybox/iproute2 `ip link` output."""
    macs: dict[str, str | None] = {}
    current: str | None = None
    for line in output.splitlines():
        head = re.match(r"^\d+:\s+([^:@\s]+)", line)
        if head:
            current = head.group(1)
            continue
        ether = re.search(r"link/ether\s+([0-9A-Fa-f:]{17})", line)
        if ether:
            mac = normalize_mac(ether.group(1))
            if mac:
                macs.setdefault(mac, current)
    return macs


async def collect_local_macs(host: str, username: str, password: str) -> dict[str, str | None]:
    """The device's own interface MACs (br0 carries the LLDP chassis id)."""
    async with asyncssh.connect(
        host, username=username, password=password, known_hosts=None, connect_timeout=10
    ) as conn:
        result = await conn.run("ip link", check=False)
    return parse_ip_link(result.stdout or "")
