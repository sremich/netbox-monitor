"""Small network helpers: ARP table reading, reverse DNS, hostname sanitizing."""

from __future__ import annotations

import asyncio
import re
import socket
import sys

import structlog

log = structlog.get_logger(__name__)

_HOSTNAME_OK = re.compile(r"[^A-Za-z0-9.-]")


def sanitize_dns_name(name: str | None) -> str:
    """NetBox dns_name only allows letters, digits, hyphens, dots."""
    if not name:
        return ""
    return _HOSTNAME_OK.sub("-", name.strip().rstrip(".")).strip("-").lower()


async def get_arp_table() -> dict[str, str]:
    """Return {ip: normalized_mac} from the OS neighbor/ARP table. Best-effort."""
    from netbox_monitor.oui import normalize_mac

    table: dict[str, str] = {}
    if sys.platform == "win32":
        cmd, pattern = ["arp", "-a"], re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s")
    else:
        cmd, pattern = (
            ["ip", "neigh", "show"],
            re.compile(r"^(\S+)\s.*lladdr\s+([0-9a-fA-F:]{17})\s"),
        )
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        for line in out.decode(errors="replace").splitlines():
            m = pattern.match(line)
            if m:
                mac = normalize_mac(m.group(2))
                if mac and mac != "00:00:00:00:00:00":
                    table[m.group(1)] = mac
    except Exception as exc:
        log.debug("ARP table read failed", error=str(exc))
    return table


async def reverse_dns(ip: str, timeout: float = 2.0) -> str | None:
    """Best-effort PTR lookup via the system resolver."""
    loop = asyncio.get_running_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout=timeout
        )
        return result[0]
    except Exception:
        return None
