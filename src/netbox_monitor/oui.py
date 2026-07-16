"""IEEE OUI database: MAC prefix -> manufacturer lookup.

Downloads the IEEE registry CSV on first use into the data dir and refreshes it
monthly. A small built-in table covers common home-lab vendors when offline.
"""

from __future__ import annotations

import csv
import io
import re
import time
from pathlib import Path

import httpx
import structlog

log = structlog.get_logger(__name__)

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
REFRESH_SECONDS = 30 * 24 * 3600

_BUILTIN = {
    "BCFCE7": "Proxmox Server Solutions GmbH",
    "F49FF3": "Ubiquiti Inc",
    "784558": "Ubiquiti Inc",
    "24A43C": "Ubiquiti Inc",
    "B827EB": "Raspberry Pi Foundation",
    "D83ADD": "Raspberry Pi Trading Ltd",
    "001132": "Synology Incorporated",
    "525400": "QEMU/KVM virtual NIC",
}


def normalize_mac(mac: str) -> str | None:
    """Normalize any common MAC format to AA:BB:CC:DD:EE:FF, or None if invalid."""
    hexonly = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(hexonly) != 12:
        return None
    hexonly = hexonly.upper()
    return ":".join(hexonly[i : i + 2] for i in range(0, 12, 2))


class OuiDB:
    def __init__(self, data_dir: str | Path):
        self.path = Path(data_dir) / "oui.csv"
        self._table: dict[str, str] = dict(_BUILTIN)
        self._loaded = False

    async def ensure_loaded(self) -> None:
        if not self._loaded:
            if self._needs_refresh():
                await self._download()
            self._parse()
            self._loaded = True

    def _needs_refresh(self) -> bool:
        try:
            return time.time() - self.path.stat().st_mtime > REFRESH_SECONDS
        except FileNotFoundError:
            return True

    async def _download(self) -> None:
        log.info("downloading IEEE OUI database", url=OUI_URL)
        try:
            async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
                resp = await client.get(OUI_URL)
                resp.raise_for_status()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_bytes(resp.content)
            log.info("OUI database saved", bytes=len(resp.content))
        except Exception as exc:
            log.warning("OUI download failed; using cached/builtin table", error=str(exc))

    def _parse(self) -> None:
        if not self.path.exists():
            return
        try:
            text = self.path.read_text(encoding="utf-8", errors="replace")
            reader = csv.DictReader(io.StringIO(text))
            count = 0
            for row in reader:
                assignment = (row.get("Assignment") or "").strip().upper()
                org = (row.get("Organization Name") or "").strip()
                if len(assignment) == 6 and org:
                    self._table[assignment] = org
                    count += 1
            log.info("OUI database loaded", entries=count)
        except Exception as exc:
            log.warning("OUI parse failed; using builtin table", error=str(exc))

    def lookup(self, mac: str | None) -> str | None:
        normalized = normalize_mac(mac or "")
        if not normalized:
            return None
        # Locally administered MACs (bit 1 of first octet) are usually VMs/randomized.
        first_octet = int(normalized[:2], 16)
        prefix = normalized.replace(":", "")[:6]
        vendor = self._table.get(prefix)
        if vendor is None and first_octet & 0x02:
            return "Locally administered (VM/randomized)"
        return vendor
