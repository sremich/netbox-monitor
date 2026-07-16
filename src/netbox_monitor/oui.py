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
# IEEE rejects non-browser clients (HTTP 418), so present a browser UA
OUI_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
}
FALLBACK_URL = "https://www.wireshark.org/download/automated/data/manuf"
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
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
            for url, headers in ((OUI_URL, OUI_HEADERS), (FALLBACK_URL, {})):
                log.info("downloading OUI database", url=url)
                try:
                    resp = await client.get(url, headers=headers)
                    resp.raise_for_status()
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                    self.path.write_bytes(resp.content)
                    log.info("OUI database saved", url=url, bytes=len(resp.content))
                    return
                except Exception as exc:
                    log.warning("OUI download failed", url=url, error=str(exc))
        log.warning("all OUI sources failed; using cached/builtin table")

    def _parse(self) -> None:
        if not self.path.exists():
            return
        try:
            text = self.path.read_text(encoding="utf-8", errors="replace")
            count = self._parse_ieee_csv(text) or self._parse_wireshark_manuf(text)
            log.info("OUI database loaded", entries=count)
        except Exception as exc:
            log.warning("OUI parse failed; using builtin table", error=str(exc))

    def _parse_ieee_csv(self, text: str) -> int:
        count = 0
        for row in csv.DictReader(io.StringIO(text)):
            assignment = (row.get("Assignment") or "").strip().upper()
            org = (row.get("Organization Name") or "").strip()
            if len(assignment) == 6 and org:
                self._table[assignment] = org
                count += 1
        return count

    def _parse_wireshark_manuf(self, text: str) -> int:
        """Wireshark manuf format: 'BC:24:11<tab>ShortName<tab>Full Name'."""
        count = 0
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            prefix = re.sub(r"[^0-9A-Fa-f]", "", parts[0].split("/")[0]).upper()
            org = (parts[2] if len(parts) > 2 and parts[2].strip() else parts[1]).strip()
            if len(prefix) == 6 and org:
                self._table[prefix] = org
                count += 1
        return count

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
