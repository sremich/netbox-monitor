"""Async client for the Technitium DNS Server HTTP API.

All endpoints return ``{"status": "ok", "response": {...}}``; anything else raises.
API docs: https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from netbox_monitor.config import TechnitiumConfig

log = structlog.get_logger(__name__)


class TechnitiumError(RuntimeError):
    pass


class TechnitiumClient:
    def __init__(self, config: TechnitiumConfig):
        self.config = config
        self._client = httpx.AsyncClient(base_url=config.url, timeout=30.0)

    async def close(self) -> None:
        await self._client.aclose()

    async def _call(self, path: str, **params: Any) -> dict[str, Any]:
        params = {k: v for k, v in params.items() if v is not None}
        params["token"] = self.config.token
        resp = await self._client.get(path, params=params)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "ok":
            raise TechnitiumError(
                f"{path}: {data.get('errorMessage') or data.get('status') or 'unknown error'}"
            )
        return data.get("response", {})

    # ------------------------------------------------------------------- DNS

    async def list_zones(self) -> list[dict[str, Any]]:
        zones: list[dict[str, Any]] = []
        page = 1
        while True:
            resp = await self._call("/api/zones/list", pageNumber=page, zonesPerPage=100)
            zones.extend(resp.get("zones", []))
            total_pages = resp.get("totalPages")
            if not total_pages or page >= total_pages:
                break
            page += 1
        return zones

    async def get_zone_records(self, zone: str) -> list[dict[str, Any]]:
        resp = await self._call("/api/zones/records/get", domain=zone, zone=zone, listZone="true")
        return resp.get("records", [])

    # ------------------------------------------------------------------ DHCP

    async def list_dhcp_scopes(self) -> list[dict[str, Any]]:
        resp = await self._call("/api/dhcp/scopes/list")
        return resp.get("scopes", [])

    async def get_dhcp_scope(self, name: str) -> dict[str, Any]:
        return await self._call("/api/dhcp/scopes/get", name=name)

    async def list_dhcp_leases(self) -> list[dict[str, Any]]:
        resp = await self._call("/api/dhcp/leases/list")
        return resp.get("leases", [])
