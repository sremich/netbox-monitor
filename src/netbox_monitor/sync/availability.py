"""Availability monitor: continually ping hosts documented by discovery / DHCP
reservations; tag them ``stale`` + status offline after 10 minutes unreachable,
and bring them back when they respond again.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog
from icmplib import async_multiping

from netbox_monitor.clients.netbox import MANAGED_TAG_SLUG, STALE_TAG_SLUG
from netbox_monitor.context import Context
from netbox_monitor.sync.common import ip_in_networks, now_iso, parse_ipv4_networks

log = structlog.get_logger(__name__)

MONITORED_SOURCES = ("src-scan", "src-dhcp")
LAST_SEEN_WRITE_INTERVAL = 900  # avoid a NetBox write per host per minute


class AvailabilitySync:
    name = "availability"

    def __init__(self, ctx: Context):
        self.ctx = ctx

    async def run(self) -> None:
        devices = await asyncio.to_thread(self._monitored_devices)
        if not devices:
            log.info("no monitored devices yet")
            return
        cfg = self.ctx.config.availability

        # An excluded prefix means "don't touch this network" — discovery already
        # skips it, and it must not be polled either. This module is global (it
        # doesn't track each device's site), so the key is the union of every
        # configured site's exclude list; for a single-site setup that's exact.
        excluded = parse_ipv4_networks(
            prefix for site in self.ctx.sites for prefix in site.config.discovery.exclude_prefixes
        )

        ip_to_device: dict[str, Any] = {}
        skipped = 0
        for device in devices:
            primary = getattr(device, "primary_ip4", None) or getattr(device, "primary_ip", None)
            if not primary:
                continue
            ip = str(primary.address).split("/")[0]
            if ip_in_networks(ip, excluded):
                skipped += 1
                continue
            ip_to_device[ip] = device

        if skipped:
            log.info("availability: skipped hosts in excluded prefixes", count=skipped)
        if not ip_to_device:
            return
        results = await async_multiping(
            list(ip_to_device),
            count=2,
            interval=0.1,
            timeout=cfg.ping_timeout,
            concurrent_tasks=cfg.concurrency,
            privileged=True,
        )
        now = time.time()
        up = down = 0
        for result in results:
            device = ip_to_device[result.address]
            key = f"device:{device.id}"
            state = await self.ctx.state.record_check(key, result.is_alive, now)
            if result.is_alive:
                up += 1
                await self._handle_up(device, key, now)
            else:
                down += 1
                await self._handle_down(device, key, state.last_seen, now)
        log.info("availability pass complete", up=up, down=down)

    async def _handle_up(self, device: Any, key: str, now: float) -> None:
        nb = self.ctx.netbox
        await self.ctx.state.delete_kv(f"firstdown:{key}")
        was_stale = STALE_TAG_SLUG in nb.obj_tag_slugs(device)
        if was_stale:
            log.info("host recovered", device=device.name)

            def recover() -> None:
                nb.remove_tags(device, STALE_TAG_SLUG)
                nb.update(device, {"status": "active"}, reason="host reachable again")
                nb.set_custom_fields(device, last_seen=now_iso())
                nb.journal(device, "Host reachable again; stale tag removed")

            await asyncio.to_thread(recover)
            return
        # throttle last_seen writes
        last_write = await self.ctx.state.get_kv(f"lastseen-write:{key}")
        if last_write is None or now - float(last_write) > LAST_SEEN_WRITE_INTERVAL:
            await asyncio.to_thread(self.ctx.netbox.set_custom_fields, device, last_seen=now_iso())
            await self.ctx.state.set_kv(f"lastseen-write:{key}", str(now))

    async def _handle_down(
        self, device: Any, key: str, last_seen: float | None, now: float
    ) -> None:
        nb = self.ctx.netbox
        stale_after = self.ctx.config.availability.stale_after
        already_stale = STALE_TAG_SLUG in nb.obj_tag_slugs(device)
        if already_stale:
            await self._maybe_grace_delete(device, key, last_seen, now)
            return
        # never seen up: only stale it once it has been failing beyond the threshold
        unreachable_for = now - last_seen if last_seen else None
        if unreachable_for is not None and unreachable_for < stale_after:
            return
        if unreachable_for is None:
            state = await self.ctx.state.get_host(key)
            first_check = state.last_checked if state else now
            # without a last_seen baseline, wait stale_after from first observation
            marker = await self.ctx.state.get_kv(f"firstdown:{key}")
            if marker is None:
                await self.ctx.state.set_kv(f"firstdown:{key}", str(first_check or now))
                return
            if now - float(marker) < stale_after:
                return

        log.warning("host unreachable beyond threshold; tagging stale", device=device.name)

        def mark_stale() -> None:
            nb.add_tags(device, STALE_TAG_SLUG)
            nb.update(device, {"status": "offline"}, reason="unreachable > stale threshold")
            nb.journal(
                device,
                f"Unreachable for over {stale_after}s; tagged stale and set offline",
                kind="warning",
            )

        await asyncio.to_thread(mark_stale)
        await self.ctx.state.set_stale(key, True)

    async def _maybe_grace_delete(
        self, device: Any, key: str, last_seen: float | None, now: float
    ) -> None:
        """Delete discovered (src-scan) devices that have stayed stale beyond the
        configured grace period. Only applies to ping-discovered hosts — reserved
        DHCP infrastructure is never auto-deleted."""
        grace_days = self.ctx.config.lifecycle.stale_grace_delete_days
        if not grace_days or last_seen is None:
            return
        if "src-scan" not in self.ctx.netbox.obj_tag_slugs(device):
            return
        if (now - last_seen) < grace_days * 86400:
            return
        nb = self.ctx.netbox
        log.warning(
            "discovered host stale beyond grace period; deleting",
            device=device.name,
            days=grace_days,
        )

        def do_delete() -> None:
            primary = getattr(device, "primary_ip4", None)
            if primary and nb.is_managed(nb.api.ipam.ip_addresses.get(primary.id), "src-scan"):
                nb.delete(nb.api.ipam.ip_addresses.get(primary.id), "src-scan")
            nb.delete(device, "src-scan")

        await asyncio.to_thread(do_delete)
        await self.ctx.state.forget_host(key)

    def _monitored_devices(self) -> list[Any]:
        nb = self.ctx.netbox
        devices = nb.filter_tagged(nb.api.dcim.devices, MANAGED_TAG_SLUG)
        return [d for d in devices if nb.obj_tag_slugs(d) & set(MONITORED_SOURCES)]
