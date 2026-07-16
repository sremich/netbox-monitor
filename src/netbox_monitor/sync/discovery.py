"""Ping discovery, per site: sweep the site's prefixes that are NOT covered by its
Technitium DHCP scopes, and document every responding host as a Device in NetBox.

Scan scope per site: the site's ``include_prefixes`` (picked in the web UI); when
empty, all NetBox prefixes scoped to that site; minus ``exclude_prefixes`` and the
site's live DHCP ranges.

Enrichment per host: MAC (OS ARP/neighbor table, L2-adjacent subnets only),
manufacturer (IEEE OUI), hostname (reverse DNS).
"""

from __future__ import annotations

import asyncio
import ipaddress
import time

import structlog
from icmplib import async_multiping

from netbox_monitor.context import Context, ResolvedSite
from netbox_monitor.net_utils import get_arp_table, reverse_dns, sanitize_dns_name
from netbox_monitor.sync.common import ensure_host_device
from netbox_monitor.sync.dhcp import scope_network

log = structlog.get_logger(__name__)

SRC = "src-scan"


class DiscoverySync:
    name = "discovery"

    def __init__(self, ctx: Context):
        self.ctx = ctx

    async def run(self) -> None:
        sites = [s for s in self.ctx.sites if s.config.discovery.enabled]
        if not sites:
            log.info("no sites with discovery enabled")
            return
        await self.ctx.oui.ensure_loaded()
        for site in sites:
            started = time.monotonic()
            try:
                found = await self._scan_site(site)
                await self.ctx.status.record(
                    self.name,
                    site.config.id,
                    True,
                    f"{found} hosts alive",
                    time.monotonic() - started,
                )
            except Exception as exc:
                log.exception("discovery failed for site", site=site.config.id)
                await self.ctx.status.record(
                    self.name, site.config.id, False, str(exc), time.monotonic() - started
                )

    async def _scan_site(self, site: ResolvedSite) -> int:
        targets = await self._build_targets(site)
        if not targets:
            log.info("no discovery targets for site", site=site.config.id)
            return 0
        cfg = self.ctx.config.discovery
        log.info("pinging targets", site=site.config.id, count=len(targets))
        results = await async_multiping(
            targets,
            count=2,
            interval=0.1,
            timeout=cfg.ping_timeout,
            concurrent_tasks=cfg.concurrency,
            privileged=True,
        )
        alive = [r.address for r in results if r.is_alive]
        log.info(
            "discovery sweep done", site=site.config.id, alive=len(alive), scanned=len(targets)
        )
        if not alive:
            return 0

        arp = await get_arp_table()
        for ip in alive:
            mac = arp.get(ip)
            vendor = self.ctx.oui.lookup(mac) if mac else None
            rdns = sanitize_dns_name(await reverse_dns(ip))
            name = rdns.split(".")[0] if rdns else f"discovered-{ip.replace('.', '-')}"
            try:
                await asyncio.to_thread(
                    ensure_host_device,
                    self.ctx.netbox,
                    name=name,
                    ip=ip,
                    source_slug=SRC,
                    site_id=site.netbox_site_id,
                    mac=mac,
                    vendor=vendor,
                    dns_name=rdns,
                    description="Discovered by ping sweep",
                )
            except Exception:
                log.exception("failed to document discovered host", ip=ip)
                continue
            await self.ctx.state.record_check(f"ip:{ip}", up=True)
        return len(alive)

    # ----------------------------------------------------------------- setup

    async def _site_prefixes(self, site: ResolvedSite) -> list[str]:
        """The site's scan candidates: explicit include list, else NetBox prefixes
        scoped to the site's NetBox Site. A single-site deployment whose prefixes
        aren't site-scoped falls back to all active prefixes (v1 behavior)."""
        if site.config.discovery.include_prefixes:
            return list(site.config.discovery.include_prefixes)
        if site.netbox_site_id is None:
            return []
        nb = self.ctx.netbox

        def fetch() -> list[str]:
            with nb.lock:
                try:
                    scoped = [
                        str(p.prefix)
                        for p in nb.api.ipam.prefixes.filter(
                            status="active",
                            scope_type="dcim.site",
                            scope_id=site.netbox_site_id,
                        )
                    ]
                except Exception:
                    # older NetBox: prefixes have a site FK instead of a scope
                    scoped = [
                        str(p.prefix)
                        for p in nb.api.ipam.prefixes.filter(
                            status="active", site_id=site.netbox_site_id
                        )
                    ]
            if not scoped and len(self.ctx.sites) == 1:
                log.info(
                    "no prefixes scoped to the NetBox site; single-site setup falls "
                    "back to all active prefixes (pick include prefixes in the UI "
                    "to narrow this)",
                    site=site.config.id,
                )
                with nb.lock:
                    return [str(p.prefix) for p in nb.api.ipam.prefixes.filter(status="active")]
            return scoped

        return await asyncio.to_thread(fetch)

    async def _build_targets(self, site: ResolvedSite) -> list[str]:
        cfg = self.ctx.config.discovery

        dhcp_ranges: list[tuple[int, int]] = []
        if site.technitium is not None:
            try:
                for scope in await site.technitium.list_dhcp_scopes():
                    network = scope_network(scope)
                    start = scope.get("startingAddress")
                    end = scope.get("endingAddress")
                    if start and end:
                        dhcp_ranges.append(
                            (int(ipaddress.ip_address(start)), int(ipaddress.ip_address(end)))
                        )
                    elif network:
                        dhcp_ranges.append(
                            (int(network.network_address), int(network.broadcast_address))
                        )
            except Exception as exc:
                log.warning(
                    "could not fetch DHCP scopes; scanning full prefixes",
                    site=site.config.id,
                    error=str(exc),
                )

        prefixes = await self._site_prefixes(site)
        exclude = [ipaddress.ip_network(p) for p in site.config.discovery.exclude_prefixes]

        targets: list[str] = []
        for prefix_str in prefixes:
            network = ipaddress.ip_network(prefix_str)
            if network.version != 4:
                continue
            if any(network.subnet_of(e) for e in exclude):
                continue
            count = 0
            for host in network.hosts():
                if count >= cfg.max_hosts_per_prefix:
                    log.warning("prefix truncated by max_hosts_per_prefix", prefix=prefix_str)
                    break
                as_int = int(host)
                if any(lo <= as_int <= hi for lo, hi in dhcp_ranges):
                    continue
                targets.append(str(host))
                count += 1
        return targets
