"""Ping discovery: sweep NetBox prefixes that are NOT covered by Technitium DHCP
scopes, and document every responding host as a Device in NetBox.

Enrichment per host: MAC (OS ARP/neighbor table, L2-adjacent subnets only),
manufacturer (IEEE OUI), hostname (reverse DNS).
"""

from __future__ import annotations

import asyncio
import ipaddress

import structlog
from icmplib import async_multiping

from netbox_monitor.context import Context
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
        await self.ctx.oui.ensure_loaded()
        targets = await self._build_targets()
        if not targets:
            log.info("no discovery targets (check prefixes in NetBox / include list)")
            return
        cfg = self.ctx.config.discovery
        log.info("pinging targets", count=len(targets))
        results = await async_multiping(
            targets,
            count=2,
            interval=0.1,
            timeout=cfg.ping_timeout,
            concurrent_tasks=cfg.concurrency,
            privileged=True,
        )
        alive = [r.address for r in results if r.is_alive]
        log.info("discovery sweep done", alive=len(alive), scanned=len(targets))
        if not alive:
            return

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
                    mac=mac,
                    vendor=vendor,
                    dns_name=rdns,
                    description="Discovered by ping sweep",
                )
            except Exception:
                log.exception("failed to document discovered host", ip=ip)
                continue
            await self.ctx.state.record_check(f"ip:{ip}", up=True)

    # ----------------------------------------------------------------- setup

    async def _build_targets(self) -> list[str]:
        """All host IPs in scannable prefixes, minus Technitium DHCP scope ranges."""
        cfg = self.ctx.config.discovery

        dhcp_ranges: list[tuple[int, int]] = []
        try:
            for scope in await self.ctx.technitium.list_dhcp_scopes():
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
            log.warning("could not fetch DHCP scopes; scanning full prefixes", error=str(exc))

        nb = self.ctx.netbox

        def fetch_prefixes() -> list[str]:
            with nb.lock:
                return [str(p.prefix) for p in nb.api.ipam.prefixes.filter(status="active")]

        prefixes = await asyncio.to_thread(fetch_prefixes)

        include = [ipaddress.ip_network(p) for p in cfg.include_prefixes]
        exclude = [ipaddress.ip_network(p) for p in cfg.exclude_prefixes]

        targets: list[str] = []
        for prefix_str in prefixes:
            network = ipaddress.ip_network(prefix_str)
            if network.version != 4:
                continue
            if include and not any(network.subnet_of(i) for i in include):
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
