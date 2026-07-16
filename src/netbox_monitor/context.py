"""Shared runtime context handed to every sync module."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import structlog

from netbox_monitor.clients.netbox import NetBoxClient, slugify
from netbox_monitor.clients.technitium import TechnitiumClient
from netbox_monitor.config import AppConfig, SiteConfig
from netbox_monitor.oui import OuiDB
from netbox_monitor.state import StateDB
from netbox_monitor.status import StatusRegistry

log = structlog.get_logger(__name__)


@dataclass
class ResolvedSite:
    config: SiteConfig
    netbox_site_id: int | None = None
    technitium: TechnitiumClient | None = None


@dataclass
class Context:
    config: AppConfig
    netbox: NetBoxClient
    state: StateDB
    oui: OuiDB
    status: StatusRegistry
    sites: list[ResolvedSite] = field(default_factory=list)

    async def close(self) -> None:
        for site in self.sites:
            if site.technitium:
                await site.technitium.close()


def _resolve_site_ids(nb: NetBoxClient, sites: list[ResolvedSite]) -> None:
    for site in sites:
        cfg = site.config
        slug = cfg.netbox_site or slugify(cfg.netbox_site_name or cfg.name)
        name = cfg.netbox_site_name or cfg.name
        try:
            obj = nb.ensure(nb.api.dcim.sites, {"slug": slug}, {"name": name, "status": "active"})
            site.netbox_site_id = obj.id if obj else None
        except Exception as exc:
            log.warning("could not resolve NetBox site", site=cfg.id, error=str(exc))


async def build_context(
    config: AppConfig,
    state: StateDB,
    status: StatusRegistry,
    dry_run_override: bool | None = None,
) -> Context:
    if dry_run_override is not None:
        config = config.model_copy(deep=True)
        config.dry_run = dry_run_override

    netbox = NetBoxClient(config.netbox, dry_run=config.dry_run)
    oui = OuiDB(config.data_dir)
    sites = [ResolvedSite(config=s) for s in config.sites]
    for site in sites:
        if site.config.technitium and site.config.technitium.configured:
            site.technitium = TechnitiumClient(site.config.technitium)

    ctx = Context(config=config, netbox=netbox, state=state, oui=oui, status=status, sites=sites)
    if config.netbox.configured:
        await asyncio.to_thread(_resolve_site_ids, netbox, sites)
    return ctx
