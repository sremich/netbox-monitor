"""Sync module registry: builds the list of enabled scheduler modules."""

from __future__ import annotations

from netbox_monitor.context import Context
from netbox_monitor.scheduler import SyncModule


def build_modules(ctx: Context) -> list[SyncModule]:
    # imports here keep startup errors scoped to the module that caused them
    from netbox_monitor.sync.availability import AvailabilitySync
    from netbox_monitor.sync.certs import CertSync
    from netbox_monitor.sync.dhcp import DhcpSync
    from netbox_monitor.sync.discovery import DiscoverySync
    from netbox_monitor.sync.dns import DnsSync
    from netbox_monitor.sync.lldp import LldpSync
    from netbox_monitor.sync.proxmox import ProxmoxSync

    candidates = [
        (ctx.config.dhcp, DhcpSync(ctx), ctx.config.dhcp.interval),
        (ctx.config.dns, DnsSync(ctx), ctx.config.dns.interval),
        (ctx.config.discovery, DiscoverySync(ctx), ctx.config.discovery.interval),
        (ctx.config.availability, AvailabilitySync(ctx), ctx.config.availability.interval),
        (ctx.config.proxmox_sync, ProxmoxSync(ctx), ctx.config.proxmox_sync.interval),
        (ctx.config.lldp, LldpSync(ctx), ctx.config.lldp.interval),
        (ctx.config.certs, CertSync(ctx), ctx.config.certs.interval),
    ]
    modules = []
    for cfg, instance, interval in candidates:
        enabled = cfg.enabled
        if instance.name == "lldp":
            # lldp runs when enabled globally OR on any site
            enabled = enabled or any(s.config.lldp.enabled for s in ctx.sites)
        if enabled:
            modules.append(SyncModule(name=instance.name, interval=interval, run=instance.run))
    return modules
