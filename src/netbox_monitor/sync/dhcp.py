"""DHCP sync: mirror Technitium DHCP leases into NetBox.

- Dynamic leases  -> IPAddress objects (status ``dhcp``); deleted when the lease goes away.
- Reserved leases -> full Devices (static infrastructure), never deleted (stale-tagged
  by the availability monitor instead).
- DHCP scope definitions -> ``dhcp_scope`` custom field on matching NetBox prefixes.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

import structlog

from netbox_monitor.context import Context
from netbox_monitor.net_utils import sanitize_dns_name
from netbox_monitor.oui import normalize_mac
from netbox_monitor.sync.common import ensure_host_device, upsert_ip

log = structlog.get_logger(__name__)

SRC = "src-dhcp"


def scope_network(scope: dict[str, Any]) -> ipaddress.IPv4Network | None:
    try:
        return ipaddress.ip_network(
            f"{scope['startingAddress']}/{scope['subnetMask']}", strict=False
        )
    except (KeyError, ValueError):
        return None


class DhcpSync:
    name = "dhcp"

    def __init__(self, ctx: Context):
        self.ctx = ctx

    async def run(self) -> None:
        await self.ctx.oui.ensure_loaded()
        scopes = await self.ctx.technitium.list_dhcp_scopes()
        leases = await self.ctx.technitium.list_dhcp_leases()
        await asyncio.to_thread(self._reconcile, scopes, leases)

    # ------------------------------------------------------------------ sync

    def _reconcile(self, scopes: list[dict], leases: list[dict]) -> None:
        nb = self.ctx.netbox
        self._annotate_prefixes(scopes)

        active_dynamic: set[str] = set()
        for lease in leases:
            address = lease.get("address")
            if not address:
                continue
            lease_type = (lease.get("type") or "").lower()
            mac = normalize_mac(lease.get("hardwareAddress") or "")
            vendor = self.ctx.oui.lookup(mac) if mac else None
            hostname = sanitize_dns_name(lease.get("hostName"))
            scope_name = lease.get("scope", "")

            try:
                if lease_type == "reserved":
                    ensure_host_device(
                        nb,
                        name=hostname.split(".")[0] if hostname else f"reserved-{address}",
                        ip=address,
                        source_slug=SRC,
                        mac=mac,
                        vendor=vendor,
                        dns_name=hostname,
                        description=f"DHCP reservation in scope '{scope_name}'",
                    )
                else:
                    active_dynamic.add(address)
                    upsert_ip(
                        nb,
                        address,
                        source_slug=SRC,
                        status="dhcp",
                        dns_name=hostname,
                        description=f"DHCP lease in scope '{scope_name}'",
                        mac=mac,
                        vendor=vendor,
                    )
            except Exception:
                log.exception("failed to sync lease", address=address, type=lease_type)

        if self.ctx.config.lifecycle.delete_dhcp_on_expiry:
            self._delete_expired(active_dynamic)

    def _annotate_prefixes(self, scopes: list[dict]) -> None:
        nb = self.ctx.netbox
        for scope in scopes:
            network = scope_network(scope)
            if network is None:
                continue
            with nb.lock:
                prefix = nb.api.ipam.prefixes.get(prefix=str(network))
            if prefix is None:
                continue
            enabled = "enabled" if scope.get("enabled", True) else "disabled"
            label = (
                f"{scope.get('name', '?')} ({scope.get('startingAddress')}"
                f"-{scope.get('endingAddress')}, {enabled})"
            )
            nb.set_custom_fields(prefix, dhcp_scope=label)

    def _delete_expired(self, active: set[str]) -> None:
        """Delete NetBox IPs tagged src:dhcp whose lease no longer exists.

        Only touches dynamic-lease records: reserved leases become Devices whose IPs
        are assigned to an interface, and those are skipped here.
        """
        nb = self.ctx.netbox
        managed = nb.filter_tagged(nb.api.ipam.ip_addresses, SRC)
        for obj in managed:
            host = str(obj.address).split("/")[0]
            if host in active:
                continue
            if getattr(obj, "assigned_object_id", None):
                continue  # belongs to a reserved-lease device; availability handles it
            log.info("dhcp lease gone; deleting IP", address=str(obj.address))
            nb.delete(obj, SRC)
