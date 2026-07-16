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
from netbox_monitor.sync.common import (
    ensure_host_device,
    find_interface_by_mac,
    find_ip,
    link_primary_ip,
    upsert_ip,
)

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
        reserved_addresses: set[str] = set()
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
                    reserved_addresses.add(address)
                    vm_match = find_interface_by_mac(nb, mac) if mac else None
                    if vm_match and vm_match[0] == "virtualization.vminterface":
                        # the reserved host is a Proxmox guest: document it on the VM,
                        # not as a standalone device
                        self._attach_reservation_to_vm(
                            vm_match, address, hostname, scope_name, mac, vendor
                        )
                    else:
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
                    # correlate the lease with the VM/device interface carrying its MAC
                    assigned_type = None
                    assigned_iface = None
                    parent_ref = None
                    if mac:
                        match = find_interface_by_mac(nb, mac)
                        if match:
                            assigned_type, assigned_iface, parent_ref = match
                    ip_obj = upsert_ip(
                        nb,
                        address,
                        source_slug=SRC,
                        status="dhcp",
                        dns_name=hostname,
                        description=f"DHCP lease in scope '{scope_name}'",
                        mac=mac,
                        vendor=vendor,
                        assigned_object_type=assigned_type,
                        assigned_object_id=assigned_iface.id if assigned_iface else None,
                    )
                    if assigned_type and ip_obj is not None:
                        link_primary_ip(nb, assigned_type, parent_ref, ip_obj, assigned_iface)
            except Exception:
                log.exception("failed to sync lease", address=address, type=lease_type)

        if self.ctx.config.lifecycle.delete_dhcp_on_expiry:
            self._delete_expired(active_dynamic, reserved_addresses)

    def _attach_reservation_to_vm(
        self,
        vm_match: tuple,
        address: str,
        hostname: str,
        scope_name: str,
        mac: str | None,
        vendor: str | None,
    ) -> None:
        """A reserved lease whose MAC belongs to a Proxmox VM interface: assign the
        IP to that VM interface, set it as the VM's primary, and remove any duplicate
        Device this sync created before the VM existed in NetBox."""
        nb = self.ctx.netbox
        object_type, iface, parent_ref = vm_match

        # drop the duplicate device (only ever touches our own src:dhcp devices)
        device_name = hostname.split(".")[0] if hostname else f"reserved-{address}"
        with nb.lock:
            duplicate = nb.api.dcim.devices.get(name=device_name)
        if duplicate is not None and nb.is_managed(duplicate, SRC):
            log.info(
                "reserved lease belongs to a Proxmox VM; removing duplicate device",
                device=device_name,
            )
            nb.delete(duplicate, SRC)

        # if the IP survived the device deletion still pointing at the old interface,
        # move it to the VM interface (it carries our src:dhcp tag, so it's ours)
        ip_obj = find_ip(nb, address)
        if (
            ip_obj is not None
            and nb.is_managed(ip_obj, SRC)
            and getattr(ip_obj, "assigned_object_id", None) != iface.id
        ):
            nb.update(
                ip_obj,
                {
                    "assigned_object_type": object_type,
                    "assigned_object_id": iface.id,
                },
                reason="reassign reservation IP to VM interface",
            )

        ip_obj = upsert_ip(
            nb,
            address,
            source_slug=SRC,
            dns_name=hostname,
            description=f"DHCP reservation in scope '{scope_name}'",
            mac=mac,
            vendor=vendor,
            assigned_object_type=object_type,
            assigned_object_id=iface.id,
        )
        if ip_obj is not None:
            link_primary_ip(nb, object_type, parent_ref, ip_obj, iface)

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

    def _delete_expired(self, active: set[str], reserved: set[str]) -> None:
        """Delete NetBox IPs tagged src:dhcp whose dynamic lease no longer exists.

        Reserved-lease IPs are never deleted (their Devices go stale instead), and
        neither are IPs assigned to physical (dcim) interfaces. Dynamic IPs linked
        to VM interfaces ARE deleted on expiry — NetBox clears the VM's primary IP
        pointer automatically, and the next lease re-links it.
        """
        nb = self.ctx.netbox
        managed = nb.filter_tagged(nb.api.ipam.ip_addresses, SRC)
        for obj in managed:
            host = str(obj.address).split("/")[0]
            if host in active or host in reserved:
                continue
            if getattr(obj, "assigned_object_type", None) == "dcim.interface":
                continue  # a device's address (reserved lease); availability handles it
            log.info("dhcp lease gone; deleting IP", address=str(obj.address))
            nb.delete(obj, SRC)
