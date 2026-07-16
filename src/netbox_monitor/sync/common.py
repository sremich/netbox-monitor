"""Shared reconciliation helpers used by multiple sync modules.

All functions here are synchronous (pynetbox) — call them via ``asyncio.to_thread``.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

import structlog
from pynetbox.core.query import RequestError

from netbox_monitor.clients.netbox import MANAGED_TAG_SLUG, NetBoxClient, slugify

log = structlog.get_logger(__name__)

UNKNOWN_VENDOR = "Unknown"


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def prefix_len_for_ip(nb: NetBoxClient, ip: str, default: int = 32) -> int:
    """Prefix length of the longest NetBox prefix containing ``ip``."""
    try:
        with nb.lock:
            prefixes = list(nb.api.ipam.prefixes.filter(contains=ip))
        if prefixes:
            return max(ipaddress.ip_network(p.prefix).prefixlen for p in prefixes)
    except Exception as exc:
        log.debug("prefix lookup failed", ip=ip, error=str(exc))
    return default


def find_ip(nb: NetBoxClient, ip: str) -> Any | None:
    """Find an IPAddress object by host address regardless of mask."""
    with nb.lock:
        matches = list(nb.api.ipam.ip_addresses.filter(address=ip))
    return matches[0] if matches else None


def upsert_ip(
    nb: NetBoxClient,
    ip: str,
    *,
    source_slug: str,
    status: str = "active",
    dns_name: str = "",
    description: str = "",
    mac: str | None = None,
    vendor: str | None = None,
    assigned_object_type: str | None = None,
    assigned_object_id: int | None = None,
) -> Any | None:
    """Create or update an IPAddress with our tags + custom fields."""
    custom_fields = {"last_seen": now_iso()}
    if mac:
        custom_fields["discovered_mac"] = mac
    if vendor:
        custom_fields["oui_vendor"] = vendor

    obj = find_ip(nb, ip)
    if obj is None:
        data: dict[str, Any] = {
            "address": f"{ip}/{prefix_len_for_ip(nb, ip)}",
            "status": status,
            "dns_name": dns_name,
            "description": description,
            "tags": nb.tag_ids(MANAGED_TAG_SLUG, source_slug),
            "custom_fields": custom_fields,
        }
        if assigned_object_type and assigned_object_id:
            data["assigned_object_type"] = assigned_object_type
            data["assigned_object_id"] = assigned_object_id
        try:
            return nb.create(nb.api.ipam.ip_addresses, **data)
        except RequestError as exc:
            # e.g. NetBox refuses IPs inside an IP range marked as populated
            log.info("NetBox rejected IP creation; skipping", ip=ip, error=str(exc))
            return None

    updates: dict[str, Any] = {}
    if nb.is_managed(obj, source_slug):
        # fully ours: keep status/description/dns_name in sync
        if str(obj.status) != status and getattr(obj.status, "value", None) != status:
            updates["status"] = status
        if dns_name and obj.dns_name != dns_name:
            updates["dns_name"] = dns_name
        if description and obj.description != description:
            updates["description"] = description
        if assigned_object_id and getattr(obj, "assigned_object_id", None) is None:
            updates["assigned_object_type"] = assigned_object_type
            updates["assigned_object_id"] = assigned_object_id
    if updates:
        nb.update(obj, updates, reason=f"upsert via {source_slug}")
    nb.set_custom_fields(obj, **custom_fields)
    return obj


def ensure_discovered_device_type(nb: NetBoxClient, vendor: str | None) -> tuple[Any, Any]:
    """Manufacturer + a generic '<Vendor> discovered device' type."""
    vendor = (vendor or UNKNOWN_VENDOR)[:100]
    manufacturer = nb.ensure(nb.api.dcim.manufacturers, {"slug": slugify(vendor)}, {"name": vendor})
    device_type = nb.ensure(
        nb.api.dcim.device_types,
        {"slug": slugify(f"{vendor}-discovered")},
        {
            "manufacturer": manufacturer.id if manufacturer else None,
            "model": f"{vendor} discovered device",
            "u_height": 0,
        },
    )
    return manufacturer, device_type


def set_interface_mac(nb: NetBoxClient, interface: Any, mac: str) -> None:
    """Assign a MAC to an interface, tolerating both pre- and post-4.2 NetBox models."""
    try:
        if getattr(interface, "mac_address", None) == mac:
            return
        nb.update(interface, {"mac_address": mac}, reason="set MAC")
    except Exception:
        # NetBox >= 4.2: MACs are standalone objects
        try:
            with nb.lock:
                existing = list(nb.api.dcim.mac_addresses.filter(mac_address=mac))
            if not existing:
                nb.create(
                    nb.api.dcim.mac_addresses,
                    mac_address=mac,
                    assigned_object_type="dcim.interface",
                    assigned_object_id=interface.id,
                )
        except Exception as exc:
            log.debug("could not set interface MAC", mac=mac, error=str(exc))


def ensure_host_device(
    nb: NetBoxClient,
    *,
    name: str,
    ip: str,
    source_slug: str,
    mac: str | None = None,
    vendor: str | None = None,
    dns_name: str = "",
    description: str = "",
) -> Any | None:
    """Create/update a discovered host: Device + interface (MAC) + primary IP."""
    device = None
    # prefer identifying an existing device by its interface MAC (survives renames)
    if mac:
        try:
            with nb.lock:
                ifaces = list(nb.api.dcim.interfaces.filter(mac_address=mac))
            for iface in ifaces:
                if iface.device:
                    device = nb.api.dcim.devices.get(iface.device.id)
                    break
        except Exception as exc:
            log.debug("MAC-based device lookup failed", mac=mac, error=str(exc))
    if device is None:
        with nb.lock:
            device = nb.api.dcim.devices.get(name=name)

    if device is None:
        _, device_type = ensure_discovered_device_type(nb, vendor)
        device = nb.create(
            nb.api.dcim.devices,
            name=name,
            role=nb.refs.get("role_discovered"),
            device_type=device_type.id if device_type else None,
            site=nb.refs.get("site"),
            status="active",
            description=description,
            tags=nb.tag_ids(MANAGED_TAG_SLUG, source_slug),
            custom_fields={"last_seen": now_iso(), "oui_vendor": vendor or ""},
        )
        if device is None:  # dry-run
            return None
    elif not nb.is_managed(device):
        # a human documented this device; enrich last_seen but leave its
        # interfaces/IPs/primary IP entirely alone
        log.info("device exists unmanaged; only updating last_seen", device=str(device))
        nb.set_custom_fields(device, last_seen=now_iso())
        return device
    else:
        nb.set_custom_fields(device, last_seen=now_iso(), oui_vendor=vendor or "")

    with nb.lock:
        iface = nb.api.dcim.interfaces.get(device_id=device.id, name="eth0")
    if iface is None:
        iface = nb.create(
            nb.api.dcim.interfaces,
            device=device.id,
            name="eth0",
            type="other",
            tags=nb.tag_ids(MANAGED_TAG_SLUG, source_slug),
        )
    if iface and mac:
        set_interface_mac(nb, iface, mac)

    ip_obj = upsert_ip(
        nb,
        ip,
        source_slug=source_slug,
        dns_name=dns_name,
        description=description,
        mac=mac,
        vendor=vendor,
        assigned_object_type="dcim.interface" if iface else None,
        assigned_object_id=iface.id if iface else None,
    )
    if ip_obj is not None and iface is not None and getattr(device, "primary_ip4", None) is None:
        if getattr(ip_obj, "assigned_object_id", None) == iface.id:
            nb.update(device, {"primary_ip4": ip_obj.id}, reason="set primary IP")
        else:
            # pre-existing IP owned by someone else; don't hijack it
            log.info(
                "IP exists but is not assigned to our interface; primary IP not set",
                device=str(device),
                ip=ip,
            )
    return device
