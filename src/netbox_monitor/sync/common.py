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


def find_interface_by_mac(nb: NetBoxClient, mac: str) -> tuple[str, Any, Any] | None:
    """Find the interface carrying ``mac``: VM interfaces preferred over device ones.

    Returns (assigned_object_type, interface, parent_ref) or None.
    """
    try:
        if _netbox_version(nb) >= (4, 2):
            with nb.lock:
                mac_objs = list(nb.api.dcim.mac_addresses.filter(mac_address=mac))
            candidates: dict[str, Any] = {}
            for mac_obj in mac_objs:
                obj_type = str(getattr(mac_obj, "assigned_object_type", "") or "")
                obj_id = getattr(mac_obj, "assigned_object_id", None)
                if obj_id and obj_type not in candidates:
                    candidates[obj_type] = obj_id
            for obj_type, endpoint, parent_attr in (
                ("virtualization.vminterface", nb.api.virtualization.interfaces, "virtual_machine"),
                ("dcim.interface", nb.api.dcim.interfaces, "device"),
            ):
                if obj_type in candidates:
                    with nb.lock:
                        iface = endpoint.get(candidates[obj_type])
                    if iface is not None:
                        return (obj_type, iface, getattr(iface, parent_attr, None))
        else:
            with nb.lock:
                vm_ifaces = list(nb.api.virtualization.interfaces.filter(mac_address=mac))
            if vm_ifaces:
                iface = vm_ifaces[0]
                return (
                    "virtualization.vminterface",
                    iface,
                    getattr(iface, "virtual_machine", None),
                )
            with nb.lock:
                dev_ifaces = list(nb.api.dcim.interfaces.filter(mac_address=mac))
            if dev_ifaces:
                iface = dev_ifaces[0]
                return ("dcim.interface", iface, getattr(iface, "device", None))
    except Exception as exc:
        log.debug("interface-by-MAC lookup failed", mac=mac, error=str(exc))
    return None


def link_primary_ip(
    nb: NetBoxClient, object_type: str, parent_ref: Any, ip_obj: Any, iface: Any
) -> None:
    """Set ``ip_obj`` as the parent's primary IPv4 if it doesn't have one yet.

    Only touches parents managed by this service, and only when the IP is actually
    assigned to ``iface`` (human-owned IP records are never reassigned, so their
    hosts can't be linked automatically).
    """
    if parent_ref is None or ip_obj is None or iface is None:
        return
    if getattr(ip_obj, "assigned_object_id", None) != iface.id:
        log.info(
            "IP not assigned to the matched interface (human-owned record?); primary IP not linked",
            ip=str(getattr(ip_obj, "address", ip_obj)),
        )
        return
    endpoint = (
        nb.api.virtualization.virtual_machines
        if object_type == "virtualization.vminterface"
        else nb.api.dcim.devices
    )
    with nb.lock:
        parent = endpoint.get(parent_ref.id)
    if parent is None or not nb.is_managed(parent):
        return
    if getattr(parent, "primary_ip4", None) is None:
        nb.update(parent, {"primary_ip4": ip_obj.id}, reason="link DHCP lease as primary IP")


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


def _netbox_version(nb: NetBoxClient) -> tuple[int, int]:
    try:
        major, minor = (int(x) for x in str(nb.api.version).split(".")[:2])
        return (major, minor)
    except Exception:
        return (4, 2)


def set_interface_mac(
    nb: NetBoxClient, interface: Any, mac: str, object_type: str = "dcim.interface"
) -> None:
    """Assign a MAC to a device or VM interface.

    NetBox >= 4.2 stores MACs as standalone ``dcim.mac_addresses`` objects
    (writing ``mac_address`` on the interface is silently ignored there);
    older versions take the field directly.
    """
    try:
        if _netbox_version(nb) >= (4, 2):
            # NetBox's MAC filter doesn't accept assigned_object_type; match client-side
            with nb.lock:
                candidates = list(nb.api.dcim.mac_addresses.filter(mac_address=mac))
            mac_obj = next(
                (
                    m
                    for m in candidates
                    if str(getattr(m, "assigned_object_type", "")) == object_type
                    and getattr(m, "assigned_object_id", None) == interface.id
                ),
                None,
            )
            if mac_obj is None:
                mac_obj = nb.create(
                    nb.api.dcim.mac_addresses,
                    mac_address=mac,
                    assigned_object_type=object_type,
                    assigned_object_id=interface.id,
                )
            if mac_obj is not None and getattr(interface, "primary_mac_address", None) is None:
                nb.update(interface, {"primary_mac_address": mac_obj.id}, reason="set primary MAC")
        else:
            if getattr(interface, "mac_address", None) != mac:
                nb.update(interface, {"mac_address": mac}, reason="set MAC")
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
        match = find_interface_by_mac(nb, mac)
        if match and match[0] == "dcim.interface" and match[2] is not None:
            with nb.lock:
                device = nb.api.dcim.devices.get(match[2].id)
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
