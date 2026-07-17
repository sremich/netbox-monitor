"""Managed-object cleanup: inventory and bulk-delete everything a (current or
previous) instance of this service created — devices, VMs, IPs, cables — all
tagged ``managed-netbox-monitor``. Used by the web UI's Cleanup page.

Never touches human-created objects: every delete goes through
``NetBoxClient.delete_if_managed`` which requires the managed tag.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from netbox_monitor.clients.netbox import MANAGED_TAG_SLUG, STALE_TAG_SLUG, NetBoxClient

log = structlog.get_logger(__name__)

OBJECT_TYPES = ("devices", "virtual_machines", "ip_addresses", "cables")


@dataclass
class GroupRow:
    object_type: str
    site: str  # NetBox site slug, or "—" / "unassigned"
    source: str  # src-* tag, or "?"
    count: int = 0
    stale: int = 0
    not_seen_30d: int = 0


@dataclass
class CleanupResult:
    dry_run: bool
    counts: dict[str, int] = field(default_factory=dict)  # object_type -> deleted/would-delete

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _source_of(nb: NetBoxClient, obj: Any) -> str:
    for slug in nb.obj_tag_slugs(obj):
        if slug.startswith("src-"):
            return slug
    return "?"


def _device_site_slug(obj: Any) -> str:
    site = getattr(obj, "site", None)
    return getattr(site, "slug", None) or "—"


def _cluster_site_slug(obj: Any) -> str:
    # VMs: site via cluster scope isn't always populated; fall back to the device
    dev = getattr(obj, "device", None)
    if dev is not None:
        return _device_site_slug(dev)
    return "—"


def _ip_site_slug(nb: NetBoxClient, obj: Any) -> str:
    assigned = getattr(obj, "assigned_object", None)
    parent = getattr(assigned, "device", None) or getattr(assigned, "virtual_machine", None)
    if parent is not None:
        with nb.lock:
            full = nb.api.dcim.devices.get(parent.id) if hasattr(parent, "id") else None
        if full is not None:
            return _device_site_slug(full)
    return "unassigned"


def _last_seen_age_days(obj: Any, now: float) -> float | None:
    cf = getattr(obj, "custom_fields", None) or {}
    raw = cf.get("last_seen")
    if not raw:
        return None
    try:
        from datetime import datetime

        ts = datetime.strptime(str(raw)[:19], "%Y-%m-%dT%H:%M:%S").timestamp()
        return (now - ts) / 86400
    except Exception:
        return None


def inventory(nb: NetBoxClient) -> list[GroupRow]:
    """Group every managed object by (type, site, source) with stale/orphan counts."""
    now = time.time()
    groups: dict[tuple[str, str, str], GroupRow] = {}

    def bump(object_type: str, site: str, source: str, obj: Any) -> None:
        key = (object_type, site, source)
        row = groups.get(key)
        if row is None:
            row = groups[key] = GroupRow(object_type, site, source)
        row.count += 1
        if STALE_TAG_SLUG in nb.obj_tag_slugs(obj):
            row.stale += 1
        age = _last_seen_age_days(obj, now)
        if age is not None and age >= 30:
            row.not_seen_30d += 1

    for obj in nb.filter_tagged(nb.api.dcim.devices, MANAGED_TAG_SLUG):
        bump("devices", _device_site_slug(obj), _source_of(nb, obj), obj)
    for obj in nb.filter_tagged(nb.api.virtualization.virtual_machines, MANAGED_TAG_SLUG):
        bump("virtual_machines", _cluster_site_slug(obj), _source_of(nb, obj), obj)
    for obj in nb.filter_tagged(nb.api.ipam.ip_addresses, MANAGED_TAG_SLUG):
        bump("ip_addresses", _ip_site_slug(nb, obj), _source_of(nb, obj), obj)
    for obj in nb.filter_tagged(nb.api.dcim.cables, MANAGED_TAG_SLUG):
        bump("cables", "—", _source_of(nb, obj), obj)

    return sorted(groups.values(), key=lambda r: (r.site, r.object_type, r.source))


def _matches(
    nb: NetBoxClient,
    obj: Any,
    site_slug: str | None,
    source: str | None,
    only_stale: bool,
    not_seen_days: int | None,
    obj_site: str,
    now: float,
) -> bool:
    if site_slug and obj_site != site_slug:
        return False
    if source and source not in nb.obj_tag_slugs(obj):
        return False
    if only_stale and STALE_TAG_SLUG not in nb.obj_tag_slugs(obj):
        return False
    if not_seen_days is not None:
        age = _last_seen_age_days(obj, now)
        if age is None or age < not_seen_days:
            return False
    return True


def delete_managed(
    nb: NetBoxClient,
    *,
    object_types: tuple[str, ...] = OBJECT_TYPES,
    site_slug: str | None = None,
    source: str | None = None,
    only_stale: bool = False,
    not_seen_days: int | None = None,
    dry_run: bool = False,
) -> CleanupResult:
    """Delete managed objects matching the filters. When ``dry_run`` (or the client
    is in dry-run) nothing is deleted and the counts are what *would* be removed.

    Deleting a device/VM first removes its managed IP addresses so no orphan IPs
    are left behind."""
    effective_dry = dry_run or nb.dry_run
    now = time.time()
    result = CleanupResult(dry_run=effective_dry)
    # dedupe IPs across the cascade and the standalone pass so the (dry-run) count
    # is accurate — an IP can be reached both by its device and by site match
    deleted_ip_ids: set[int] = set()

    def do_delete(obj: Any) -> bool:
        if effective_dry:
            return True  # count only
        return nb.delete_if_managed(obj)

    def delete_ip(ip: Any) -> None:
        if ip.id in deleted_ip_ids or MANAGED_TAG_SLUG not in nb.obj_tag_slugs(ip):
            return
        if do_delete(ip):
            deleted_ip_ids.add(ip.id)
            result.counts["ip_addresses"] = result.counts.get("ip_addresses", 0) + 1

    def delete_parent_ips(parent_id: int, endpoint) -> None:
        # remove managed IPs assigned to this device/VM before deleting it
        with nb.lock:
            ips = list(nb.api.ipam.ip_addresses.filter(**{endpoint: parent_id}))
        for ip in ips:
            delete_ip(ip)

    if "devices" in object_types:
        for obj in nb.filter_tagged(nb.api.dcim.devices, MANAGED_TAG_SLUG):
            if _matches(
                nb, obj, site_slug, source, only_stale, not_seen_days, _device_site_slug(obj), now
            ):
                delete_parent_ips(obj.id, "device_id")
                if do_delete(obj):
                    result.counts["devices"] = result.counts.get("devices", 0) + 1

    if "virtual_machines" in object_types:
        for obj in nb.filter_tagged(nb.api.virtualization.virtual_machines, MANAGED_TAG_SLUG):
            if _matches(
                nb, obj, site_slug, source, only_stale, not_seen_days, _cluster_site_slug(obj), now
            ):
                delete_parent_ips(obj.id, "virtual_machine_id")
                if do_delete(obj):
                    result.counts["virtual_machines"] = result.counts.get("virtual_machines", 0) + 1

    if "ip_addresses" in object_types:
        # any remaining managed IPs (e.g. dynamic DHCP IPs not tied to a deleted device)
        for obj in nb.filter_tagged(nb.api.ipam.ip_addresses, MANAGED_TAG_SLUG):
            if _matches(
                nb, obj, site_slug, source, only_stale, not_seen_days, _ip_site_slug(nb, obj), now
            ):
                delete_ip(obj)

    if "cables" in object_types and not site_slug:  # cables aren't site-scoped
        for obj in nb.filter_tagged(nb.api.dcim.cables, MANAGED_TAG_SLUG):
            if _matches(nb, obj, None, source, only_stale, not_seen_days, "—", now):
                if do_delete(obj):
                    result.counts["cables"] = result.counts.get("cables", 0) + 1

    log.info(
        "cleanup complete",
        dry_run=effective_dry,
        total=result.total,
        counts=result.counts,
        site=site_slug,
        source=source,
    )
    return result
