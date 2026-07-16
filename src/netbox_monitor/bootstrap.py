"""Idempotent NetBox bootstrap: tags, custom fields, device roles, default site.

Runs at every startup; only creates what's missing. In dry-run mode missing
objects get placeholder ids so the sync loops can still log their intents.
"""

from __future__ import annotations

import structlog

from netbox_monitor.clients.netbox import ALL_TAGS, NetBoxClient, slugify
from netbox_monitor.config import AppConfig

log = structlog.get_logger(__name__)

# name, type, object_types, label
CUSTOM_FIELDS = [
    (
        "last_seen",
        "datetime",
        ["ipam.ipaddress", "dcim.device", "virtualization.virtualmachine"],
        "Last seen",
    ),
    ("discovered_mac", "text", ["ipam.ipaddress"], "Discovered MAC"),
    ("oui_vendor", "text", ["ipam.ipaddress", "dcim.device"], "OUI vendor"),
    ("dhcp_scope", "text", ["ipam.prefix"], "DHCP scope"),
    (
        "cert_expiry",
        "datetime",
        ["dcim.device", "virtualization.virtualmachine"],
        "TLS cert expiry",
    ),
    ("cert_issuer", "text", ["dcim.device", "virtualization.virtualmachine"], "TLS cert issuer"),
    ("cert_cn", "text", ["dcim.device", "virtualization.virtualmachine"], "TLS cert CN"),
]

DEVICE_ROLES = [
    ("Discovered", "discovered", "9e9e9e", "Auto-discovered by netbox-monitor"),
    ("Hypervisor", "hypervisor", "673ab7", "Proxmox VE node"),
]


def _ensure_tag(nb: NetBoxClient, name: str, slug: str, color: str, description: str) -> None:
    obj = nb.ensure(
        nb.api.extras.tags,
        {"slug": slug},
        {"name": name, "color": color, "description": description},
    )
    nb.register_tag(slug, obj.id if obj else 0)


def _ensure_custom_field(
    nb: NetBoxClient, name: str, cf_type: str, object_types: list[str], label: str
) -> None:
    with nb.lock:
        existing = nb.api.extras.custom_fields.get(name=name)
    if existing:
        return
    payload = {
        "name": name,
        "type": cf_type,
        "label": label,
        "object_types": object_types,
        "description": "Managed by netbox-monitor",
    }
    try:
        nb.create(nb.api.extras.custom_fields, **payload)
    except Exception:
        # NetBox < 4.0 uses content_types instead of object_types
        payload["content_types"] = payload.pop("object_types")
        nb.create(nb.api.extras.custom_fields, **payload)


def bootstrap(nb: NetBoxClient, config: AppConfig) -> None:
    log.info("bootstrapping NetBox objects")

    for slug, (name, color, description) in ALL_TAGS.items():
        _ensure_tag(nb, name, slug, color, description)
    # user-applied tag marking switches for LLDP collection
    _ensure_tag(
        nb,
        config.lldp.source_tag,
        slugify(config.lldp.source_tag),
        "3f51b5",
        "Apply to switches netbox-monitor should poll for LLDP neighbors",
    )

    for name, cf_type, object_types, label in CUSTOM_FIELDS:
        _ensure_custom_field(nb, name, cf_type, object_types, label)

    for name, slug, color, description in DEVICE_ROLES:
        role = nb.ensure(
            nb.api.dcim.device_roles,
            {"slug": slug},
            {"name": name, "color": color, "description": description, "vm_role": False},
        )
        nb.refs[f"role_{slug}"] = role.id if role else None

    site = nb.ensure(
        nb.api.dcim.sites,
        {"slug": slugify(config.netbox.default_site)},
        {"name": config.netbox.default_site, "status": "active"},
    )
    nb.refs["site"] = site.id if site else None

    log.info("bootstrap complete", refs=nb.refs)
