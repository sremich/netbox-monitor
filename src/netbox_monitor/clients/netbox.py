"""NetBox API client wrapper.

Central rules enforced here:
- ``dry_run``: every write logs what it *would* do and returns without touching NetBox.
- Ownership guard: objects are only deleted / lifecycle-modified when they carry our
  ``managed:netbox-monitor`` tag (plus the expected source tag). Human-created records
  are never deleted by this service.
"""

from __future__ import annotations

import re
import threading
from typing import Any

import pynetbox
import structlog
from pynetbox.core.query import RequestError

from netbox_monitor.config import NetBoxConfig

log = structlog.get_logger(__name__)

MANAGED_TAG_SLUG = "managed-netbox-monitor"
STALE_TAG_SLUG = "stale"
CERT_EXPIRING_TAG_SLUG = "cert-expiring"
CERT_EXPIRED_TAG_SLUG = "cert-expired"

# slug -> (name, color, description)
ALL_TAGS: dict[str, tuple[str, str, str]] = {
    MANAGED_TAG_SLUG: (
        "managed:netbox-monitor",
        "2196f3",
        "Created and managed by the netbox-monitor service",
    ),
    "src-dhcp": ("src:dhcp", "00bcd4", "Sourced from a Technitium DHCP lease"),
    "src-scan": ("src:scan", "009688", "Discovered by netbox-monitor ping scanning"),
    "src-proxmox": ("src:proxmox", "ff9800", "Synced from Proxmox VE"),
    "src-lldp": ("src:lldp", "9c27b0", "Topology learned via LLDP"),
    STALE_TAG_SLUG: ("stale", "f44336", "Host has been unreachable beyond the stale threshold"),
    CERT_EXPIRING_TAG_SLUG: ("cert-expiring", "ffc107", "TLS certificate expires soon"),
    CERT_EXPIRED_TAG_SLUG: ("cert-expired", "d32f2f", "TLS certificate has expired"),
}


def slugify(value: str) -> str:
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9_-]+", "-", value)
    return re.sub(r"-{2,}", "-", value).strip("-") or "unknown"


class NetBoxClient:
    def __init__(self, config: NetBoxConfig, dry_run: bool = False):
        self.config = config
        self.dry_run = dry_run
        self.api = pynetbox.api(config.url, token=config.token)
        self.api.http_session.verify = config.verify_ssl
        if not config.verify_ssl:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        # pynetbox shares one requests.Session; serialize access across sync loops.
        self.lock = threading.RLock()
        self._tag_ids: dict[str, int] = {}  # slug -> id
        self.refs: dict[str, Any] = {}  # populated by bootstrap (site/role ids, cf names)

    # ------------------------------------------------------------------ tags

    def register_tag(self, slug: str, tag_id: int) -> None:
        self._tag_ids[slug] = tag_id

    def tag_ids(self, *slugs: str) -> list[int]:
        return [self._tag_ids[s] for s in slugs]

    @staticmethod
    def obj_tag_slugs(obj: Any) -> set[str]:
        return {t.slug for t in (getattr(obj, "tags", None) or [])}

    def is_managed(self, obj: Any, source_slug: str | None = None) -> bool:
        slugs = self.obj_tag_slugs(obj)
        if MANAGED_TAG_SLUG not in slugs:
            return False
        return source_slug is None or source_slug in slugs

    # ---------------------------------------------------------------- writes

    def create(self, endpoint: Any, **data: Any) -> Any | None:
        """Create an object; returns None in dry-run mode."""
        if self.dry_run:
            log.info("dry-run: would create", endpoint=str(endpoint.url), data=data)
            return None
        with self.lock:
            obj = endpoint.create(**data)
        log.info("created", endpoint=str(endpoint.url), id=obj.id, data=data)
        return obj

    def update(self, obj: Any, data: dict[str, Any], reason: str = "") -> bool:
        """Update fields on an object. Callers must only pass fields this service owns
        (dns_name, custom fields, our tags, status of managed objects, ...)."""
        if self.dry_run:
            log.info("dry-run: would update", obj=str(obj), data=data, reason=reason)
            return False
        with self.lock:
            ok = obj.update(data)
        log.info("updated", obj=str(obj), data=data, reason=reason)
        return ok

    def delete(self, obj: Any, source_slug: str) -> bool:
        """Delete an object — refused unless it carries our managed tag + source tag."""
        if not self.is_managed(obj, source_slug):
            log.warning(
                "refusing to delete object not managed by us",
                obj=str(obj),
                required_source=source_slug,
                tags=sorted(self.obj_tag_slugs(obj)),
            )
            return False
        if self.dry_run:
            log.info("dry-run: would delete", obj=str(obj), source=source_slug)
            return False
        with self.lock:
            ok = obj.delete()
        log.info("deleted", obj=str(obj), source=source_slug)
        return ok

    def delete_if_managed(self, obj: Any) -> bool:
        """Cleanup-safe delete: removes the object only if it carries our managed
        tag (any source). Never touches human-created objects. Honors dry_run."""
        if MANAGED_TAG_SLUG not in self.obj_tag_slugs(obj):
            log.warning("refusing to delete object not managed by us", obj=str(obj))
            return False
        if self.dry_run:
            log.info("dry-run: would delete (cleanup)", obj=str(obj))
            return False
        with self.lock:
            ok = obj.delete()
        log.info("deleted (cleanup)", obj=str(obj))
        return ok

    def add_tags(self, obj: Any, *slugs: str) -> bool:
        current = self.obj_tag_slugs(obj)
        missing = [s for s in slugs if s not in current]
        if not missing:
            return False
        new_ids = [t.id for t in obj.tags] + self.tag_ids(*missing)
        return self.update(obj, {"tags": new_ids}, reason=f"add tags {missing}")

    def remove_tags(self, obj: Any, *slugs: str) -> bool:
        current = self.obj_tag_slugs(obj)
        present = [s for s in slugs if s in current]
        if not present:
            return False
        keep = [t.id for t in obj.tags if t.slug not in present]
        return self.update(obj, {"tags": keep}, reason=f"remove tags {present}")

    def set_custom_fields(self, obj: Any, **fields: Any) -> bool:
        current = dict(getattr(obj, "custom_fields", None) or {})
        changed = {k: v for k, v in fields.items() if current.get(k) != v}
        if not changed:
            return False
        return self.update(obj, {"custom_fields": {**current, **changed}}, reason="custom fields")

    # --------------------------------------------------------------- helpers

    def filter_tagged(self, endpoint: Any, tag_slug: str, **extra: Any) -> list[Any]:
        """Filter an endpoint by tag slug; empty when the tag doesn't exist yet
        (fresh NetBox in dry-run mode, where bootstrap didn't really create tags)."""
        try:
            with self.lock:
                return list(endpoint.filter(tag=[tag_slug], **extra))
        except RequestError as exc:
            if "not one of the available choices" in str(exc):
                log.info("tag not present in NetBox yet", tag=tag_slug)
                return []
            raise

    def ensure(self, endpoint: Any, lookup: dict[str, Any], defaults: dict[str, Any]) -> Any | None:
        """Get an object matching ``lookup``; create it (lookup+defaults) if absent."""
        with self.lock:
            obj = endpoint.get(**lookup)
        if obj:
            return obj
        return self.create(endpoint, **lookup, **defaults)

    _JOURNAL_TYPES = {
        "ip-addresses": "ipam.ipaddress",
        "prefixes": "ipam.prefix",
        "devices": "dcim.device",
        "interfaces": "dcim.interface",
        "cables": "dcim.cable",
        "virtual-machines": "virtualization.virtualmachine",
        "services": "ipam.service",
    }

    def journal(self, obj: Any, comments: str, kind: str = "info") -> None:
        """Attach a journal entry to any NetBox object (best-effort)."""
        if self.dry_run:
            log.info("dry-run: would journal", obj=str(obj), comments=comments)
            return
        endpoint_name = getattr(getattr(obj, "endpoint", None), "name", "")
        object_type = self._JOURNAL_TYPES.get(endpoint_name)
        if not object_type:
            log.debug("no journal object type mapping", endpoint=endpoint_name)
            return
        try:
            with self.lock:
                self.api.extras.journal_entries.create(
                    assigned_object_type=object_type,
                    assigned_object_id=obj.id,
                    kind=kind,
                    comments=comments,
                )
        except Exception as exc:
            log.debug("journal entry failed", obj=str(obj), error=str(exc))
