"""Cross-site auto-migration: a managed device re-discovered at a different site
(matched by MAC) is moved to the current site; a name-only match is not."""

from types import SimpleNamespace

from netbox_monitor.clients.netbox import MANAGED_TAG_SLUG
from netbox_monitor.sync.common import ensure_host_device


def _site(nb, slug):
    existing = nb.api.dcim.sites.get(slug=slug)
    obj = existing or nb.api.dcim.sites.create(name=slug.title(), slug=slug)
    return obj


def test_mac_match_migrates_device_to_current_site(nb):
    home = _site(nb, "home")
    uk = _site(nb, "uk")
    nb.refs["role_discovered"] = nb.api.dcim.device_roles.get(slug="discovered").id

    # a device created earlier on the Home site, with a MAC on its interface
    dev = nb.api.dcim.devices.create(
        name="host-1",
        site=SimpleNamespace(id=home.id, slug="home"),
        tags=nb.tag_ids(MANAGED_TAG_SLUG, "src-scan"),
        primary_ip4=None,
    )
    iface = nb.api.dcim.interfaces.create(device=dev, name="eth0")
    nb.api.dcim.mac_addresses.create(
        mac_address="24:A4:3C:11:22:33",
        assigned_object_type="dcim.interface",
        assigned_object_id=iface.id,
    )

    # re-discovered at the UK site with the same MAC
    ensure_host_device(
        nb,
        name="host-1-renamed",
        ip="10.9.9.9",
        source_slug="src-scan",
        site_id=uk.id,
        mac="24:A4:3C:11:22:33",
    )

    moved = nb.api.dcim.devices.get(dev.id)
    assert moved.site == uk.id  # migrated to the current site


def test_name_only_match_does_not_migrate(nb):
    home = _site(nb, "home")
    uk = _site(nb, "uk")
    nb.refs["role_discovered"] = nb.api.dcim.device_roles.get(slug="discovered").id

    dev = nb.api.dcim.devices.create(
        name="samename",
        site=SimpleNamespace(id=home.id, slug="home"),
        tags=nb.tag_ids(MANAGED_TAG_SLUG, "src-scan"),
        primary_ip4=None,
    )
    # re-discovered at UK by NAME only (no MAC) — must NOT move (could be coincidental)
    ensure_host_device(
        nb, name="samename", ip="10.9.9.9", source_slug="src-scan", site_id=uk.id, mac=None
    )
    assert nb.api.dcim.devices.get(dev.id).site.id == home.id  # unchanged
