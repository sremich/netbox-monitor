"""Managed-object cleanup: inventory grouping and safe bulk delete."""

from types import SimpleNamespace

from netbox_monitor.clients.netbox import MANAGED_TAG_SLUG
from netbox_monitor.sync.cleanup import delete_managed, inventory


def site(nb, slug):
    existing = nb.api.dcim.sites.get(slug=slug)
    if existing:
        return SimpleNamespace(id=existing.id, slug=slug)
    s = nb.api.dcim.sites.create(name=slug.title(), slug=slug)
    return SimpleNamespace(id=s.id, slug=slug)


def managed_device(nb, name, site_slug, source, managed=True, stale=False, last_seen=None):
    tags = []
    if managed:
        tags += nb.tag_ids(MANAGED_TAG_SLUG, source)
    if stale:
        tags += nb.tag_ids("stale")
    return nb.api.dcim.devices.create(
        name=name,
        site=site(nb, site_slug),
        tags=tags,
        custom_fields={"last_seen": last_seen} if last_seen else {},
    )


def managed_ip(nb, address, device, source):
    return nb.api.ipam.ip_addresses.create(
        address=address,
        tags=nb.tag_ids(MANAGED_TAG_SLUG, source),
        assigned_object=SimpleNamespace(device=SimpleNamespace(id=device.id)),
    )


def test_inventory_groups_by_site_source(nb):
    managed_device(nb, "a", "home", "src-scan")
    managed_device(nb, "b", "home", "src-scan")
    managed_device(nb, "c", "home", "src-dhcp")
    managed_device(nb, "d", "beach", "src-scan")
    managed_device(nb, "human", "home", "src-scan", managed=False)  # not ours

    rows = inventory(nb)
    got = {(r.object_type, r.site, r.source): r.count for r in rows}
    assert got[("devices", "home", "src-scan")] == 2
    assert got[("devices", "home", "src-dhcp")] == 1
    assert got[("devices", "beach", "src-scan")] == 1
    # the human device is untagged -> not in inventory
    assert sum(r.count for r in rows if r.object_type == "devices") == 4


def test_inventory_counts_stale(nb):
    managed_device(nb, "up", "home", "src-scan")
    managed_device(nb, "gone", "home", "src-scan", stale=True)
    row = next(r for r in inventory(nb) if r.source == "src-scan")
    assert row.count == 2 and row.stale == 1


def test_delete_by_site_removes_only_that_site(nb):
    d_home = managed_device(nb, "home-dev", "home", "src-scan")
    managed_ip(nb, "10.0.0.5/24", d_home, "src-scan")
    managed_device(nb, "beach-dev", "beach", "src-scan")
    managed_device(nb, "human-home", "home", "src-scan", managed=False)

    result = delete_managed(nb, site_slug="home")
    assert result.dry_run is False
    names = {d.name for d in nb.api.dcim.devices.items}
    assert "home-dev" not in names  # deleted
    assert "beach-dev" in names  # other site untouched
    assert "human-home" in names  # unmanaged untouched
    # the home device's managed IP was cascaded away
    assert nb.api.ipam.ip_addresses.items == []


def test_dry_run_counts_without_deleting(nb):
    managed_device(nb, "a", "home", "src-scan")
    managed_device(nb, "b", "home", "src-dhcp")
    result = delete_managed(nb, site_slug="home", dry_run=True)
    assert result.dry_run is True
    assert result.counts.get("devices") == 2
    assert len(nb.api.dcim.devices.items) == 2  # nothing actually deleted


def test_delete_by_source_filter(nb):
    managed_device(nb, "scan1", "home", "src-scan")
    managed_device(nb, "dhcp1", "home", "src-dhcp")
    delete_managed(nb, source="src-dhcp")
    names = {d.name for d in nb.api.dcim.devices.items}
    assert names == {"scan1"}  # only src-dhcp removed


def test_delete_if_managed_refuses_untagged(nb):
    human = nb.api.dcim.devices.create(name="human", site=site(nb, "home"), tags=[])
    assert nb.delete_if_managed(human) is False
    assert human in nb.api.dcim.devices.items
