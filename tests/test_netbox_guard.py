"""The ownership guard: netbox-monitor must never delete records it doesn't manage."""

from netbox_monitor.clients.netbox import MANAGED_TAG_SLUG


def test_delete_refuses_unmanaged(nb):
    ip = nb.api.ipam.ip_addresses.create(address="10.0.0.5/24", status="active", tags=[])
    assert nb.delete(ip, "src-dhcp") is False
    assert ip in nb.api.ipam.ip_addresses.items


def test_delete_refuses_wrong_source(nb):
    ip = nb.api.ipam.ip_addresses.create(
        address="10.0.0.5/24", tags=nb.tag_ids(MANAGED_TAG_SLUG, "src-scan")
    )
    assert nb.delete(ip, "src-dhcp") is False
    assert ip in nb.api.ipam.ip_addresses.items


def test_delete_allows_managed_with_source(nb):
    ip = nb.api.ipam.ip_addresses.create(
        address="10.0.0.5/24", tags=nb.tag_ids(MANAGED_TAG_SLUG, "src-dhcp")
    )
    assert nb.delete(ip, "src-dhcp") is True
    assert ip not in nb.api.ipam.ip_addresses.items


def test_dry_run_never_writes(nb):
    nb.dry_run = True
    result = nb.create(nb.api.ipam.ip_addresses, address="10.0.0.9/24")
    assert result is None
    assert nb.api.ipam.ip_addresses.items == []

    ip = nb.api.ipam.ip_addresses.create(
        address="10.0.0.5/24", tags=nb.tag_ids(MANAGED_TAG_SLUG, "src-dhcp")
    )
    assert nb.delete(ip, "src-dhcp") is False
    assert ip in nb.api.ipam.ip_addresses.items


def test_add_remove_tags(nb):
    device = nb.api.dcim.devices.create(name="host1", tags=nb.tag_ids(MANAGED_TAG_SLUG))
    nb.add_tags(device, "stale")
    assert "stale" in nb.obj_tag_slugs(device)
    nb.remove_tags(device, "stale")
    assert "stale" not in nb.obj_tag_slugs(device)
