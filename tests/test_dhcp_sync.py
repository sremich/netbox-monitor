"""DHCP lifecycle: dynamic leases create/delete IPs; reserved leases become devices;
records not managed by us are never touched."""

from netbox_monitor.clients.netbox import MANAGED_TAG_SLUG
from netbox_monitor.sync.dhcp import DhcpSync

SCOPES = [
    {
        "name": "lan",
        "enabled": True,
        "startingAddress": "10.200.10.100",
        "endingAddress": "10.200.10.200",
        "subnetMask": "255.255.255.0",
    }
]


def dynamic_lease(address="10.200.10.150", host="laptop.lan"):
    return {
        "scope": "lan",
        "type": "Dynamic",
        "hardwareAddress": "24-A4-3C-AA-BB-CC",
        "address": address,
        "hostName": host,
    }


def reserved_lease(address="10.200.10.20", host="nas.lan"):
    return {
        "scope": "lan",
        "type": "Reserved",
        "hardwareAddress": "24-A4-3C-11-22-33",
        "address": address,
        "hostName": host,
    }


def test_dynamic_lease_creates_ip(ctx):
    sync = DhcpSync(ctx)
    sync._reconcile(SCOPES, [dynamic_lease()])
    ips = ctx.netbox.api.ipam.ip_addresses.items
    assert len(ips) == 1
    ip = ips[0]
    assert ip.address.startswith("10.200.10.150/")
    assert ip.status == "dhcp"
    assert ip.dns_name == "laptop.lan"
    slugs = {t.slug for t in ip.tags}
    assert MANAGED_TAG_SLUG in slugs and "src-dhcp" in slugs
    assert ip.custom_fields["discovered_mac"] == "24:A4:3C:AA:BB:CC"
    assert ip.custom_fields["oui_vendor"] == "Ubiquiti Inc"


def test_expired_lease_deletes_ip(ctx):
    sync = DhcpSync(ctx)
    sync._reconcile(SCOPES, [dynamic_lease()])
    assert len(ctx.netbox.api.ipam.ip_addresses.items) == 1
    sync._reconcile(SCOPES, [])  # lease gone
    assert ctx.netbox.api.ipam.ip_addresses.items == []


def test_expired_lease_kept_when_delete_disabled(ctx):
    ctx.config.lifecycle.delete_dhcp_on_expiry = False
    sync = DhcpSync(ctx)
    sync._reconcile(SCOPES, [dynamic_lease()])
    sync._reconcile(SCOPES, [])
    assert len(ctx.netbox.api.ipam.ip_addresses.items) == 1


def test_unmanaged_ip_never_deleted(ctx):
    # a human documented this IP by hand — no managed tag
    ctx.netbox.api.ipam.ip_addresses.create(address="10.200.10.150/24", status="active", tags=[])
    sync = DhcpSync(ctx)
    sync._reconcile(SCOPES, [])
    assert len(ctx.netbox.api.ipam.ip_addresses.items) == 1


def test_reserved_lease_creates_device(ctx):
    sync = DhcpSync(ctx)
    sync._reconcile(SCOPES, [reserved_lease()])
    devices = ctx.netbox.api.dcim.devices.items
    assert len(devices) == 1
    device = devices[0]
    assert device.name == "nas"
    slugs = {t.slug for t in device.tags}
    assert MANAGED_TAG_SLUG in slugs and "src-dhcp" in slugs

    interfaces = ctx.netbox.api.dcim.interfaces.items
    assert len(interfaces) == 1 and interfaces[0].name == "eth0"

    ips = ctx.netbox.api.ipam.ip_addresses.items
    assert len(ips) == 1
    assert ips[0].assigned_object_id == interfaces[0].id
    # reserved-lease IPs are assigned to a device and must survive lease listing churn
    sync._reconcile(SCOPES, [])
    assert len(ctx.netbox.api.ipam.ip_addresses.items) == 1


def test_scope_annotates_prefix(ctx):
    prefix = ctx.netbox.api.ipam.prefixes.create(prefix="10.200.10.0/24", status="active")
    sync = DhcpSync(ctx)
    sync._reconcile(SCOPES, [])
    assert "lan" in prefix.custom_fields["dhcp_scope"]
    assert "10.200.10.100-10.200.10.200" in prefix.custom_fields["dhcp_scope"]
