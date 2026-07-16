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


def make_vm_with_mac(nb, name, mac, managed=True):
    vm = nb.api.virtualization.virtual_machines.create(
        name=name,
        status="active",
        primary_ip4=None,
        tags=nb.tag_ids(MANAGED_TAG_SLUG, "src-proxmox") if managed else [],
    )
    iface = nb.api.virtualization.interfaces.create(virtual_machine=vm, name="net0")
    # NetBox >= 4.2 model: MACs are standalone objects assigned to interfaces
    nb.api.dcim.mac_addresses.create(
        mac_address=mac,
        assigned_object_type="virtualization.vminterface",
        assigned_object_id=iface.id,
    )
    return vm, iface


def test_dynamic_lease_links_to_vm_by_mac(ctx):
    nb = ctx.netbox
    vm, iface = make_vm_with_mac(nb, "jellyfin", "24:A4:3C:AA:BB:CC")

    sync = DhcpSync(ctx)
    sync._reconcile(SCOPES, [dynamic_lease()])  # same MAC as the VM interface

    ips = nb.api.ipam.ip_addresses.items
    assert len(ips) == 1
    assert ips[0].assigned_object_type == "virtualization.vminterface"
    assert ips[0].assigned_object_id == iface.id
    assert vm.primary_ip4 == ips[0].id

    # lease expires: the IP is deleted even though it was assigned to a VM interface
    sync._reconcile(SCOPES, [])
    assert nb.api.ipam.ip_addresses.items == []


def test_dynamic_lease_does_not_claim_unmanaged_vm(ctx):
    nb = ctx.netbox
    vm, _iface = make_vm_with_mac(nb, "handmade-vm", "24:A4:3C:AA:BB:CC", managed=False)
    sync = DhcpSync(ctx)
    sync._reconcile(SCOPES, [dynamic_lease()])
    # the IP is still linked to the interface, but a human-made VM's primary is not touched
    assert nb.api.ipam.ip_addresses.items[0].assigned_object_type == ("virtualization.vminterface")
    assert vm.primary_ip4 is None


def test_reserved_lease_for_vm_attaches_and_dedupes(ctx):
    nb = ctx.netbox
    sync = DhcpSync(ctx)

    # first pass: VM not in NetBox yet -> a device gets created for the reservation
    sync._reconcile(SCOPES, [reserved_lease()])
    assert nb.api.dcim.devices.get(name="nas") is not None

    # proxmox sync later documents the guest with the same MAC
    vm, iface = make_vm_with_mac(nb, "nas", "24:A4:3C:11:22:33")

    # next pass: the duplicate device is removed, IP moves to the VM interface
    sync._reconcile(SCOPES, [reserved_lease()])
    assert nb.api.dcim.devices.get(name="nas") is None
    ips = nb.api.ipam.ip_addresses.items
    assert len(ips) == 1
    assert ips[0].assigned_object_type == "virtualization.vminterface"
    assert ips[0].assigned_object_id == iface.id
    assert vm.primary_ip4 == ips[0].id

    # reserved IPs are never deleted, even when assigned to a VM interface
    sync._reconcile(SCOPES, [reserved_lease()])
    assert len(nb.api.ipam.ip_addresses.items) == 1


def test_scope_annotates_prefix(ctx):
    prefix = ctx.netbox.api.ipam.prefixes.create(prefix="10.200.10.0/24", status="active")
    sync = DhcpSync(ctx)
    sync._reconcile(SCOPES, [])
    assert "lan" in prefix.custom_fields["dhcp_scope"]
    assert "10.200.10.100-10.200.10.200" in prefix.custom_fields["dhcp_scope"]
