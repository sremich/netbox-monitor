"""Multi-site behavior: two sites, independent scopes; the delete pass only runs
on complete data across all sites."""

import asyncio

from netbox_monitor.config import SiteConfig
from netbox_monitor.context import ResolvedSite
from netbox_monitor.sync.dhcp import DhcpSync


class FakeTechnitium:
    def __init__(self, scopes, leases, fail=False):
        self.scopes, self.leases, self.fail = scopes, leases, fail

    async def list_dhcp_scopes(self):
        if self.fail:
            raise RuntimeError("technitium unreachable")
        return self.scopes

    async def list_dhcp_leases(self):
        if self.fail:
            raise RuntimeError("technitium unreachable")
        return self.leases


def lease(address, mac="24-A4-3C-AA-BB-01", host="host.lan", type_="Dynamic"):
    return {
        "scope": "lan",
        "type": type_,
        "hardwareAddress": mac,
        "address": address,
        "hostName": host,
    }


def scope(name, prefix24):
    """A /24 DHCP scope for the given first-three-octets prefix (e.g. '10.200.10')."""
    return {
        "name": name,
        "enabled": True,
        "startingAddress": f"{prefix24}.1",
        "endingAddress": f"{prefix24}.254",
        "subnetMask": "255.255.255.0",
    }


SCOPE_A = scope("lan-a", "10.200.10")
SCOPE_B = scope("lan-b", "192.168.50")


def two_site_ctx(ctx, nb, leases_a, leases_b, fail_b=False):
    site_b_cfg = SiteConfig(id="beach", name="Beach", netbox_site="beach")
    beach = nb.api.dcim.sites.create(name="Beach", slug="beach")
    ctx.sites = [
        ResolvedSite(
            config=ctx.config.sites[0],
            netbox_site_id=nb.home_site_id,
            technitium=FakeTechnitium([SCOPE_A], leases_a),
        ),
        ResolvedSite(
            config=site_b_cfg,
            netbox_site_id=beach.id,
            technitium=FakeTechnitium([SCOPE_B], leases_b, fail=fail_b),
        ),
    ]
    return ctx


def test_two_sites_sync_independent_leases(ctx):
    nb = ctx.netbox
    ctx = two_site_ctx(ctx, nb, [lease("10.200.10.50")], [lease("192.168.50.60", mac=None)])
    asyncio.run(DhcpSync(ctx).run())
    addresses = {str(ip.address).split("/")[0] for ip in nb.api.ipam.ip_addresses.items}
    assert addresses == {"10.200.10.50", "192.168.50.60"}


def test_expiry_deletes_across_sites(ctx):
    nb = ctx.netbox
    ctx = two_site_ctx(ctx, nb, [lease("10.200.10.50")], [lease("192.168.50.60", mac=None)])
    asyncio.run(DhcpSync(ctx).run())
    # site A's lease expires; site B keeps its lease
    ctx.sites[0].technitium.leases = []
    asyncio.run(DhcpSync(ctx).run())
    addresses = {str(ip.address).split("/")[0] for ip in nb.api.ipam.ip_addresses.items}
    assert addresses == {"192.168.50.60"}


def test_failed_site_ips_not_deleted(ctx):
    nb = ctx.netbox
    ctx = two_site_ctx(ctx, nb, [lease("10.200.10.50")], [lease("192.168.50.60", mac=None)])
    asyncio.run(DhcpSync(ctx).run())
    assert len(nb.api.ipam.ip_addresses.items) == 2

    # site B goes unreachable AND site A's lease expires. Site A's expired IP is
    # still deleted (scope A was fetched), but site B's IP survives (scope B was not).
    ctx.sites[1].technitium.fail = True
    ctx.sites[0].technitium.leases = []
    asyncio.run(DhcpSync(ctx).run())
    addresses = {str(ip.address).split("/")[0] for ip in nb.api.ipam.ip_addresses.items}
    assert addresses == {"192.168.50.60"}  # B's IP untouched despite missing from this run

    assert any(
        module == "dhcp" and scope == "beach" and not ok
        for module, scope, ok, _ in ctx.status.records
    )


def test_removed_site_ips_not_deleted(ctx):
    """M1 regression: dropping a site from config (e.g. disabled/token blanked)
    must not make its dynamic IPs look expired."""
    nb = ctx.netbox
    ctx = two_site_ctx(ctx, nb, [lease("10.200.10.50")], [lease("192.168.50.60", mac=None)])
    asyncio.run(DhcpSync(ctx).run())
    assert len(nb.api.ipam.ip_addresses.items) == 2

    # site B is removed entirely (config shrinkage) — only site A remains
    ctx.sites = [ctx.sites[0]]
    asyncio.run(DhcpSync(ctx).run())
    addresses = {str(ip.address).split("/")[0] for ip in nb.api.ipam.ip_addresses.items}
    assert "192.168.50.60" in addresses  # B's IP is NOT deleted


def test_reserved_lease_created_in_its_site(ctx):
    nb = ctx.netbox
    ctx = two_site_ctx(
        ctx, nb, [], [lease("192.168.50.10", host="nas.beach.lan", type_="Reserved")]
    )
    asyncio.run(DhcpSync(ctx).run())
    device = nb.api.dcim.devices.get(name="nas")
    assert device is not None
    beach_site = nb.api.dcim.sites.get(slug="beach")
    assert device.site == beach_site.id
