"""Per-site LLDP credential resolution and site scoping, exercised through the
crawl's unified registry.collect() call."""

import asyncio
from types import SimpleNamespace

import pytest

from netbox_monitor.config import LldpCredential, SiteLldpConfig
from netbox_monitor.sync import lldp as lldp_mod
from netbox_monitor.sync.lldp import LldpSync


@pytest.fixture(autouse=True)
def _switch_role(nb):
    role = nb.api.dcim.device_roles.create(name="Switch", slug="switch")
    nb.refs["role_switch"] = role.id
    return nb


def make_switch(nb, name, site_id, platform_slug, ip):
    tag = nb.api.extras.tags.get(slug="lldp-source") or nb.api.extras.tags.create(
        name="lldp-source", slug="lldp-source"
    )
    return nb.api.dcim.devices.create(
        name=name,
        site=site_id,
        platform=SimpleNamespace(slug=platform_slug),
        primary_ip4=SimpleNamespace(address=f"{ip}/24"),
        tags=[tag],
    )


def capture_collect(ctx):
    """Run LldpSync, capturing every registry.collect(driver, host, **kw)."""
    calls = []

    async def fake_collect(driver, host, **kw):
        calls.append((driver, host, kw))
        return []

    orig = lldp_mod.registry.collect
    lldp_mod.registry.collect = fake_collect
    try:
        asyncio.run(LldpSync(ctx).run())
    finally:
        lldp_mod.registry.collect = orig
    return calls


def test_disabled_site_not_polled(ctx):
    ctx.config.lldp.enabled = False
    ctx.sites[0].config.lldp = SiteLldpConfig(enabled=False)
    make_switch(ctx.netbox, "sw1", ctx.netbox.home_site_id, "unifi", "10.0.0.5")
    assert capture_collect(ctx) == []


def test_site_ssh_credentials_used(ctx):
    ctx.sites[0].config.lldp = SiteLldpConfig(
        enabled=True, ssh_username="siteadmin", ssh_password="sitepass"
    )
    make_switch(ctx.netbox, "sw1", ctx.netbox.home_site_id, "unifi", "10.0.0.5")
    calls = capture_collect(ctx)
    # first attempt uses the unifi driver (platform hint) with the site SSH creds
    driver, host, kw = calls[0]
    assert host == "10.0.0.5"
    assert driver == "unifi"
    assert kw["username"] == "siteadmin" and kw["password"] == "sitepass"


def test_site_snmp_community_used(ctx):
    ctx.sites[0].config.lldp = SiteLldpConfig(enabled=True, snmp_community="sitecomm")
    make_switch(ctx.netbox, "sw2", ctx.netbox.home_site_id, "generic", "10.0.0.6")
    calls = capture_collect(ctx)
    drivers = {d for d, _h, _k in calls}
    assert "snmp" in drivers
    snmp_call = next(c for c in calls if c[0] == "snmp")
    assert snmp_call[2]["snmp_community"] == "sitecomm"


def test_global_credential_profiles_tried(ctx):
    ctx.sites[0].config.lldp = SiteLldpConfig(enabled=True)  # no site creds
    ctx.config.lldp.credentials = [
        LldpCredential(name="corp-snmp", driver="snmp", snmp_community="globalcomm")
    ]
    make_switch(ctx.netbox, "sw3", ctx.netbox.home_site_id, "generic", "10.0.0.7")
    calls = capture_collect(ctx)
    snmp_call = next(c for c in calls if c[0] == "snmp")
    assert snmp_call[2]["snmp_community"] == "globalcomm"


def test_known_vendor_host_not_credential_sprayed(ctx):
    """A switch whose vendor is known (platform hint) must only be tried with that
    one SSH driver, not every vendor's login — anti-lockout for production gear."""
    ctx.sites[0].config.lldp = SiteLldpConfig(enabled=True, ssh_username="admin", ssh_password="pw")
    # a unifi-platform seed with an 'auto' credential
    make_switch(ctx.netbox, "usw", ctx.netbox.home_site_id, "unifi", "10.0.0.5")
    calls = capture_collect(ctx)
    ssh_calls = [c for c in calls if c[0] in {"cisco", "arista", "aruba", "mikrotik", "unifi"}]
    # only the unifi driver is attempted, not all five SSH drivers
    assert {c[0] for c in ssh_calls} == {"unifi"}


def test_other_sites_switches_not_polled(ctx):
    ctx.sites[0].config.lldp = SiteLldpConfig(enabled=True, snmp_community="c")
    other = ctx.netbox.api.dcim.sites.create(name="Elsewhere", slug="elsewhere")
    make_switch(ctx.netbox, "far-switch", other.id, "generic", "10.9.9.9")
    calls = capture_collect(ctx)
    assert "10.9.9.9" not in [h for _d, h, _k in calls]
