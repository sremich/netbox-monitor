"""Per-site LLDP: switches are selected by site, credentials resolve
netbox-secrets -> site -> global fallback."""

import asyncio
from unittest.mock import AsyncMock, patch

from netbox_monitor.config import LldpFallbackCred, SiteLldpConfig
from netbox_monitor.sync.lldp import LldpSync


def make_switch(nb, name, site_id, platform_slug, ip):
    from types import SimpleNamespace

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


def test_site_lldp_disabled_means_no_polling(ctx):
    ctx.config.lldp.enabled = False
    ctx.sites[0].config.lldp = SiteLldpConfig(enabled=False)
    make_switch(ctx.netbox, "sw1", ctx.netbox.home_site_id, "unifi", "10.0.0.5")
    sync = LldpSync(ctx)
    with patch("netbox_monitor.sync.lldp.unifi_ssh_driver") as ssh:
        asyncio.run(sync.run())
        ssh.collect.assert_not_called()


def test_site_credentials_used_for_unifi(ctx):
    ctx.sites[0].config.lldp = SiteLldpConfig(
        enabled=True, ssh_username="siteadmin", ssh_password="sitepass"
    )
    make_switch(ctx.netbox, "sw1", ctx.netbox.home_site_id, "unifi", "10.0.0.5")
    sync = LldpSync(ctx)
    with patch(
        "netbox_monitor.sync.lldp.unifi_ssh_driver.collect", new=AsyncMock(return_value=[])
    ) as collect:
        asyncio.run(sync.run())
        collect.assert_awaited_once_with("10.0.0.5", "siteadmin", "sitepass")


def test_site_snmp_community_used(ctx):
    ctx.sites[0].config.lldp = SiteLldpConfig(enabled=True, snmp_community="sitecomm")
    make_switch(ctx.netbox, "sw2", ctx.netbox.home_site_id, "edgeswitch", "10.0.0.6")
    sync = LldpSync(ctx)
    with patch(
        "netbox_monitor.sync.lldp.snmp_driver.collect", new=AsyncMock(return_value=[])
    ) as collect:
        asyncio.run(sync.run())
        collect.assert_awaited_once_with("10.0.0.6", "sitecomm")


def test_global_fallback_when_site_has_no_creds(ctx):
    ctx.sites[0].config.lldp = SiteLldpConfig(enabled=True)
    ctx.config.lldp.fallback_creds = {"edgeswitch": LldpFallbackCred(community="globalcomm")}
    make_switch(ctx.netbox, "sw3", ctx.netbox.home_site_id, "edgeswitch", "10.0.0.7")
    sync = LldpSync(ctx)
    with patch(
        "netbox_monitor.sync.lldp.snmp_driver.collect", new=AsyncMock(return_value=[])
    ) as collect:
        asyncio.run(sync.run())
        collect.assert_awaited_once_with("10.0.0.7", "globalcomm")


def test_other_sites_switches_not_polled(ctx):
    ctx.sites[0].config.lldp = SiteLldpConfig(enabled=True, snmp_community="c")
    other_site = ctx.netbox.api.dcim.sites.create(name="Elsewhere", slug="elsewhere")
    make_switch(ctx.netbox, "far-switch", other_site.id, "edgeswitch", "10.9.9.9")
    sync = LldpSync(ctx)
    with patch(
        "netbox_monitor.sync.lldp.snmp_driver.collect", new=AsyncMock(return_value=[])
    ) as collect:
        asyncio.run(sync.run())
        collect.assert_not_awaited()
