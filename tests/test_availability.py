"""Availability monitor: excluded prefixes are neither scanned nor polled.

The bug this guards: a device whose IP is in a site's ``exclude_prefixes`` was
still pinged every minute (the monitor queries managed devices globally, with no
exclude filter), which kept stale/excluded hosts alive and polled excluded ranges.
"""

from types import SimpleNamespace

from netbox_monitor.clients.netbox import MANAGED_TAG_SLUG
from netbox_monitor.config import AppConfig, NetBoxConfig, SiteConfig, SiteDiscoveryConfig
from netbox_monitor.context import ResolvedSite
from netbox_monitor.sync import availability as availability_mod
from netbox_monitor.sync.availability import AvailabilitySync
from netbox_monitor.sync.common import ip_in_networks, parse_ipv4_networks

# ------------------------------------------------------------- unit: helpers


def test_ip_in_networks_matches_and_misses():
    nets = parse_ipv4_networks(["10.210.11.0/24", "10.210.12.0/24"])
    assert ip_in_networks("10.210.11.33", nets) is True
    assert ip_in_networks("10.210.12.254", nets) is True
    assert ip_in_networks("10.200.11.7", nets) is False


def test_ip_in_networks_is_safe_on_junk_and_ipv6():
    nets = parse_ipv4_networks(["10.210.11.0/24"])
    assert ip_in_networks("not-an-ip", nets) is False
    assert ip_in_networks("2001:db8::1", nets) is False  # v6 never matches a v4 net
    assert ip_in_networks("10.0.0.1", []) is False


def test_parse_ipv4_networks_drops_non_v4_and_invalid():
    nets = parse_ipv4_networks(["10.0.0.0/8", "2001:db8::/32", "garbage"])
    assert [str(n) for n in nets] == ["10.0.0.0/8"]


# --------------------------------------------------- integration: run() skips


def _monitored_device(nb, name, ip):
    return nb.api.dcim.devices.create(
        name=name,
        site=SimpleNamespace(id=nb.home_site_id, slug="home"),
        tags=nb.tag_ids(MANAGED_TAG_SLUG, "src-scan"),
        primary_ip4=SimpleNamespace(address=f"{ip}/24"),
    )


def _ctx(nb, exclude):
    config = AppConfig(
        netbox=NetBoxConfig(url="http://nb", token="t"),
        sites=[
            SiteConfig(
                id="uk",
                name="UK",
                netbox_site="uk",
                discovery=SiteDiscoveryConfig(exclude_prefixes=exclude),
            )
        ],
    )
    return SimpleNamespace(
        config=config,
        netbox=nb,
        state=None,  # unused: our fake ping returns no results, so the result loop is skipped
        sites=[ResolvedSite(config=config.sites[0], netbox_site_id=nb.home_site_id)],
    )


def test_availability_does_not_ping_excluded_ips(nb, monkeypatch):
    _monitored_device(nb, "in-scope", "10.200.11.7")
    _monitored_device(nb, "excluded-a", "10.210.11.33")
    _monitored_device(nb, "excluded-b", "10.210.12.254")

    pinged: list[str] = []

    async def fake_multiping(addresses, **kw):
        pinged.extend(addresses)
        return []  # no results -> run() does no state work

    monkeypatch.setattr(availability_mod, "async_multiping", fake_multiping)

    import asyncio

    ctx = _ctx(nb, exclude=["10.210.11.0/24", "10.210.12.0/24"])
    asyncio.run(AvailabilitySync(ctx).run())

    assert "10.200.11.7" in pinged
    assert "10.210.11.33" not in pinged
    assert "10.210.12.254" not in pinged


def test_availability_pings_everything_when_nothing_excluded(nb, monkeypatch):
    _monitored_device(nb, "a", "10.200.11.7")
    _monitored_device(nb, "b", "10.210.11.33")

    pinged: list[str] = []

    async def fake_multiping(addresses, **kw):
        pinged.extend(addresses)
        return []

    monkeypatch.setattr(availability_mod, "async_multiping", fake_multiping)

    import asyncio

    asyncio.run(AvailabilitySync(_ctx(nb, exclude=[])).run())
    assert set(pinged) == {"10.200.11.7", "10.210.11.33"}
