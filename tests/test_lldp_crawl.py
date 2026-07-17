"""LLDP crawl engine: BFS propagation, dedup, bounds, credential trials,
auto-create switches, and the non-switch guard."""

import asyncio
from types import SimpleNamespace

import pytest

from netbox_monitor.config import LldpCredential, SiteLldpConfig
from netbox_monitor.lldp import LldpNeighbor
from netbox_monitor.sync import lldp as lldp_mod
from netbox_monitor.sync.lldp import LldpSync


@pytest.fixture(autouse=True)
def _switch_role(nb):
    role = nb.api.dcim.device_roles.create(name="Switch", slug="switch")
    nb.refs["role_switch"] = role.id
    return nb


def seed_switch(nb, name, ip, platform="mikrotik"):
    tag = nb.api.extras.tags.get(slug="lldp-source") or nb.api.extras.tags.create(
        name="lldp-source", slug="lldp-source"
    )
    return nb.api.dcim.devices.create(
        name=name,
        site=nb.home_site_id,
        platform=SimpleNamespace(slug=platform),
        primary_ip4=SimpleNamespace(address=f"{ip}/24"),
        tags=[tag],
    )


def nbr(port, ip, mac, descr, caps=("bridge",), sysname=None):
    return LldpNeighbor(
        local_port=port,
        chassis_mac=mac,
        sysname=sysname or f"sw-{ip}",
        remote_port="uplink",
        mgmt_ip=ip,
        capabilities=set(caps),
        sys_descr=descr,
    )


def run_lldp(ctx, fake_topology, enable_crawl=True, max_switches=100):
    """fake_topology: {host_ip: [LldpNeighbor,...]} returned by the collector."""
    ctx.config.lldp.crawl_enabled = enable_crawl
    ctx.config.lldp.max_switches = max_switches
    ctx.config.lldp.credentials = [
        LldpCredential(name="p1", driver="mikrotik", username="admin", password="pw")
    ]
    ctx.sites[0].config.lldp = SiteLldpConfig(enabled=True, ssh_username="admin", ssh_password="pw")

    calls = []

    async def fake_collect(driver, host, **kw):
        calls.append((driver, host))
        if host in fake_topology:
            return fake_topology[host]
        raise RuntimeError("unreachable")

    orig = lldp_mod.registry.collect
    lldp_mod.registry.collect = fake_collect
    try:
        asyncio.run(LldpSync(ctx).run())
    finally:
        lldp_mod.registry.collect = orig
    return calls


def test_crawl_propagates_and_autocreates(ctx):
    nb = ctx.netbox
    seed_switch(nb, "sw-a", "10.0.0.1")
    topo = {
        "10.0.0.1": [nbr("e1", "10.0.0.2", "aa:bb:cc:00:00:02", "Cisco IOS", sysname="sw-b")],
        "10.0.0.2": [nbr("e9", "10.0.0.3", "aa:bb:cc:00:00:03", "Arista EOS", sysname="sw-c")],
        "10.0.0.3": [],
    }
    run_lldp(ctx, topo)
    names = {d.name for d in nb.api.dcim.devices.items}
    assert "sw-a" in names  # seed
    assert "sw-b" in names and "sw-c" in names  # crawled + auto-created
    # cables drawn
    assert len(nb.api.dcim.cables.items) >= 2


def test_crawl_skips_non_switch_neighbors(ctx):
    nb = ctx.netbox
    seed_switch(nb, "sw-a", "10.0.0.1")
    # a Proxmox/Debian host advertising bridge — must NOT be crawled or created
    topo = {
        "10.0.0.1": [
            nbr("e1", "10.0.0.50", "aa:bb:cc:00:00:50", "Debian GNU/Linux", sysname="pve1")
        ],
        "10.0.0.50": [],
    }
    calls = run_lldp(ctx, topo)
    assert "10.0.0.50" not in [host for _d, host in calls]  # never polled
    assert nb.api.dcim.devices.get(name="pve1") is None  # never created


def test_crawl_respects_max_switches(ctx):
    nb = ctx.netbox
    seed_switch(nb, "sw-a", "10.0.0.1")
    topo = {
        "10.0.0.1": [nbr("e1", "10.0.0.2", "aa:bb:cc:00:00:02", "Cisco IOS", sysname="sw-b")],
        "10.0.0.2": [nbr("e2", "10.0.0.3", "aa:bb:cc:00:00:03", "Cisco IOS", sysname="sw-c")],
        "10.0.0.3": [],
    }
    calls = run_lldp(ctx, topo, max_switches=1)
    assert len([h for _d, h in calls]) == 1  # capped at one poll


def test_crawl_dedup_on_loop(ctx):
    nb = ctx.netbox
    seed_switch(nb, "sw-a", "10.0.0.1")
    # a-b-a loop: each sees the other; should not poll a host twice
    topo = {
        "10.0.0.1": [nbr("e1", "10.0.0.2", "aa:bb:cc:00:00:02", "Cisco IOS", sysname="sw-b")],
        "10.0.0.2": [nbr("e2", "10.0.0.1", "aa:bb:cc:00:00:01", "Cisco IOS", sysname="sw-a")],
    }
    calls = run_lldp(ctx, topo)
    hosts = [h for _d, h in calls]
    assert hosts.count("10.0.0.1") == 1
    assert hosts.count("10.0.0.2") == 1


def test_excluded_host_never_authenticated(ctx):
    nb = ctx.netbox
    seed_switch(nb, "sw-a", "10.0.0.1")
    # the seed sees a production router (10.0.0.254) that is a real switch/gateway
    topo = {
        "10.0.0.1": [
            nbr("e1", "10.0.0.254", "aa:bb:cc:00:02:54", "Ubiquiti UniFi UCG", sysname="router")
        ],
        "10.0.0.254": [nbr("x", "10.0.0.99", "aa:bb:cc:00:00:99", "Cisco IOS")],  # would crawl on
    }
    ctx.config.lldp.exclude_hosts = ["10.0.0.254"]
    calls = run_lldp(ctx, topo)
    polled_hosts = [h for _d, h in calls]
    # the router is documented but NEVER contacted
    assert "10.0.0.254" not in polled_hosts
    assert nb.api.dcim.devices.get(name="router") is not None  # still documented
    # and nothing behind it was reached (no session to the router = no onward crawl)
    assert "10.0.0.99" not in polled_hosts


def test_dead_switch_does_not_abort(ctx):
    nb = ctx.netbox
    seed_switch(nb, "sw-a", "10.0.0.1")
    # sw-b is unreachable (not in topology) but sw-c is fine
    topo = {
        "10.0.0.1": [
            nbr("e1", "10.0.0.2", "aa:bb:cc:00:00:02", "Cisco IOS", sysname="sw-b"),
            nbr("e2", "10.0.0.3", "aa:bb:cc:00:00:03", "Cisco IOS", sysname="sw-c"),
        ],
        "10.0.0.3": [],  # sw-c reachable; sw-b absent -> collect raises
    }
    run_lldp(ctx, topo)
    # sw-c still got polled/created despite sw-b failing
    assert nb.api.dcim.devices.get(name="sw-c") is not None


class _LogRecorder:
    """Captures structlog calls so a diagnostic can be asserted on."""

    def __init__(self):
        self.warnings: list[tuple[str, dict]] = []

    def warning(self, event, **kw):
        self.warnings.append((event, kw))

    def info(self, *a, **kw):
        pass

    debug = exception = info


def test_failed_switch_reports_why_in_status(ctx):
    """A switch that no driver/credential works for must say *why* — otherwise it is
    indistinguishable from one that was never tried."""
    seed_switch(ctx.netbox, "sw-a", "10.0.0.1")
    run_lldp(ctx, {})  # nothing reachable -> the collector raises

    _module, _scope, ok, message = ctx.status.records[-1]
    assert not ok
    assert "10.0.0.1" in message
    assert "RuntimeError" in message  # the actual failure type, not just "unreachable"


def test_seed_at_unconfigured_site_is_reported(ctx, monkeypatch):
    """Seeds are looked up per site, so an lldp-source switch left on an old site is
    silently never polled. It must at least be flagged."""
    nb = ctx.netbox
    other = nb.api.dcim.sites.create(name="Old Site", slug="old-site")
    tag = nb.api.extras.tags.get(slug="lldp-source") or nb.api.extras.tags.create(
        name="lldp-source", slug="lldp-source"
    )
    nb.api.dcim.devices.create(
        name="sw-stranded",
        site=SimpleNamespace(id=other.id, slug="old-site"),
        platform=SimpleNamespace(slug="mikrotik"),
        primary_ip4=SimpleNamespace(address="10.9.9.9/24"),
        tags=[tag],
    )
    seed_switch(nb, "sw-a", "10.0.0.1")  # a normal seed at the configured site

    rec = _LogRecorder()
    monkeypatch.setattr(lldp_mod, "log", rec)
    calls = run_lldp(ctx, {"10.0.0.1": []})

    assert any(
        "never be polled" in event and kw.get("switch") == "sw-stranded"
        for event, kw in rec.warnings
    )
    assert "10.9.9.9" not in [h for _d, h in calls]  # still not polled — only reported
