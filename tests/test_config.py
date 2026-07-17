import textwrap

import pytest

from netbox_monitor.config import (
    CONFIG_SCHEMA_VERSION,
    ConfigSchemaTooNewError,
    _detect_schema,
    config_from_raw,
    load_config,
    migrate_legacy,
    migrate_to_current,
)


def test_legacy_config_migrates_to_single_site(tmp_path, monkeypatch):
    monkeypatch.setenv("NETBOX_TOKEN", "sekrit")
    monkeypatch.delenv("TECHNITIUM_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        textwrap.dedent(
            """
            netbox:
              url: http://netbox.home.lan:8000
              token: ${NETBOX_TOKEN}
              default_site: Home
            technitium:
              url: http://10.200.11.2:5380
              token: ${TECHNITIUM_TOKEN:-fallback}
            proxmox:
              - host: 10.200.11.91
                user: monitor@pve
                token_name: netbox
                token_value: pvetoken
            discovery:
              include_prefixes: ["10.200.9.0/24"]
              exclude_prefixes: ["10.200.99.0/29"]
            dry_run: true
            """
        ),
        encoding="utf-8",
    )
    cfg = load_config(cfg_file)
    assert cfg.netbox.token == "sekrit"
    assert cfg.dry_run is True
    # legacy flat config becomes exactly one site
    assert len(cfg.sites) == 1
    site = cfg.sites[0]
    assert site.id == "home"
    assert site.netbox_site == "home"
    assert site.technitium is not None and site.technitium.token == "fallback"
    assert site.proxmox[0].host == "10.200.11.91"
    assert site.discovery.include_prefixes == ["10.200.9.0/24"]
    assert site.discovery.exclude_prefixes == ["10.200.99.0/29"]
    # global defaults intact
    assert cfg.availability.stale_after == 600
    assert cfg.lifecycle.delete_dhcp_on_expiry is True
    assert cfg.certs.ports == [443, 8443]
    assert cfg.webui.port == 8899


def test_v2_config_not_remigrated():
    raw = {"sites": [{"id": "a", "name": "A"}], "technitium": {"url": "x"}}
    result = migrate_legacy(dict(raw))
    assert result["sites"] == raw["sites"]  # untouched


def test_sites_config_loads(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        textwrap.dedent(
            """
            netbox: { url: http://nb, token: t }
            sites:
              - id: home
                name: Home
                netbox_site: home
                technitium: { url: "http://10.200.11.2:5380", token: abc }
              - id: beach
                name: Beach House
                netbox_site: beach-house
                discovery:
                  include_prefixes: ["192.168.50.0/24"]
            dhcp: { interval: 120 }
            """
        ),
        encoding="utf-8",
    )
    cfg = load_config(cfg_file)
    assert [s.id for s in cfg.sites] == ["home", "beach"]
    assert cfg.sites[1].technitium is None
    assert cfg.dhcp.interval == 120


# --------------------------------------------------- schema version + chain


def test_detect_schema_reads_explicit_field():
    assert _detect_schema({"schema_version": 2, "sites": []}) == 2
    assert _detect_schema({"schema_version": 7}) == 7


def test_detect_schema_sniffs_configs_predating_the_field():
    # v2 layout is identified by its sites list...
    assert _detect_schema({"sites": [{"id": "home"}]}) == 2
    # ...and a v1 flat config by the absence of one
    assert _detect_schema({"technitium": {"url": "x"}}) == 1


def test_migrate_to_current_upgrades_v1_and_stamps_the_version():
    raw = migrate_to_current({"netbox": {"default_site": "Home"}, "technitium": {"url": "x"}})
    assert raw["schema_version"] == CONFIG_SCHEMA_VERSION
    assert [s["id"] for s in raw["sites"]] == ["home"]
    assert raw["sites"][0]["technitium"] == {"url": "x"}


def test_migrate_to_current_is_idempotent():
    once = migrate_to_current({"technitium": {"url": "x"}})
    twice = migrate_to_current(dict(once))
    assert twice == once


def test_config_from_raw_refuses_a_newer_schema():
    with pytest.raises(ConfigSchemaTooNewError) as exc:
        config_from_raw({"schema_version": CONFIG_SCHEMA_VERSION + 1, "sites": []})
    assert exc.value.found == CONFIG_SCHEMA_VERSION + 1


def test_config_from_raw_migrates_a_v1_dict():
    """The gap that used to bite: a v1-shaped dict validated straight to sites=[]."""
    config = config_from_raw(
        {
            "netbox": {"url": "http://nb", "default_site": "Home"},
            "technitium": {"url": "http://t", "token": "tok"},
        }
    )
    assert [s.id for s in config.sites] == ["home"]
    assert config.sites[0].technitium.token == "tok"
