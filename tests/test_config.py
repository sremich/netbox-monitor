import textwrap

from netbox_monitor.config import load_config


def test_load_config_env_interpolation(tmp_path, monkeypatch):
    monkeypatch.setenv("NETBOX_TOKEN", "sekrit")
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        textwrap.dedent(
            """
            netbox:
              url: http://netbox.home.lan:8000
              token: ${NETBOX_TOKEN}
            technitium:
              url: http://10.200.11.2:5380
              token: ${TECHNITIUM_TOKEN:-fallback}
            dry_run: true
            """
        ),
        encoding="utf-8",
    )
    cfg = load_config(cfg_file)
    assert cfg.netbox.token == "sekrit"
    assert cfg.technitium.token == "fallback"
    assert cfg.dry_run is True
    # defaults
    assert cfg.availability.stale_after == 600
    assert cfg.lifecycle.delete_dhcp_on_expiry is True
    assert cfg.lldp.enabled is False
    assert cfg.certs.ports == [443, 8443]
