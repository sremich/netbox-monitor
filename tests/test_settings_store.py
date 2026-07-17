import json
import os

import pytest

from netbox_monitor.config import (
    CONFIG_SCHEMA_VERSION,
    AppConfig,
    ConfigSchemaTooNewError,
    NetBoxConfig,
    SiteConfig,
)
from netbox_monitor.settings_store import SettingsStore


def make_store(tmp_path) -> SettingsStore:
    return SettingsStore.bootstrap(tmp_path, None)


def test_bootstrap_creates_settings_file(tmp_path):
    store = make_store(tmp_path)
    assert (tmp_path / "settings.json").exists()
    assert store.get().webui.session_secret  # auto-generated


def test_bootstrap_imports_yaml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    yaml_file = tmp_path / "config.yaml"
    yaml_file.write_text(
        "netbox: { url: http://nb, token: t }\ntechnitium: { url: http://dns, token: x }\n",
        encoding="utf-8",
    )
    store = SettingsStore.bootstrap(tmp_path, yaml_file)
    config = store.get()
    assert config.netbox.url == "http://nb"
    assert len(config.sites) == 1  # legacy migrated
    # persisted
    on_disk = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert on_disk["netbox"]["url"] == "http://nb"


def test_existing_settings_take_precedence_over_yaml(tmp_path):
    store = make_store(tmp_path)
    store.replace(AppConfig(netbox=NetBoxConfig(url="http://fromjson", token="t")))
    yaml_file = tmp_path / "config.yaml"
    yaml_file.write_text("netbox: { url: http://fromyaml, token: y }\n", encoding="utf-8")
    reloaded = SettingsStore.bootstrap(tmp_path, yaml_file)
    assert reloaded.get().netbox.url == "http://fromjson"


def test_update_bumps_generation_and_persists(tmp_path):
    store = make_store(tmp_path)
    generation = store.generation
    store.update_field(
        lambda c: c.sites.append(SiteConfig(id="lab", name="Lab", netbox_site="lab"))
    )
    assert store.generation == generation + 1
    on_disk = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert on_disk["sites"][0]["id"] == "lab"


def test_get_returns_copy(tmp_path):
    store = make_store(tmp_path)
    config = store.get()
    config.netbox.url = "http://mutated"
    assert store.get().netbox.url != "http://mutated"


def test_bootstrap_migrates_a_legacy_settings_json(tmp_path):
    """A v1-shaped settings.json used to validate straight through into sites=[],
    silently no-opping every module. It must be migrated on load."""
    (tmp_path / "settings.json").write_text(
        json.dumps(
            {
                "netbox": {"url": "http://nb", "token": "t", "default_site": "Home"},
                "technitium": {"url": "http://dns", "token": "sekrit"},
            }
        ),
        encoding="utf-8",
    )
    store = SettingsStore.bootstrap(tmp_path, None)
    config = store.get()
    assert [s.id for s in config.sites] == ["home"]
    assert config.sites[0].technitium.token == "sekrit"
    # and the file is upgraded in place, so the migration runs once not every boot
    on_disk = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert on_disk["schema_version"] == CONFIG_SCHEMA_VERSION
    assert on_disk["sites"][0]["id"] == "home"


def test_bootstrap_refuses_a_settings_json_from_a_newer_build(tmp_path):
    (tmp_path / "settings.json").write_text(
        json.dumps({"schema_version": CONFIG_SCHEMA_VERSION + 1, "sites": []}), encoding="utf-8"
    )
    with pytest.raises(ConfigSchemaTooNewError):
        SettingsStore.bootstrap(tmp_path, None)


def test_replace_with_backup_writes_bak(tmp_path):
    store = make_store(tmp_path)
    store.replace(AppConfig(netbox=NetBoxConfig(url="http://before", token="t")))

    backup_path = store.replace(
        AppConfig(netbox=NetBoxConfig(url="http://after", token="t")), backup=True
    )

    assert backup_path == tmp_path / "settings.json.bak"
    assert store.get().netbox.url == "http://after"
    # the .bak holds the config as it was *before* this replace
    saved = json.loads(backup_path.read_text(encoding="utf-8"))
    assert saved["netbox"]["url"] == "http://before"


def test_replace_without_backup_writes_no_bak(tmp_path):
    store = make_store(tmp_path)
    store.replace(AppConfig(netbox=NetBoxConfig(url="http://x", token="t")))
    assert not (tmp_path / "settings.json.bak").exists()


@pytest.mark.skipif(os.name == "nt", reason="Windows chmod only maps the read-only bit")
def test_settings_file_is_not_world_readable(tmp_path):
    """settings.json holds plaintext API tokens."""
    store = make_store(tmp_path)
    store.replace(AppConfig(netbox=NetBoxConfig(url="http://nb", token="sekrit")), backup=True)
    assert (tmp_path / "settings.json").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "settings.json.bak").stat().st_mode & 0o777 == 0o600
