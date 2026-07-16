import json

from netbox_monitor.config import AppConfig, NetBoxConfig, SiteConfig
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
