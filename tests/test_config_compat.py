"""Backwards compatibility, enforced against real artifacts.

The promise (see CLAUDE.md): **every release must be able to load configs written by
older releases.** These fixtures are the contract, not test data:

  fixtures/settings_json/    on-disk configs as older releases wrote them
  fixtures/config_exports/   config exports, one pair per release from 2.3.0 on

They are APPEND-ONLY. Regenerating one to make a red test go green destroys the
guarantee silently — if a fixture stops loading, fix the migration chain instead.

Note there is deliberately no pre-2.3.0 *export* fixture: the export format ships in
2.3.0, so an older one cannot honestly exist. Compatibility with earlier releases is
proven by the settings_json family instead.
"""

import json
from pathlib import Path

import pytest

from netbox_monitor import __version__
from netbox_monitor.config import CONFIG_SCHEMA_VERSION, AppConfig, config_from_raw
from netbox_monitor.config_transfer import import_config, peek
from netbox_monitor.settings_store import SettingsStore

FIXTURES = Path(__file__).parent / "fixtures"
SETTINGS_GOLDENS = sorted((FIXTURES / "settings_json").glob("*.json"))
EXPORT_GOLDENS = sorted((FIXTURES / "config_exports").glob("*.json"))

#: the passphrase the encrypted export goldens were generated with
GOLDEN_PASSPHRASE = "golden-fixture-passphrase"


def _ids(paths):
    return [p.name for p in paths]


# ------------------------------------------------- settings.json from old builds


def test_settings_goldens_exist():
    assert SETTINGS_GOLDENS, "no settings.json goldens — compatibility is untested"


@pytest.mark.parametrize("path", SETTINGS_GOLDENS, ids=_ids(SETTINGS_GOLDENS))
def test_old_settings_json_still_loads(path):
    raw = json.loads(path.read_text(encoding="utf-8"))
    config = config_from_raw(raw)
    assert isinstance(config, AppConfig)
    assert config.schema_version == CONFIG_SCHEMA_VERSION
    # every golden describes a configured instance; losing its sites is the exact
    # silent failure the migration chain exists to prevent
    assert config.sites, f"{path.name} migrated to an empty sites list"
    assert config.netbox.url


@pytest.mark.parametrize("path", SETTINGS_GOLDENS, ids=_ids(SETTINGS_GOLDENS))
def test_old_settings_json_boots_the_store(path, tmp_path):
    """The real path a user upgrading in place takes."""
    (tmp_path / "settings.json").write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    store = SettingsStore.bootstrap(tmp_path, None)
    assert store.get().sites
    # migrated in place, so the next boot doesn't repeat the work
    on_disk = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert on_disk["schema_version"] == CONFIG_SCHEMA_VERSION


def test_v1_legacy_settings_keeps_its_secrets_through_migration():
    raw = json.loads((FIXTURES / "settings_json" / "v1-legacy.json").read_text(encoding="utf-8"))
    config = config_from_raw(raw)
    site = config.sites[0]
    assert site.technitium.token == "v1-technitium-token"
    assert site.proxmox[0].token_value == "v1-proxmox-token"
    assert site.discovery.include_prefixes == ["10.0.0.0/24"]


def test_v221_settings_keeps_its_secrets_through_migration():
    raw = json.loads((FIXTURES / "settings_json" / "v2.2.1.json").read_text(encoding="utf-8"))
    config = config_from_raw(raw)
    site = config.sites[0]
    assert config.netbox.token == "v221-netbox-token"
    assert site.technitium.token == "v221-technitium-token"
    assert site.lldp.ssh_password == "v221-site-ssh-password"
    assert config.lldp.credentials[0].password == "v221-cred-password"
    assert config.lldp.exclude_hosts == ["10.0.0.1"]


# ---------------------------------------------------- exports from old builds


@pytest.mark.parametrize("path", EXPORT_GOLDENS, ids=_ids(EXPORT_GOLDENS))
def test_old_export_still_imports(path):
    blob = path.read_bytes()
    header = peek(blob)
    passphrase = GOLDEN_PASSPHRASE if header["encrypted"] else None
    result = import_config(blob, passphrase=passphrase, current=AppConfig())
    assert isinstance(result.config, AppConfig)
    assert result.config.schema_version == CONFIG_SCHEMA_VERSION
    assert result.config.sites


def test_encrypted_golden_round_trips_its_secrets():
    path = FIXTURES / "config_exports" / "2.3.0-encrypted.json"
    result = import_config(path.read_bytes(), passphrase=GOLDEN_PASSPHRASE, current=AppConfig())
    assert result.config.netbox.token == "v221-netbox-token"
    assert result.config.sites[0].lldp.ssh_password == "v221-site-ssh-password"
    assert result.unresolved_secrets == ()


def test_redacted_golden_carries_no_secrets():
    path = FIXTURES / "config_exports" / "2.3.0-redacted.json"
    assert b"v221-netbox-token" not in path.read_bytes()
    result = import_config(path.read_bytes(), passphrase=None, current=AppConfig())
    assert result.config.netbox.token == ""
    assert result.unresolved_secrets  # reported, not silently blank


def test_a_golden_export_exists_for_the_current_version():
    """The forcing function: bumping the version fails CI until a golden is added.

    Regenerate with:
        python -c "import json,sys; sys.path.insert(0,'src');
        from netbox_monitor import __version__;
        from netbox_monitor.config import config_from_raw;
        from netbox_monitor.config_transfer import export_config;
        cfg=config_from_raw(json.load(open('tests/fixtures/settings_json/v2.2.1.json')));
        [open(f'tests/fixtures/config_exports/{__version__}-{k}.json','wb').write(
            export_config(cfg, passphrase='golden-fixture-passphrase' if e else None))
         for k,e in (('encrypted',True),('redacted',False))]"
    """
    versions = {peek(p.read_bytes())["app_version"] for p in EXPORT_GOLDENS}
    assert __version__ in versions, (
        f"no config export golden for v{__version__} — add "
        f"tests/fixtures/config_exports/{__version__}-{{encrypted,redacted}}.json "
        "so future releases are held to importing this one. See this test's docstring."
    )
