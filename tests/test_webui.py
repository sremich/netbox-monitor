"""Web UI: auth flow, settings edit (intervals), site CRUD, security guards."""

from fastapi.testclient import TestClient

from conftest import FakeStatus, csrf_token, login
from netbox_monitor import __version__
from netbox_monitor.config import CONFIG_SCHEMA_VERSION
from netbox_monitor.settings_store import SettingsStore
from netbox_monitor.webui.app import _same_origin, create_app
from netbox_monitor.webui.auth import verify_password

PP = "correct-horse-battery-staple"


def test_requires_login(client):
    assert client.get("/").status_code == 303
    assert client.get("/").headers["location"] == "/login"


def test_wrong_password_rejected(client):
    response = client.post("/login", data={"password": "nope"})
    assert response.status_code == 200
    assert "Wrong password" in response.text


def test_login_and_dashboard(client):
    login(client)
    response = client.get("/")
    assert response.status_code == 200
    assert "Dashboard" in response.text


def _settings_form():
    form = {"log_level": "INFO", "stale_after": "600"}
    for m in ("dhcp", "dns", "discovery", "availability", "proxmox", "lldp", "certs"):
        form[f"interval_{m}"] = "300"
    return form


def test_password_change_requires_current_password(client, store):
    login(client)
    old_hash = store.get().webui.password_hash
    form = _settings_form() | {"new_password": "brandnewpass", "current_password": "wrong"}
    response = client.post("/settings", data=form)
    assert response.status_code == 200
    assert "Current password is incorrect" in response.text
    assert store.get().webui.password_hash == old_hash  # unchanged


def test_password_change_rotates_session(client, store):
    login(client)
    old_secret = store.get().webui.session_secret
    form = _settings_form() | {"new_password": "brandnewpass", "current_password": "hunter22"}
    response = client.post("/settings", data=form)
    assert response.status_code == 200
    cfg = store.get()
    assert verify_password("brandnewpass", cfg.webui.password_hash)
    assert cfg.webui.session_secret != old_secret  # old cookies invalidated


def test_short_new_password_rejected(client, store):
    login(client)
    form = _settings_form() | {"new_password": "short", "current_password": "hunter22"}
    response = client.post("/settings", data=form)
    assert "at least 8 characters" in response.text
    assert verify_password("hunter22", store.get().webui.password_hash)  # unchanged


def test_cross_origin_post_blocked(client):
    login(client)
    # a POST whose Origin isn't our host is rejected (CSRF defense)
    response = client.post(
        "/run/dhcp", headers={"origin": "http://evil.example.com", "host": "localhost"}
    )
    assert response.status_code == 403


def test_netbox_test_never_forwards_token_to_foreign_url(client, store, monkeypatch):
    """The saved NetBox token must never be sent to a URL that isn't the saved one."""
    login(client)
    store.update_field(
        lambda c: (
            setattr(c.netbox, "url", "https://netbox.mine:8000"),
            setattr(c.netbox, "token", "SAVEDNBTOKEN"),
        )
    )

    captured = {}

    class FakeApi:
        def __init__(self, url, token=None):
            captured["url"] = url
            captured["token"] = token
            self.http_session = type("S", (), {"verify": True})()

        def status(self):
            return {"netbox-version": "4.3.6"}

    import pynetbox

    monkeypatch.setattr(pynetbox, "api", FakeApi)

    # blank token + a FOREIGN url -> saved token must NOT be forwarded
    resp = client.post(
        "/test/netbox", data={"netbox_url": "https://attacker.evil:8000", "netbox_token": ""}
    )
    assert "SAVEDNBTOKEN" not in captured.get("token", "") if captured else True
    assert "different NetBox URL" in resp.text  # refused, no request made
    assert captured == {}  # FakeApi was never constructed

    # blank token + the SAVED url -> saved token IS used (same origin)
    resp = client.post(
        "/test/netbox", data={"netbox_url": "https://netbox.mine:8000", "netbox_token": ""}
    )
    assert captured["url"] == "https://netbox.mine:8000"
    assert captured["token"] == "SAVEDNBTOKEN"


def test_cleanup_page_requires_auth(client):
    assert client.get("/cleanup").status_code == 303  # redirect to login


def test_cleanup_page_loads_when_authed(client, store):
    login(client)
    # netbox not configured -> page still renders (no managed objects)
    resp = client.get("/cleanup")
    assert resp.status_code == 200
    assert "Cleanup" in resp.text


def test_cleanup_delete_requires_confirm(client, store):
    login(client)
    store.update_field(
        lambda c: (setattr(c.netbox, "url", "http://nb"), setattr(c.netbox, "token", "t"))
    )
    # without confirm=on, the delete is refused before touching anything
    resp = client.post("/cleanup/delete", data={"site_slug": "home"})
    assert resp.status_code == 200
    assert "confirmation not checked" in resp.text


def test_same_origin_helper():
    assert _same_origin("https://nb.test:8000", "https://nb.test:8000/api") is True
    assert _same_origin("https://nb.test", "https://nb.test:443") is False  # explicit vs implicit
    assert _same_origin("https://nb.test", "https://evil.test") is False
    assert _same_origin("", "https://nb.test") is False


def test_first_run_setup(tmp_path):
    store = SettingsStore.bootstrap(tmp_path / "fresh", None)
    client = TestClient(create_app(store, None, FakeStatus()), follow_redirects=False)
    # everything redirects to /setup until a password exists
    assert client.get("/").headers["location"] == "/setup"
    response = client.post("/setup", data={"password": "longpassword", "confirm": "longpassword"})
    assert response.status_code == 303
    assert store.get().webui.password_hash


def test_settings_updates_intervals(client, store):
    login(client)
    config = store.get()
    form = {
        "netbox_url": "https://netbox.test",
        "netbox_token": "newtoken",
        "netbox_verify_ssl": "on",
        "log_level": "INFO",
        "stale_after": "600",
        "delete_dhcp_on_expiry": "on",
        "stale_grace_delete_days": "",
    }
    for module in ("dhcp", "dns", "discovery", "availability", "proxmox", "lldp", "certs"):
        form[f"interval_{module}"] = "333"
        form[f"enabled_{module}"] = "on"
    response = client.post("/settings", data=form)
    assert response.status_code == 200
    config = store.get()
    assert config.netbox.token == "newtoken"
    assert config.dhcp.interval == 333
    assert config.proxmox_sync.interval == 333
    assert config.certs.interval == 333
    assert config.lldp.enabled is True


def test_settings_lldp_credential_profiles(client, store):
    login(client)
    base = {"log_level": "INFO", "stale_after": "600"}
    for module in ("dhcp", "dns", "discovery", "availability", "proxmox", "lldp", "certs"):
        base[f"interval_{module}"] = "300"
    # add two credential profiles + a blank row
    base["cred_name"] = ["homelab-ssh", "corp-snmp", ""]
    base["cred_driver"] = ["mikrotik", "snmp", "auto"]
    base["cred_username"] = ["admin", "", ""]
    base["cred_password"] = ["secret", "", ""]
    base["cred_community"] = ["", "public", ""]
    base["lldp_crawl_enabled"] = "on"
    base["lldp_max_switches"] = "50"
    base["lldp_max_depth"] = "5"
    assert client.post("/settings", data=base).status_code == 200
    lldp = store.get().lldp
    assert lldp.crawl_enabled is True
    assert lldp.max_switches == 50 and lldp.max_depth == 5
    assert [c.name for c in lldp.credentials] == ["homelab-ssh", "corp-snmp"]
    assert lldp.credentials[0].driver == "mikrotik"
    assert lldp.credentials[0].password == "secret"
    assert lldp.credentials[1].snmp_community == "public"

    # editing with a blank password keeps the stored one
    base["cred_name"] = ["homelab-ssh"]
    base["cred_driver"] = ["mikrotik"]
    base["cred_username"] = ["admin"]
    base["cred_password"] = [""]
    base["cred_community"] = [""]
    assert client.post("/settings", data=base).status_code == 200
    assert store.get().lldp.credentials[0].password == "secret"


def test_site_crud(client, store):
    login(client)
    response = client.post(
        "/sites/new",
        data={
            "name": "Beach House",
            "netbox_site": "__new__",
            "netbox_site_name": "Beach House",
            "tech_url": "http://192.168.50.2:5380",
            "tech_token": "abc",
            "include_extra": "192.168.50.0/24",
            "dhcp_enabled": "on",
            "dns_enabled": "on",
            "discovery_enabled": "on",
        },
    )
    assert response.status_code == 303
    sites = store.get().sites
    assert len(sites) == 1
    site = sites[0]
    assert site.id == "beach-house"
    assert site.netbox_site == "beach-house"
    assert site.technitium.url == "http://192.168.50.2:5380"
    assert site.discovery.include_prefixes == ["192.168.50.0/24"]
    assert site.proxmox == []

    # edit: blank token keeps the existing one
    response = client.post(
        "/sites/beach-house",
        data={
            "name": "Beach House",
            "netbox_site": "beach-house",
            "tech_url": "http://192.168.50.2:5380",
            "tech_token": "",
            "dhcp_enabled": "on",
        },
    )
    assert response.status_code == 303
    site = store.get().sites[0]
    assert site.technitium.token == "abc"
    assert site.dns_enabled is False  # unchecked boxes turn off

    response = client.post("/sites/beach-house/delete")
    assert response.status_code == 303
    assert store.get().sites == []


def test_site_lldp_settings(client, store):
    login(client)
    base = {
        "name": "Lab",
        "netbox_site": "__new__",
        "netbox_site_name": "Lab",
        "lldp_enabled": "on",
        "lldp_snmp_community": "labcommunity",
        "lldp_ssh_username": "admin",
        "lldp_ssh_password": "hunter33",
    }
    assert client.post("/sites/new", data=base).status_code == 303
    site = store.get().sites[0]
    assert site.lldp.enabled is True
    assert site.lldp.snmp_community == "labcommunity"
    assert site.lldp.ssh_username == "admin"
    assert site.lldp.ssh_password == "hunter33"

    # edit with blank secret fields: community/password kept, username is literal
    edit = {
        "name": "Lab",
        "netbox_site": "lab",
        "lldp_enabled": "on",
        "lldp_snmp_community": "",
        "lldp_ssh_username": "admin",
        "lldp_ssh_password": "",
    }
    assert client.post("/sites/lab", data=edit).status_code == 303
    site = store.get().sites[0]
    assert site.lldp.snmp_community == "labcommunity"
    assert site.lldp.ssh_password == "hunter33"

    # unchecking the box disables lldp for the site
    edit.pop("lldp_enabled")
    assert client.post("/sites/lab", data=edit).status_code == 303
    assert store.get().sites[0].lldp.enabled is False


# ------------------------------------------------------- footer + healthz


def test_healthz_is_unauthenticated_and_reports_shape(client):
    """Docker's healthcheck carries no cookie, so this must answer without auth."""
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__
    assert body["configured"] is False  # nothing set up in this fixture
    assert body["config_schema"] == CONFIG_SCHEMA_VERSION
    assert isinstance(body["uptime_s"], float)


def test_healthz_leaks_no_configuration(client, store):
    store.update_field(
        lambda c: (
            setattr(c.netbox, "url", "https://netbox.internal.example"),
            setattr(c.netbox, "token", "SEKRIT"),
        )
    )
    body = client.get("/healthz").text
    assert "netbox.internal.example" not in body
    assert "SEKRIT" not in body
    assert client.get("/healthz").json()["configured"] is True


def test_healthz_stays_ok_when_netbox_is_unreachable(client, store):
    """Health must not depend on NetBox: a NetBox outage restarting the container
    would only amplify the outage."""
    store.update_field(
        lambda c: (
            setattr(c.netbox, "url", "http://192.0.2.1:9999"),  # TEST-NET-1, unroutable
            setattr(c.netbox, "token", "t"),
        )
    )
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_footer_shows_version_and_github_link(client):
    login(client)
    body = client.get("/").text
    assert f"netbox-monitor v{__version__}" in body
    assert "https://github.com/sremich/netbox-monitor" in body


def test_footer_renders_on_unauthenticated_pages(client):
    """login/setup extend base.html — a version injected via the render() context
    instead of a Jinja global would silently vanish here."""
    assert f"v{__version__}" in client.get("/login").text


def test_footer_renders_on_setup(tmp_path):
    store = SettingsStore.bootstrap(tmp_path / "fresh", None)
    fresh = TestClient(create_app(store, None, FakeStatus()), follow_redirects=False)
    assert f"v{__version__}" in fresh.get("/setup").text


# ------------------------------------------------------- backup / restore


def _configured(store):
    store.update_field(
        lambda c: (
            setattr(c.netbox, "url", "https://netbox.test"),
            setattr(c.netbox, "token", "NBTOKEN"),
        )
    )


def test_backup_page_requires_auth(client):
    assert client.get("/backup").status_code == 303


def test_backup_page_loads(client):
    login(client)
    response = client.get("/backup")
    assert response.status_code == 200
    assert "Backup &amp; restore" in response.text or "Backup & restore" in response.text


def test_export_downloads_a_file_and_is_not_cacheable(client, store):
    login(client)
    _configured(store)
    response = client.post(
        "/backup/export",
        data={"mode": "encrypted", "passphrase": PP, "passphrase_confirm": PP},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert "attachment" in response.headers["content-disposition"]
    assert ".json" in response.headers["content-disposition"]
    # an encrypted export is every token the user owns
    assert response.headers["cache-control"] == "no-store"
    assert b"NBTOKEN" not in response.content  # encrypted, not merely wrapped


def test_export_redacted_strips_secrets(client, store):
    login(client)
    _configured(store)
    response = client.post("/backup/export", data={"mode": "redacted"})
    assert response.status_code == 200
    assert b"NBTOKEN" not in response.content
    assert b"__REDACTED__" in response.content


def test_export_rejects_mismatched_passphrases(client, store):
    login(client)
    response = client.post(
        "/backup/export",
        data={"mode": "encrypted", "passphrase": PP, "passphrase_confirm": "different"},
    )
    assert response.status_code == 200
    assert "do not match" in response.text


def test_export_rejects_short_passphrase(client, store):
    login(client)
    response = client.post(
        "/backup/export",
        data={"mode": "encrypted", "passphrase": "abc", "passphrase_confirm": "abc"},
    )
    assert "at least" in response.text


def _export_blob(client, store) -> bytes:
    _configured(store)
    return client.post(
        "/backup/export", data={"mode": "encrypted", "passphrase": PP, "passphrase_confirm": PP}
    ).content


def test_import_round_trip_applies_config_and_bumps_generation(client, store):
    login(client)
    blob = _export_blob(client, store)
    store.update_field(lambda c: setattr(c.netbox, "token", "REPLACED"))
    generation = store.generation

    response = client.post(
        "/backup/import",
        data={"confirm": "on", "passphrase": PP, "csrf": csrf_token(store)},
        files={"file": ("cfg.json", blob, "application/json")},
    )
    assert response.status_code == 200
    assert "Imported from" in response.text
    assert store.get().netbox.token == "NBTOKEN"
    # generation bumped -> the scheduler hot-reloads, no restart needed
    assert store.generation > generation
    assert (store.path.parent / "settings.json.bak").exists()


def test_import_requires_confirm(client, store):
    login(client)
    blob = _export_blob(client, store)
    response = client.post(
        "/backup/import",
        data={"passphrase": PP, "csrf": csrf_token(store)},
        files={"file": ("cfg.json", blob, "application/json")},
    )
    assert "confirmation not checked" in response.text


def test_import_requires_a_valid_csrf_token(client, store):
    login(client)
    blob = _export_blob(client, store)
    response = client.post(
        "/backup/import",
        data={"confirm": "on", "passphrase": PP, "csrf": "forged"},
        files={"file": ("cfg.json", blob, "application/json")},
    )
    assert "invalid CSRF token" in response.text


def test_import_requires_auth(client):
    assert client.post("/backup/import", data={"confirm": "on"}).status_code == 401


def test_import_reports_a_wrong_passphrase(client, store):
    login(client)
    blob = _export_blob(client, store)
    response = client.post(
        "/backup/import",
        data={"confirm": "on", "passphrase": "wrong-passphrase-x", "csrf": csrf_token(store)},
        files={"file": ("cfg.json", blob, "application/json")},
    )
    assert "wrong passphrase" in response.text


def test_import_rejects_a_foreign_file(client, store):
    login(client)
    response = client.post(
        "/backup/import",
        data={"confirm": "on", "csrf": csrf_token(store)},
        files={"file": ("nope.json", b'{"not": "ours"}', "application/json")},
    )
    assert "netbox-monitor config export" in response.text


def test_import_rejects_an_oversized_file(client, store):
    login(client)
    response = client.post(
        "/backup/import",
        data={"confirm": "on", "csrf": csrf_token(store)},
        files={"file": ("big.json", b"x" * (2 << 20), "application/json")},
    )
    assert "too large" in response.text


def test_import_never_changes_the_login(client, store):
    """A hostile export must not be able to hand over the admin session."""
    login(client)
    blob = _export_blob(client, store)
    before = store.get().webui

    client.post(
        "/backup/import",
        data={"confirm": "on", "passphrase": PP, "csrf": csrf_token(store)},
        files={"file": ("cfg.json", blob, "application/json")},
    )
    after = store.get().webui
    assert after.password_hash == before.password_hash
    assert after.session_secret == before.session_secret
