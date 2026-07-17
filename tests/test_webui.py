"""Web UI: auth flow, settings edit (intervals), site CRUD, security guards."""

import pytest
from fastapi.testclient import TestClient

from netbox_monitor.settings_store import SettingsStore
from netbox_monitor.webui.app import _same_origin, create_app
from netbox_monitor.webui.auth import hash_password, verify_password


class FakeStatus:
    async def snapshot(self):
        return {}


@pytest.fixture
def store(tmp_path):
    store = SettingsStore.bootstrap(tmp_path, None)
    store.update_field(lambda c: setattr(c.webui, "password_hash", hash_password("hunter22")))
    return store


@pytest.fixture
def client(store):
    app = create_app(store, engine=None, status=FakeStatus())
    return TestClient(app, follow_redirects=False)


def login(client):
    response = client.post("/login", data={"password": "hunter22"})
    assert response.status_code == 303
    client.cookies.update(response.cookies)


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
