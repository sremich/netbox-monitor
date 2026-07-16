"""Web UI: auth flow, settings edit (intervals), site CRUD."""

import pytest
from fastapi.testclient import TestClient

from netbox_monitor.settings_store import SettingsStore
from netbox_monitor.webui.app import create_app
from netbox_monitor.webui.auth import hash_password


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
