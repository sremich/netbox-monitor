"""Test fixtures: an in-memory fake of the pynetbox API surface we use."""

from __future__ import annotations

import ipaddress
import itertools
from types import SimpleNamespace

import pytest

from netbox_monitor.clients.netbox import ALL_TAGS, NetBoxClient
from netbox_monitor.config import AppConfig, NetBoxConfig, SiteConfig
from netbox_monitor.context import ResolvedSite

_ids = itertools.count(1)


class FakeRecord:
    def __init__(self, endpoint: FakeEndpoint, **attrs):
        self._endpoint = endpoint
        self.id = next(_ids)
        self.custom_fields = dict(attrs.pop("custom_fields", {}) or {})
        self.tags = endpoint.api._resolve_tags(attrs.pop("tags", []) or [])
        for key, value in attrs.items():
            setattr(self, key, value)

    def update(self, data: dict) -> bool:
        data = dict(data)
        if "tags" in data:
            self.tags = self._endpoint.api._resolve_tags(data.pop("tags"))
        if "custom_fields" in data:
            self.custom_fields = {**self.custom_fields, **data.pop("custom_fields")}
        for key, value in data.items():
            setattr(self, key, value)
        return True

    def delete(self) -> bool:
        self._endpoint.items.remove(self)
        return True

    def __str__(self) -> str:
        for attr in ("name", "address", "prefix", "slug"):
            value = getattr(self, attr, None)
            if value:
                return str(value)
        return f"record-{self.id}"


class FakeEndpoint:
    def __init__(self, api: FakeApi, name: str):
        self.api = api
        self.name = name
        self.url = f"http://fake/api/{name}/"
        self.items: list[FakeRecord] = []

    def create(self, **attrs) -> FakeRecord:
        record = FakeRecord(self, **attrs)
        self.items.append(record)
        return record

    def all(self):
        return list(self.items)

    def _matches(self, record: FakeRecord, key: str, value) -> bool:
        if key == "tag":
            wanted = set(value if isinstance(value, list) else [value])
            return bool({t.slug for t in record.tags} & wanted)
        if key == "address":
            addr = str(getattr(record, "address", ""))
            return addr == value or addr.split("/")[0] == str(value).split("/")[0]
        if key == "contains":
            try:
                network = ipaddress.ip_network(getattr(record, "prefix", ""))
                return ipaddress.ip_address(value) in network
            except ValueError:
                return False
        if key == "device_id":
            device = getattr(record, "device", None) or getattr(
                getattr(record, "assigned_object", None), "device", None
            )
            return device == value or getattr(device, "id", None) == value
        if key == "site_id":
            site = getattr(record, "site", None)
            return site == value or getattr(site, "id", None) == value
        if key in ("cluster_id", "virtual_machine_id"):
            field = key.rsplit("_", 1)[0]
            obj = getattr(record, field, None) or getattr(
                getattr(record, "assigned_object", None), field, None
            )
            return obj == value or getattr(obj, "id", None) == value
        if key == "name__ie":
            return str(getattr(record, "name", "")).lower() == str(value).lower()
        if key == "has_primary_ip":
            return bool(getattr(record, "primary_ip4", None)) == bool(value)
        return getattr(record, key, None) == value

    def filter(self, **kw):
        return [r for r in self.items if all(self._matches(r, k, v) for k, v in kw.items())]

    def get(self, *args, **kw):
        if args:
            for record in self.items:
                if record.id == args[0]:
                    return record
            return None
        matches = self.filter(**kw)
        return matches[0] if matches else None


class FakeApi:
    version = "4.2"

    def __init__(self):
        def group(**endpoints):
            return SimpleNamespace(**endpoints)

        self.ipam = group(
            ip_addresses=FakeEndpoint(self, "ip-addresses"),
            prefixes=FakeEndpoint(self, "prefixes"),
        )
        self.dcim = group(
            devices=FakeEndpoint(self, "devices"),
            interfaces=FakeEndpoint(self, "interfaces"),
            device_types=FakeEndpoint(self, "device-types"),
            device_roles=FakeEndpoint(self, "device-roles"),
            manufacturers=FakeEndpoint(self, "manufacturers"),
            sites=FakeEndpoint(self, "sites"),
            mac_addresses=FakeEndpoint(self, "mac-addresses"),
            cables=FakeEndpoint(self, "cables"),
        )
        self.extras = group(
            tags=FakeEndpoint(self, "tags"),
            custom_fields=FakeEndpoint(self, "custom-fields"),
            journal_entries=FakeEndpoint(self, "journal-entries"),
        )
        self.virtualization = group(
            clusters=FakeEndpoint(self, "clusters"),
            cluster_types=FakeEndpoint(self, "cluster-types"),
            virtual_machines=FakeEndpoint(self, "virtual-machines"),
            interfaces=FakeEndpoint(self, "vm-interfaces"),
        )

    def _resolve_tags(self, tags: list) -> list:
        resolved = []
        for tag in tags:
            if isinstance(tag, int):
                found = self.extras.tags.get(tag)
                if found:
                    resolved.append(found)
            else:
                resolved.append(tag)
        return resolved


@pytest.fixture
def nb() -> NetBoxClient:
    client = NetBoxClient(NetBoxConfig(url="http://netbox.test", token="token"), dry_run=False)
    client.api = FakeApi()
    for slug, (name, color, _desc) in ALL_TAGS.items():
        tag = client.api.extras.tags.create(name=name, slug=slug, color=color)
        client.register_tag(slug, tag.id)
    site = client.api.dcim.sites.create(name="Home", slug="home")
    role = client.api.dcim.device_roles.create(name="Discovered", slug="discovered")
    hyper = client.api.dcim.device_roles.create(name="Hypervisor", slug="hypervisor")
    client.refs = {"role_discovered": role.id, "role_hypervisor": hyper.id}
    client.home_site_id = site.id  # convenience for tests
    return client


@pytest.fixture
def app_config() -> AppConfig:
    return AppConfig(
        netbox=NetBoxConfig(url="http://netbox.test", token="token"),
        sites=[SiteConfig(id="home", name="Home", netbox_site="home")],
    )


class FakeOui:
    def lookup(self, mac):
        return "Ubiquiti Inc" if mac and mac.upper().startswith("24:A4:3C") else None

    async def ensure_loaded(self):
        return None


class FakeStatus:
    def __init__(self):
        self.records = []

    async def record(self, module, scope, ok, message="", duration=None):
        self.records.append((module, scope, ok, message))

    async def snapshot(self):
        return {}


@pytest.fixture
def ctx(nb, app_config):
    sites = [ResolvedSite(config=app_config.sites[0], netbox_site_id=nb.home_site_id)]
    return SimpleNamespace(
        config=app_config,
        netbox=nb,
        state=None,
        oui=FakeOui(),
        status=FakeStatus(),
        sites=sites,
    )
