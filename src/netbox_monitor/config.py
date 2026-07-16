"""Configuration loading: YAML file with ${ENV_VAR} interpolation, secrets from .env."""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

_ENV_RE = re.compile(r"\$\{(?P<name>[A-Za-z0-9_]+)(?::-(?P<default>[^}]*))?\}")


def _interpolate(value: object) -> object:
    if isinstance(value, str):

        def repl(m: re.Match) -> str:
            return os.environ.get(m.group("name"), m.group("default") or "")

        return _ENV_RE.sub(repl, value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


class NetBoxConfig(BaseModel):
    url: str
    token: str
    default_site: str = "Home"
    verify_ssl: bool = True


class TechnitiumConfig(BaseModel):
    url: str = "http://10.200.11.2:5380"
    token: str = ""


class ProxmoxInstance(BaseModel):
    host: str
    port: int = 8006
    user: str = "root@pam"
    token_name: str = ""
    token_value: str = ""
    verify_ssl: bool = False
    cluster_name: str | None = None  # NetBox cluster name; defaults to PVE cluster/host name


class ModuleConfig(BaseModel):
    enabled: bool = True
    interval: int = 300


class DnsSyncConfig(ModuleConfig):
    interval: int = 300
    zones_exclude: list[str] = Field(default_factory=list)


class DhcpSyncConfig(ModuleConfig):
    interval: int = 60


class DiscoveryConfig(ModuleConfig):
    interval: int = 900
    include_prefixes: list[str] = Field(default_factory=list)  # empty = all active prefixes
    exclude_prefixes: list[str] = Field(default_factory=list)
    ping_timeout: float = 1.0
    concurrency: int = 128
    max_hosts_per_prefix: int = 4096  # safety valve against scanning huge prefixes


class AvailabilityConfig(ModuleConfig):
    interval: int = 60
    stale_after: int = 600  # seconds unreachable before an object is tagged stale
    ping_timeout: float = 1.0
    concurrency: int = 128


class LldpFallbackCred(BaseModel):
    driver: str = "snmp"  # "snmp" or "unifi-ssh"
    community: str = "public"
    username: str = ""
    password: str = ""


class LldpConfig(ModuleConfig):
    enabled: bool = False  # requires switches tagged in NetBox; off until configured
    interval: int = 1800
    source_tag: str = "lldp-source"
    # platform slug -> driver name ("snmp" | "unifi-ssh"); unmatched platforms default to snmp
    platform_drivers: dict[str, str] = Field(default_factory=dict)
    secrets_private_key: str | None = None  # path to RSA private key for netbox-secrets plugin
    # platform slug -> credentials used when netbox-secrets has none for a device
    fallback_creds: dict[str, LldpFallbackCred] = Field(default_factory=dict)


class CertsConfig(ModuleConfig):
    interval: int = 86400
    ports: list[int] = Field(default_factory=lambda: [443, 8443])
    expiring_days: int = 30
    timeout: float = 5.0
    concurrency: int = 32


class ProxmoxSyncConfig(ModuleConfig):
    interval: int = 300


class LifecycleConfig(BaseModel):
    delete_dhcp_on_expiry: bool = True
    # if set, stale objects older than this many days are deleted; None = never delete
    stale_grace_delete_days: int | None = None


class AppConfig(BaseModel):
    netbox: NetBoxConfig
    technitium: TechnitiumConfig = Field(default_factory=TechnitiumConfig)
    proxmox: list[ProxmoxInstance] = Field(default_factory=list)
    dns: DnsSyncConfig = Field(default_factory=DnsSyncConfig)
    dhcp: DhcpSyncConfig = Field(default_factory=DhcpSyncConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    availability: AvailabilityConfig = Field(default_factory=AvailabilityConfig)
    lldp: LldpConfig = Field(default_factory=LldpConfig)
    certs: CertsConfig = Field(default_factory=CertsConfig)
    proxmox_sync: ProxmoxSyncConfig = Field(default_factory=ProxmoxSyncConfig)
    lifecycle: LifecycleConfig = Field(default_factory=LifecycleConfig)
    dry_run: bool = False
    data_dir: str = "data"
    log_level: str = "INFO"

    @property
    def state_db_path(self) -> Path:
        return Path(self.data_dir) / "state.db"


def load_config(path: str | Path) -> AppConfig:
    """Load YAML config with ${ENV_VAR} / ${ENV_VAR:-default} interpolation.

    Secrets are read from a ``.env`` sitting next to the config file (if any).
    """
    path = Path(path)
    load_dotenv(path.resolve().parent / ".env")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return AppConfig.model_validate(_interpolate(raw))
