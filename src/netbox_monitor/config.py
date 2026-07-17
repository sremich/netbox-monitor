"""Configuration models.

v2 layout: a global section plus a list of *sites*, each pairing a NetBox Site
with its own Technitium instance, Proxmox instances, and discovery scope.

Legacy (v1) flat YAML configs — top-level ``technitium`` / ``proxmox`` /
``discovery`` and ``netbox.default_site`` — are migrated into a single site by
``migrate_legacy``. YAML values support ``${ENV_VAR}`` / ``${ENV_VAR:-default}``
interpolation; the runtime settings.json (see settings_store.py) is literal.

**Schema versioning.** Every serialized config carries ``schema_version``.
``config_from_raw`` is the only sanctioned path from a serialized dict to an
``AppConfig``: it detects the schema, runs the ``MIGRATIONS`` chain up to
``CONFIG_SCHEMA_VERSION``, then validates. Changing the serialized shape means
bumping ``CONFIG_SCHEMA_VERSION`` and adding a migration keyed by the version it
migrates *from* — see CLAUDE.md, which makes the compatibility promise explicit.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

_ENV_RE = re.compile(r"\$\{(?P<name>[A-Za-z0-9_]+)(?::-(?P<default>[^}]*))?\}")

#: Serialized-config schema. 1 = the v1 flat layout; 2 = the current sites layout.
CONFIG_SCHEMA_VERSION = 2


class ConfigSchemaTooNewError(RuntimeError):
    """A config was written by a newer build than this one."""

    def __init__(self, found: int, supported: int):
        super().__init__(
            f"config schema {found} is newer than this build supports ({supported}) — "
            "upgrade netbox-monitor, or restore the settings.json.bak from before the upgrade"
        )
        self.found = found
        self.supported = supported


class ConfigMigrationError(RuntimeError):
    """A config could not be migrated up to the current schema."""


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
    url: str = ""
    token: str = ""
    default_site: str = "Home"  # legacy (v1); used only during migration
    verify_ssl: bool = True

    @property
    def configured(self) -> bool:
        return bool(self.url and self.token)


class TechnitiumConfig(BaseModel):
    url: str = "http://10.200.11.2:5380"
    token: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.url and self.token)


class ProxmoxInstance(BaseModel):
    host: str
    port: int = 8006
    user: str = "root@pam"
    token_name: str = ""
    token_value: str = ""
    verify_ssl: bool = False
    cluster_name: str | None = None  # NetBox cluster name; defaults to PVE cluster/host name


class SiteDiscoveryConfig(BaseModel):
    enabled: bool = True
    include_prefixes: list[str] = Field(default_factory=list)  # empty = site's NetBox prefixes
    exclude_prefixes: list[str] = Field(default_factory=list)


class SiteLldpConfig(BaseModel):
    """Per-site LLDP credentials for the site's switches (tagged ``lldp-source``).

    The netbox-secrets plugin (global lldp settings) still wins when it holds
    credentials for a specific switch.
    """

    enabled: bool = False
    snmp_community: str = ""  # for SNMP-polled switches
    ssh_username: str = ""  # for UniFi (SSH + lldpd) switches
    ssh_password: str = ""


class SiteConfig(BaseModel):
    id: str  # internal slug, unique
    name: str  # display name
    netbox_site: str = ""  # NetBox site slug
    netbox_site_name: str = ""  # display name (used to create the site if missing)
    technitium: TechnitiumConfig | None = None
    proxmox: list[ProxmoxInstance] = Field(default_factory=list)
    discovery: SiteDiscoveryConfig = Field(default_factory=SiteDiscoveryConfig)
    lldp: SiteLldpConfig = Field(default_factory=SiteLldpConfig)
    dhcp_enabled: bool = True
    dns_enabled: bool = True
    proxmox_enabled: bool = True


class ModuleConfig(BaseModel):
    enabled: bool = True
    interval: int = Field(default=300, ge=15)


class DnsSyncConfig(ModuleConfig):
    interval: int = Field(default=300, ge=15)
    zones_exclude: list[str] = Field(default_factory=list)


class DhcpSyncConfig(ModuleConfig):
    interval: int = Field(default=60, ge=15)


class DiscoveryConfig(ModuleConfig):
    """Global discovery tuning; per-site scope lives in SiteDiscoveryConfig."""

    interval: int = Field(default=900, ge=15)
    ping_timeout: float = 1.0
    concurrency: int = 128
    max_hosts_per_prefix: int = 4096  # safety valve against scanning huge prefixes


class AvailabilityConfig(ModuleConfig):
    interval: int = Field(default=60, ge=15)
    stale_after: int = 600  # seconds unreachable before an object is tagged stale
    ping_timeout: float = 1.0
    concurrency: int = 128


class LldpFallbackCred(BaseModel):
    driver: str = "snmp"  # "snmp" or "unifi-ssh"
    community: str = "public"
    username: str = ""
    password: str = ""


class LldpCredential(BaseModel):
    """A credential profile the crawl tries against discovered switches, in order."""

    name: str
    driver: str = "auto"  # auto | cisco | arista | aruba | mikrotik | unifi | snmp
    username: str = ""
    password: str = ""
    snmp_community: str = ""


class LldpConfig(ModuleConfig):
    enabled: bool = False  # requires switches tagged in NetBox; off until configured
    interval: int = Field(default=1800, ge=15)
    source_tag: str = "lldp-source"
    # platform slug -> driver name; unmatched platforms are auto-detected
    platform_drivers: dict[str, str] = Field(default_factory=dict)
    secrets_private_key: str | None = None  # path to RSA private key for netbox-secrets plugin
    # platform slug -> credentials used when netbox-secrets has none for a device
    fallback_creds: dict[str, LldpFallbackCred] = Field(default_factory=dict)
    # crawl: propagate from seed switches to their switch-neighbors
    crawl_enabled: bool = True
    max_switches: int = 100  # crawl safety cap
    max_depth: int = 8
    max_auth_attempts: int = 4  # cap credential tries per host (anti-lockout)
    # global credential profiles tried (after site creds) against discovered switches
    credentials: list[LldpCredential] = Field(default_factory=list)
    # hosts the crawl must NEVER open a session to (SSH/SNMP). They are still
    # documented as devices and cabled from neighbor data — but never authenticated.
    # Use for production routers/firewalls where any connection is unwanted.
    exclude_hosts: list[str] = Field(default_factory=list)


class CertsConfig(ModuleConfig):
    interval: int = Field(default=86400, ge=15)
    ports: list[int] = Field(default_factory=lambda: [443, 8443])
    expiring_days: int = 30
    timeout: float = 5.0
    concurrency: int = 32


class ProxmoxSyncConfig(ModuleConfig):
    interval: int = Field(default=300, ge=15)


class LifecycleConfig(BaseModel):
    delete_dhcp_on_expiry: bool = True
    # if set, stale objects older than this many days are deleted; None = never delete
    stale_grace_delete_days: int | None = None


class WebUIConfig(BaseModel):
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8899
    password_hash: str = ""  # empty -> first-run setup page (or WEBUI_PASSWORD env)
    session_secret: str = ""  # auto-generated on first save


class AppConfig(BaseModel):
    schema_version: int = CONFIG_SCHEMA_VERSION
    netbox: NetBoxConfig = Field(default_factory=NetBoxConfig)
    sites: list[SiteConfig] = Field(default_factory=list)
    dns: DnsSyncConfig = Field(default_factory=DnsSyncConfig)
    dhcp: DhcpSyncConfig = Field(default_factory=DhcpSyncConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    availability: AvailabilityConfig = Field(default_factory=AvailabilityConfig)
    lldp: LldpConfig = Field(default_factory=LldpConfig)
    certs: CertsConfig = Field(default_factory=CertsConfig)
    proxmox_sync: ProxmoxSyncConfig = Field(default_factory=ProxmoxSyncConfig)
    lifecycle: LifecycleConfig = Field(default_factory=LifecycleConfig)
    webui: WebUIConfig = Field(default_factory=WebUIConfig)
    dry_run: bool = False
    data_dir: str = "data"
    log_level: str = "INFO"

    @property
    def state_db_path(self) -> Path:
        return Path(self.data_dir) / "state.db"


def _slugify(value: str) -> str:
    value = re.sub(r"[^a-z0-9_-]+", "-", value.lower().strip())
    return re.sub(r"-{2,}", "-", value).strip("-") or "site"


def migrate_legacy(raw: dict) -> dict:
    """Convert a v1 flat config dict into the v2 sites layout (idempotent)."""
    if "sites" in raw:
        return raw
    legacy_keys = ("technitium", "proxmox")
    if not any(k in raw for k in legacy_keys):
        # nothing site-specific configured; still produce an empty sites list
        raw.setdefault("sites", [])
        return raw

    site_name = (raw.get("netbox") or {}).get("default_site", "Home")
    discovery = raw.get("discovery") or {}
    site: dict = {
        "id": _slugify(site_name),
        "name": site_name,
        "netbox_site": _slugify(site_name),
        "netbox_site_name": site_name,
        "discovery": {
            "enabled": discovery.get("enabled", True),
            "include_prefixes": discovery.get("include_prefixes", []),
            "exclude_prefixes": discovery.get("exclude_prefixes", []),
        },
    }
    if raw.get("technitium"):
        site["technitium"] = raw.pop("technitium")
    if raw.get("proxmox"):
        site["proxmox"] = raw.pop("proxmox")
    # scope keys move to the site; global tuning keys stay in discovery
    for key in ("include_prefixes", "exclude_prefixes"):
        (raw.get("discovery") or {}).pop(key, None)
    raw["sites"] = [site]
    return raw


#: Migrations keyed by the schema version they migrate *from*. Append-only:
#: removing a step breaks every config still written at that version.
MIGRATIONS: dict[int, Callable[[dict], dict]] = {1: migrate_legacy}


def _detect_schema(raw: dict) -> int:
    """Schema of a *serialized* config dict.

    Runs before validation, so a config predating ``schema_version`` is sniffed
    structurally rather than defaulting to the current version (which would skip
    its migration and silently drop data).
    """
    version = raw.get("schema_version")
    if version is not None:
        try:
            return int(version)
        except (TypeError, ValueError):
            raise ConfigMigrationError(f"invalid schema_version: {version!r}") from None
    return 2 if "sites" in raw else 1


def migrate_to_current(raw: dict) -> dict:
    """Apply every migration from the detected schema up to the current one."""
    version = _detect_schema(raw)
    if version > CONFIG_SCHEMA_VERSION:
        raise ConfigSchemaTooNewError(version, CONFIG_SCHEMA_VERSION)
    if version < 1:
        raise ConfigMigrationError(f"invalid schema version {version}")
    while version < CONFIG_SCHEMA_VERSION:
        step = MIGRATIONS.get(version)
        if step is None:
            raise ConfigMigrationError(f"no migration from config schema {version}")
        raw = step(raw)
        version += 1
    raw["schema_version"] = CONFIG_SCHEMA_VERSION
    return raw


def config_from_raw(raw: dict) -> AppConfig:
    """Migrate a serialized config up to the current schema, then validate.

    The only sanctioned path from serialized input to ``AppConfig`` — validating
    a raw dict directly skips migration.
    """
    return AppConfig.model_validate(migrate_to_current(raw))


def load_config(path: str | Path) -> AppConfig:
    """Load YAML config with ${ENV_VAR} interpolation and schema migration.

    Secrets are read from a ``.env`` sitting next to the config file (if any).
    """
    path = Path(path)
    load_dotenv(path.resolve().parent / ".env")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return config_from_raw(_interpolate(raw))
