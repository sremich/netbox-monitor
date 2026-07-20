"""LLDP topology sync with seed-and-crawl propagation.

Per site, start from ``lldp-source``-tagged switches, poll their LLDP neighbors,
document the links as NetBox cables, and — for neighbors that are themselves
switches — auto-create them, authenticate with the site/global credential
profiles, and crawl onward until the fabric is mapped (bounded by max_switches
/max_depth).

Credential resolution per switch: netbox-secrets plugin → site LLDP credentials
→ global credential profiles. The working (driver, profile) is cached so later
runs skip the trial loop.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import structlog

from netbox_monitor.clients.netbox import MANAGED_TAG_SLUG, NetBoxClient, slugify
from netbox_monitor.clients.secrets import DeviceSecrets, SecretsClient
from netbox_monitor.config import LldpCredential
from netbox_monitor.context import Context, ResolvedSite
from netbox_monitor.lldp import LldpNeighbor, registry
from netbox_monitor.oui import normalize_mac
from netbox_monitor.sync.common import (
    ensure_discovered_device_type,
    find_interface_by_mac,
    find_ip,
    now_iso,
    set_interface_mac,
)

log = structlog.get_logger(__name__)

SRC = "src-lldp"

_CONN_ERR_SIGNS = (
    "reset",
    "refused",
    "timed out",
    "timeout",
    "unreachable",
    "connection lost",
    "not a valid",
    "closed",
    "no route",
)


def _is_connection_error(exc: Exception) -> bool:
    """True when an SSH failure is transport-level (reset/refused/timeout) rather
    than an authentication rejection — i.e. retrying other SSH creds won't help."""
    import asyncssh

    if isinstance(exc, asyncssh.PermissionDenied):
        return False  # auth failure: a different credential might still work
    if isinstance(exc, (ConnectionError, TimeoutError, OSError)):
        return True
    text = str(exc).lower()
    return any(sign in text for sign in _CONN_ERR_SIGNS)


@dataclass
class CrawlTarget:
    host: str
    device: Any | None  # NetBox device, if known
    hint_driver: str | None
    depth: int
    sys_descr: str | None = None
    chassis_mac: str | None = None
    last_error: str | None = None  # why every driver/credential failed, for the status line


# never treat these as a chassis identity: RouterOS loopbacks report all-zeros,
# and matching on a placeholder merges two different switches into one
_NON_IDENTITY_MACS = {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}


def _is_identity_mac(mac: str | None) -> bool:
    return bool(mac) and mac not in _NON_IDENTITY_MACS


@dataclass
class SiteStats:
    polled: int = 0
    created: int = 0
    failed: int = 0
    failures: list[str] = field(default_factory=list)


class LldpSync:
    name = "lldp"

    def __init__(self, ctx: Context):
        self.ctx = ctx
        # the netbox-secrets HTTP client is created per-run and closed at the end,
        # so it never outlives a run (no leak across settings reloads)
        self._secrets: SecretsClient | None = None

    def _enabled_sites(self) -> list[ResolvedSite]:
        enabled = [s for s in self.ctx.sites if s.config.lldp.enabled]
        if enabled:
            return enabled
        return list(self.ctx.sites) if self.ctx.config.lldp.enabled else []

    async def run(self) -> None:
        sites = self._enabled_sites()
        if not sites:
            log.info("no sites with LLDP enabled")
            return
        await self._warn_stranded_seeds(sites)
        if self.ctx.config.lldp.secrets_private_key:
            self._secrets = SecretsClient(
                self.ctx.config.netbox.url,
                self.ctx.config.netbox.token,
                self.ctx.config.lldp.secrets_private_key,
                verify_ssl=self.ctx.config.netbox.verify_ssl,
            )
        try:
            for site in sites:
                started = time.monotonic()
                try:
                    stats = await self._crawl_site(site)
                    ok = stats.failed == 0
                    message = f"{stats.polled} polled, {stats.created} switches created" + (
                        f", {stats.failed} unreachable" if stats.failed else ""
                    )
                    if stats.failures:
                        message += " — " + "; ".join(stats.failures[:3])
                    await self.ctx.status.record(
                        self.name, site.config.id, ok, message, time.monotonic() - started
                    )
                except Exception as exc:
                    log.exception("lldp sync failed for site", site=site.config.id)
                    await self.ctx.status.record(
                        self.name, site.config.id, False, str(exc), time.monotonic() - started
                    )
        finally:
            if self._secrets is not None:
                await self._secrets.close()
                self._secrets = None

    async def _warn_stranded_seeds(self, sites: list[ResolvedSite]) -> None:
        """Flag ``lldp-source`` switches sitting at a NetBox site that no LLDP-enabled
        site maps to. Seeds are looked up per site, so these are silently never polled
        — most often a device left behind on an old site after a site migration."""
        nb = self.ctx.netbox
        tag_slug = slugify(self.ctx.config.lldp.source_tag)
        try:
            seeds = await asyncio.to_thread(nb.filter_tagged, nb.api.dcim.devices, tag_slug)
        except Exception as exc:  # diagnostics only — never fail the run over this
            log.debug("could not check for stranded LLDP seeds", error=str(exc))
            return
        covered = {s.netbox_site_id for s in sites}
        for dev in seeds:
            site = getattr(dev, "site", None)
            if getattr(site, "id", site) not in covered:
                log.warning(
                    "lldp seed switch is at a site with no LLDP-enabled config; "
                    "it will never be polled",
                    switch=getattr(dev, "name", "?"),
                    site=str(getattr(dev, "site", None)),
                )

    # ------------------------------------------------------------------ crawl

    def _credential_profiles(self, site: ResolvedSite) -> list[LldpCredential]:
        """Site LLDP credentials first (as an implicit profile), then globals."""
        profiles: list[LldpCredential] = []
        s = site.config.lldp
        if s.ssh_username or s.snmp_community:
            profiles.append(
                LldpCredential(
                    name=f"{site.config.id}-site",
                    driver="auto",
                    username=s.ssh_username,
                    password=s.ssh_password,
                    snmp_community=s.snmp_community,
                )
            )
        profiles.extend(self.ctx.config.lldp.credentials)
        return profiles

    async def _crawl_site(self, site: ResolvedSite) -> SiteStats:
        cfg = self.ctx.config.lldp
        nb = self.ctx.netbox
        tag_slug = slugify(cfg.source_tag)
        profiles = self._credential_profiles(site)
        exclude = {h.strip() for h in cfg.exclude_hosts if h.strip()}
        stats = SiteStats()

        seeds = await asyncio.to_thread(
            nb.filter_tagged, nb.api.dcim.devices, tag_slug, site_id=site.netbox_site_id
        )
        if not seeds:
            log.info("no seed switches tagged for LLDP at site", site=site.config.id)
            return stats

        queue: deque[CrawlTarget] = deque()
        visited_ip: set[str] = set()
        visited_mac: set[str] = set()
        for seed in seeds:
            primary = getattr(seed, "primary_ip4", None) or getattr(seed, "primary_ip", None)
            if not primary:
                log.warning("seed switch has no primary IP; skipping", switch=seed.name)
                continue
            host = str(primary.address).split("/")[0]
            platform = getattr(getattr(seed, "platform", None), "slug", "") or ""
            queue.append(
                CrawlTarget(
                    host=host, device=seed, hint_driver=registry.select_driver(platform), depth=0
                )
            )

        while queue and stats.polled < cfg.max_switches:
            target = queue.popleft()
            if target.host in visited_ip:
                continue
            visited_ip.add(target.host)
            if target.chassis_mac:
                visited_mac.add(target.chassis_mac)

            if target.host in exclude:
                # document-only host (e.g. production router): never authenticate it.
                # It is already created + cabled by the neighbor that reported it.
                log.info(
                    "lldp: host excluded from authentication (document-only)", host=target.host
                )
                continue

            poll = await self._poll_target(target, site, profiles)
            if poll is None:
                stats.failed += 1
                stats.failures.append(
                    f"{target.host}: {target.last_error or 'unreachable/no working credential'}"
                )
                continue
            neighbors, cred, driver = poll
            stats.polled += 1

            device = target.device
            if device is None:
                device = await asyncio.to_thread(
                    self._ensure_switch_device,
                    site,
                    target.host,
                    target.sys_descr,
                    target.chassis_mac,
                    None,
                )
                if getattr(device, "_created", False):
                    stats.created += 1
            if device is None:
                continue

            # learn the switch's OWN MACs (its chassis identity) so a box reachable
            # at several management IPs collapses into one device instead of many
            local_macs: dict[str, str | None] = {}
            if cred is not None:
                local_macs = await registry.collect_local_macs(
                    driver,
                    target.host,
                    username=cred.username,
                    password=cred.password,
                    snmp_community=cred.snmp_community,
                )
            device, identity_macs = await asyncio.to_thread(
                self._dedup_and_record_macs, device, target.chassis_mac, local_macs
            )
            visited_mac |= identity_macs

            await asyncio.to_thread(self._reconcile, site, device, neighbors)

            if not cfg.crawl_enabled or target.depth >= cfg.max_depth:
                continue
            for neighbor in neighbors:
                if not neighbor.is_crawlable_switch():
                    continue
                if neighbor.mgmt_ip in visited_ip or (
                    neighbor.chassis_mac and neighbor.chassis_mac in visited_mac
                ):
                    continue
                ndev = await asyncio.to_thread(
                    self._ensure_switch_device,
                    site,
                    neighbor.mgmt_ip,
                    neighbor.sys_descr,
                    neighbor.chassis_mac,
                    neighbor.sysname,
                )
                if getattr(ndev, "_created", False):
                    stats.created += 1
                queue.append(
                    CrawlTarget(
                        host=neighbor.mgmt_ip,
                        device=ndev,
                        hint_driver=registry.select_driver(None, neighbor.sys_descr),
                        depth=target.depth + 1,
                        sys_descr=neighbor.sys_descr,
                        chassis_mac=neighbor.chassis_mac,
                    )
                )
        return stats

    async def _poll_target(
        self, target: CrawlTarget, site: ResolvedSite, profiles: list[LldpCredential]
    ) -> tuple[list[LldpNeighbor], LldpCredential | None, str] | None:
        """Try credentials/drivers until neighbors come back. Returns
        (neighbors, cred, driver) or None if nothing worked."""
        attempts = await self._build_attempts(target, site, profiles)
        # hard safety cap: never make more than this many auth attempts against one
        # host (protects production gear from credential-spray lockouts)
        max_attempts = self.ctx.config.lldp.max_auth_attempts
        ssh_unreachable = False  # a pre-auth reset means every SSH driver will fail alike
        tried: list[str] = []  # "driver/ErrorType" per failed attempt, for diagnostics
        details: list[str] = []
        capped = False
        for attempt_num, (driver, cred) in enumerate(attempts):
            if attempt_num >= max_attempts:
                capped = True
                log.info(
                    "lldp: auth attempt cap reached; giving up on host",
                    host=target.host,
                    cap=max_attempts,
                )
                break
            if ssh_unreachable and driver in registry.SSH_DRIVERS:
                continue
            try:
                neighbors = await registry.collect(
                    driver,
                    target.host,
                    username=cred.username if cred else "",
                    password=cred.password if cred else "",
                    snmp_community=cred.snmp_community if cred else "",
                )
                await self._cache_working(target.host, driver, cred)
                log.info(
                    "lldp polled",
                    host=target.host,
                    driver=driver,
                    cred=cred.name if cred else "netbox-secrets",
                    neighbors=len(neighbors),
                )
                return neighbors, cred, driver
            except Exception as exc:
                tried.append(f"{driver}/{type(exc).__name__}")
                # some exceptions (e.g. TimeoutError) stringify to "" — fall back to the type
                detail = str(exc) or type(exc).__name__
                details.append(
                    f"{driver} ({cred.name if cred else 'netbox-secrets'}): {detail}"[:200]
                )
                log.debug("lldp attempt failed", host=target.host, driver=driver, error=str(exc))
                if driver in registry.SSH_DRIVERS and _is_connection_error(exc):
                    # host rejects SSH at the transport level (reset/refused/timeout);
                    # other SSH drivers/creds will hit the same wall — stop trying them
                    ssh_unreachable = True

        # Nothing worked. Report *why* at info level: at the default log level a
        # silently-skipped switch is indistinguishable from one that was never tried.
        if not attempts:
            target.last_error = "no driver/credential available to try"
        elif tried:
            target.last_error = ", ".join(tried) + (" (attempt cap reached)" if capped else "")
        else:
            target.last_error = (
                "no credential tried (attempt cap reached)" if capped else "unreachable"
            )
        log.info(
            "lldp: no working driver/credential for host",
            host=target.host,
            tried=target.last_error,
            errors=details,
        )
        return None

    async def _build_attempts(
        self, target: CrawlTarget, site: ResolvedSite, profiles: list[LldpCredential]
    ) -> list[tuple[str, LldpCredential | None]]:
        attempts: list[tuple[str, LldpCredential | None]] = []
        seen: set[tuple[str, str, str, str]] = set()

        def add(driver: str, cred: LldpCredential | None):
            # dedupe by (driver, actual secret values) so identical creds under
            # different profile names don't multiply connection attempts
            key = (
                driver,
                cred.username if cred else "",
                cred.password if cred else "",
                cred.snmp_community if cred else "",
            )
            if driver in registry.ALL_DRIVERS and key not in seen:
                seen.add(key)
                attempts.append((driver, cred))

        # 1. cached working combo for this host
        cached = await self._cached_working(target.host)
        # 2. netbox-secrets (device-attached), if we have a device + secrets client
        secret_cred = await self._secrets_cred(target.device)

        def drivers_for(cred: LldpCredential | None) -> list[str]:
            if cred and cred.driver != "auto":
                return [cred.driver]
            # when the switch's vendor is known (platform hint or LLDP sysDescr),
            # try ONLY that SSH driver — never spray every vendor's login at one host
            hint = target.hint_driver
            ssh_order = [hint] if hint else list(registry.AUTO_ORDER)
            out = []
            for d in ssh_order:
                if d in registry.SSH_DRIVERS and cred and cred.username:
                    out.append(d)
            # SNMP is a separate transport; offer it whenever a community is present
            if cred and cred.snmp_community:
                out.append("snmp")
            return out

        if cached:
            cached_driver, cached_name = cached
            cred = next((p for p in profiles if p.name == cached_name), secret_cred)
            add(cached_driver, cred)
        if secret_cred:
            for d in drivers_for(secret_cred):
                add(d, secret_cred)
        for profile in profiles:
            for d in drivers_for(profile):
                add(d, profile)
        return attempts

    async def _secrets_cred(self, device: Any | None) -> LldpCredential | None:
        if not self._secrets or device is None:
            return None
        try:
            secrets: DeviceSecrets = await self._secrets.get_device_secrets(device.id)
        except Exception as exc:
            log.debug("secrets lookup failed", device=getattr(device, "name", "?"), error=str(exc))
            return None
        if secrets.ssh_username or secrets.snmp_community:
            return LldpCredential(
                name="netbox-secrets",
                driver="auto",
                username=secrets.ssh_username or "",
                password=secrets.ssh_password or "",
                snmp_community=secrets.snmp_community or "",
            )
        return None

    async def _cached_working(self, host: str) -> tuple[str, str] | None:
        if self.ctx.state is None:
            return None
        try:
            raw = await self.ctx.state.get_kv(f"lldpcred:{host}")
        except Exception:
            return None
        if raw:
            data = json.loads(raw)
            return data["driver"], data.get("cred", "")
        return None

    async def _cache_working(self, host: str, driver: str, cred: LldpCredential | None) -> None:
        if self.ctx.state is None:
            return
        try:
            await self.ctx.state.set_kv(
                f"lldpcred:{host}",
                json.dumps({"driver": driver, "cred": cred.name if cred else ""}),
            )
        except Exception:
            pass

    # ------------------------------------------------------- device creation

    def _vendor_name(self, sys_descr: str | None, chassis_mac: str | None) -> str:
        driver = registry.select_driver(None, sys_descr)
        names = {
            "cisco": "Cisco",
            "arista": "Arista",
            "aruba": "Aruba",
            "mikrotik": "MikroTik",
            "unifi": "Ubiquiti",
        }
        if driver in names:
            return names[driver]
        vendor = self.ctx.oui.lookup(chassis_mac) if chassis_mac else None
        return vendor or "Unknown"

    @staticmethod
    def _device_by_ip(nb: NetBoxClient, ip: str) -> Any | None:
        """The device owning ``ip`` via its assigned interface, if any."""
        ip_obj = find_ip(nb, ip)
        if ip_obj is None:
            return None
        if str(getattr(ip_obj, "assigned_object_type", "") or "") != "dcim.interface":
            return None  # unassigned, or a VM's — a switch match must be a device
        iface_id = getattr(ip_obj, "assigned_object_id", None)
        if not iface_id:
            return None
        with nb.lock:
            iface = nb.api.dcim.interfaces.get(iface_id)
        parent = getattr(iface, "device", None) if iface else None
        if parent is None:
            return None
        with nb.lock:
            return nb.api.dcim.devices.get(getattr(parent, "id", parent))

    def _ensure_switch_device(
        self,
        site: ResolvedSite,
        mgmt_ip: str | None,
        sys_descr: str | None,
        chassis_mac: str | None,
        sysname: str | None,
    ) -> Any | None:
        nb = self.ctx.netbox
        # match existing: by chassis MAC, then sysname, then mgmt IP
        device = None
        if chassis_mac:
            # find_interface_by_mac reads dcim.mac_addresses — under NetBox >= 4.2
            # interfaces no longer answer a mac_address filter directly
            match = find_interface_by_mac(nb, chassis_mac)
            if match and match[0] == "dcim.interface" and match[2] is not None:
                with nb.lock:
                    device = nb.api.dcim.devices.get(getattr(match[2], "id", match[2]))
        if device is None and sysname:
            short = sysname.split(".")[0]
            with nb.lock:
                matches = list(nb.api.dcim.devices.filter(name__ie=short))
            device = matches[0] if matches else None
        if device is None and mgmt_ip:
            device = self._device_by_ip(nb, mgmt_ip)
        if device is not None:
            return device

        if site.netbox_site_id is None:
            log.warning("cannot create switch without a NetBox site", site=site.config.id)
            return None
        vendor = self._vendor_name(sys_descr, chassis_mac)
        _mfr, device_type = ensure_discovered_device_type(nb, f"{vendor} Switch")
        name = (sysname.split(".")[0] if sysname else None) or (
            f"switch-{mgmt_ip.replace('.', '-')}" if mgmt_ip else f"switch-{chassis_mac}"
        )
        device = nb.create(
            nb.api.dcim.devices,
            name=name,
            role=nb.refs.get("role_switch") or nb.refs.get("role_discovered"),
            device_type=device_type.id if device_type else None,
            site=site.netbox_site_id,
            status="active",
            description="Auto-created from LLDP crawl",
            tags=nb.tag_ids(MANAGED_TAG_SLUG, SRC),
            custom_fields={"last_seen": now_iso(), "oui_vendor": vendor},
        )
        if device is None:
            return None
        device._created = True
        # a management interface carrying the chassis MAC + primary IP
        with nb.lock:
            mgmt_if = nb.api.dcim.interfaces.get(device_id=device.id, name="mgmt")
        if mgmt_if is None:
            mgmt_if = nb.create(
                nb.api.dcim.interfaces,
                device=device.id,
                name="mgmt",
                type="other",
                tags=nb.tag_ids(MANAGED_TAG_SLUG, SRC),
            )
        if mgmt_if and chassis_mac:
            set_interface_mac(nb, mgmt_if, chassis_mac)
        if mgmt_ip and mgmt_if:
            from netbox_monitor.sync.common import upsert_ip

            ip_obj = upsert_ip(
                nb,
                mgmt_ip,
                source_slug=SRC,
                description=f"LLDP mgmt IP for {name}",
                assigned_object_type="dcim.interface",
                assigned_object_id=mgmt_if.id,
            )
            if ip_obj is not None and getattr(device, "primary_ip4", None) is None:
                nb.update(device, {"primary_ip4": ip_obj.id}, reason="set switch primary IP")
        return device

    # ----------------------------------------------------------------- dedup

    def _dedup_and_record_macs(
        self, device: Any, chassis_mac: str | None, local_macs: dict[str, str | None]
    ) -> tuple[Any, set[str]]:
        """Fold duplicates of ``device`` into one record, then store its own MACs.

        A switch reachable at two management IPs gets documented twice (discovery
        or a seed on one IP, the crawl on another). Its own MACs are the identity
        that ties the copies together: any *other* device already carrying one of
        them is the same physical box. Returns the surviving device plus the MAC
        set (the caller adds it to visited_mac so the crawl doesn't re-poll this
        chassis through its other addresses).
        """
        nb = self.ctx.netbox
        identity: dict[str, str | None] = {}
        if _is_identity_mac(chassis_mac):
            identity[chassis_mac] = None
        for mac, ifname in list(local_macs.items())[:16]:
            if _is_identity_mac(mac):
                identity.setdefault(mac, ifname)

        for mac in identity:
            match = find_interface_by_mac(nb, mac)
            if not match or match[0] != "dcim.interface" or match[2] is None:
                continue
            other_id = getattr(match[2], "id", match[2])
            if other_id is None or other_id == device.id:
                continue
            with nb.lock:
                other = nb.api.dcim.devices.get(other_id)
            if other is None or other.id == device.id:
                continue
            try:
                device = self._merge_duplicate(device, other, mac)
            except Exception as exc:
                # a failed merge must not abort the crawl; the next run retries
                log.warning(
                    "merge of duplicate switch failed",
                    a=device.name,
                    b=other.name,
                    error=str(exc)[:200],
                )
            break

        self._record_local_macs(device, identity)
        return device, set(identity)

    def _merge_duplicate(self, polled: Any, other: Any, mac: str) -> Any:
        """Merge two devices that are the same physical switch; return the keeper.

        Ownership decides direction: a human-created device always wins and only a
        managed duplicate is ever deleted (``delete_if_managed`` enforces this even
        if the direction logic were wrong). The loser's managed IPs move onto
        same-named interfaces of the keeper; its interfaces/cables cascade away
        with it and the next crawl redraws them on the keeper.
        """
        nb = self.ctx.netbox
        polled_managed = nb.is_managed(polled)
        other_managed = nb.is_managed(other)
        if polled_managed and not other_managed:
            keep, lose = other, polled
        elif other_managed and not polled_managed:
            keep, lose = polled, other
        elif polled_managed and other_managed:
            # both ours: prefer a human-tagged seed, else the one answering right now
            seed = "lldp-source" in nb.obj_tag_slugs(other)
            keep, lose = (other, polled) if seed else (polled, other)
        else:
            log.warning(
                "same switch documented twice but neither device is managed; not merging",
                a=polled.name,
                b=other.name,
                mac=mac,
            )
            return polled

        with nb.lock:
            lose_ips = list(nb.api.ipam.ip_addresses.filter(device_id=lose.id))
        if any(MANAGED_TAG_SLUG not in nb.obj_tag_slugs(ip) for ip in lose_ips):
            # a human-owned IP record hangs off the duplicate; deleting it would
            # silently unassign that record. Leave both devices alone.
            log.warning(
                "duplicate switch holds an IP we don't manage; not merging",
                device=lose.name,
            )
            return polled

        log.info(
            "merging duplicate switch",
            keep=keep.name,
            absorb=lose.name,
            matched_mac=mac,
        )
        lose_primary_id = getattr(getattr(lose, "primary_ip4", None), "id", None)
        # NetBox refuses to reassign an IP while it is a device's primary — release
        # the designation first ("Cannot reassign IP address while it is designated
        # as the primary IP for the parent object")
        if lose_primary_id is not None or getattr(lose, "primary_ip6", None) is not None:
            nb.update(
                lose,
                {"primary_ip4": None, "primary_ip6": None},
                reason="release primary IPs before merge",
            )
        for ip in lose_ips:
            iface_name = None
            iface_id = getattr(ip, "assigned_object_id", None)
            if iface_id:
                with nb.lock:
                    src_iface = nb.api.dcim.interfaces.get(iface_id)
                iface_name = getattr(src_iface, "name", None) if src_iface else None
            dest = self._local_interface(nb, keep, iface_name or "mgmt")
            if dest is None:
                continue
            nb.update(
                ip,
                {"assigned_object_type": "dcim.interface", "assigned_object_id": dest.id},
                reason="merge duplicate switch",
            )
            if ip.id == lose_primary_id and getattr(keep, "primary_ip4", None) is None:
                nb.update(keep, {"primary_ip4": ip.id}, reason="primary IP from merged duplicate")
        nb.journal(keep, f"Merged duplicate device '{lose.name}' (same chassis, MAC {mac})")
        if not nb.delete_if_managed(lose):
            return polled  # dry-run, or the guard refused — nothing was changed
        with nb.lock:
            refreshed = nb.api.dcim.devices.get(keep.id)
        return refreshed or keep

    def _record_local_macs(self, device: Any, identity: dict[str, str | None]) -> None:
        """Store the switch's own MACs on its interfaces, so later crawls (and the
        cross-module MAC matching) recognise this chassis at any of its IPs."""
        nb = self.ctx.netbox
        mgmt = None
        for mac, ifname in identity.items():
            iface = None
            if ifname:
                with nb.lock:
                    iface = nb.api.dcim.interfaces.get(device_id=device.id, name=ifname)
            if iface is None:
                if mgmt is None:
                    mgmt = self._local_interface(nb, device, "mgmt")
                iface = mgmt
            if iface is not None:
                set_interface_mac(nb, iface, mac)

    # ------------------------------------------------------------- reconcile

    def _reconcile(self, site: ResolvedSite, switch: Any, neighbors: list[LldpNeighbor]) -> None:
        nb = self.ctx.netbox
        for neighbor in neighbors:
            local_iface = self._local_interface(nb, switch, neighbor.local_port)
            if local_iface is None:
                continue
            remote_device = self._find_remote_device(nb, neighbor)
            if remote_device is None and neighbor.is_crawlable_switch():
                remote_device = self._ensure_switch_device(
                    site,
                    neighbor.mgmt_ip,
                    neighbor.sys_descr,
                    neighbor.chassis_mac,
                    neighbor.sysname,
                )
            if remote_device is None:
                log.info(
                    "lldp neighbor not found in NetBox",
                    switch=switch.name,
                    local_port=neighbor.local_port,
                    sysname=neighbor.sysname,
                    chassis_mac=neighbor.chassis_mac,
                )
                continue
            remote_iface = self._find_remote_interface(nb, remote_device, neighbor)
            if remote_iface is None:
                log.info(
                    "lldp remote interface not found",
                    remote=remote_device.name,
                    port=neighbor.remote_port,
                )
                continue
            self._ensure_cable(nb, switch, local_iface, remote_device, remote_iface)

    def _local_interface(self, nb: NetBoxClient, switch: Any, name: str) -> Any | None:
        if not name:
            return None
        with nb.lock:
            iface = nb.api.dcim.interfaces.get(device_id=switch.id, name=name)
        if iface is not None:
            return iface
        return nb.create(
            nb.api.dcim.interfaces,
            device=switch.id,
            name=name,
            type="other",
            description="Created from LLDP local port",
            tags=nb.tag_ids(MANAGED_TAG_SLUG, SRC),
        )

    def _find_remote_device(self, nb: NetBoxClient, neighbor: LldpNeighbor) -> Any | None:
        if neighbor.sysname:
            shortname = neighbor.sysname.split(".")[0]
            for candidate in (neighbor.sysname, shortname):
                with nb.lock:
                    matches = list(nb.api.dcim.devices.filter(name__ie=candidate))
                if matches:
                    return matches[0]
        if neighbor.chassis_mac:
            match = find_interface_by_mac(nb, neighbor.chassis_mac)
            if match and match[0] == "dcim.interface" and match[2] is not None:
                with nb.lock:
                    return nb.api.dcim.devices.get(getattr(match[2], "id", match[2]))
        if neighbor.mgmt_ip:
            with nb.lock:
                ips = list(nb.api.ipam.ip_addresses.filter(address=neighbor.mgmt_ip))
            for ip in ips:
                dev = getattr(ip, "assigned_object", None)
                parent = getattr(dev, "device", None) if dev else None
                if parent:
                    with nb.lock:
                        return nb.api.dcim.devices.get(parent.id)
        return None

    def _find_remote_interface(
        self, nb: NetBoxClient, device: Any, neighbor: LldpNeighbor
    ) -> Any | None:
        if neighbor.remote_port and not neighbor.remote_port_is_mac:
            with nb.lock:
                iface = nb.api.dcim.interfaces.get(device_id=device.id, name=neighbor.remote_port)
            if iface is not None:
                return iface
            # create the port on a switch we manage
            if nb.is_managed(device, SRC):
                return nb.create(
                    nb.api.dcim.interfaces,
                    device=device.id,
                    name=neighbor.remote_port,
                    type="other",
                    description="Created from LLDP remote port",
                    tags=nb.tag_ids(MANAGED_TAG_SLUG, SRC),
                )
        if neighbor.remote_port and neighbor.remote_port_is_mac:
            mac = normalize_mac(neighbor.remote_port)
            if mac:
                with nb.lock:
                    matches = list(
                        nb.api.dcim.interfaces.filter(device_id=device.id, mac_address=mac)
                    )
                if matches:
                    return matches[0]
        with nb.lock:
            ifaces = list(nb.api.dcim.interfaces.filter(device_id=device.id))
        return ifaces[0] if len(ifaces) == 1 else None

    def _ensure_cable(
        self,
        nb: NetBoxClient,
        switch: Any,
        local_iface: Any,
        remote_device: Any,
        remote_iface: Any,
    ) -> None:
        local_cable = getattr(local_iface, "cable", None)
        remote_cable = getattr(remote_iface, "cable", None)
        if local_cable and remote_cable and local_cable.id == remote_cable.id:
            return
        if local_cable or remote_cable:
            log.warning(
                "existing cable conflicts with LLDP topology; not touching it",
                switch=switch.name,
                local_port=local_iface.name,
                remote=remote_device.name,
                remote_port=remote_iface.name,
            )
            return
        cable = nb.create(
            nb.api.dcim.cables,
            a_terminations=[{"object_type": "dcim.interface", "object_id": local_iface.id}],
            b_terminations=[{"object_type": "dcim.interface", "object_id": remote_iface.id}],
            status="connected",
            description="Documented from LLDP",
            tags=nb.tag_ids(MANAGED_TAG_SLUG, SRC),
        )
        if cable is not None:
            log.info(
                "cable documented",
                a=f"{switch.name}:{local_iface.name}",
                b=f"{remote_device.name}:{remote_iface.name}",
            )
