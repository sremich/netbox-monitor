"""DNS sync: collate Technitium DNS records with NetBox IP addresses.

- A/AAAA records whose IP exists in NetBox -> set that IPAddress's ``dns_name``.
- PTR records enrich IPs that have no forward record.
- Drift (NetBox dns_name not present in DNS, or DNS pointing at unknown IPs) is
  logged; managed objects additionally get a journal entry.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time

import structlog

from netbox_monitor.context import Context
from netbox_monitor.net_utils import sanitize_dns_name

log = structlog.get_logger(__name__)


def ptr_name_to_ip(record_name: str) -> str | None:
    """Convert '5.0.200.10.in-addr.arpa' / ip6.arpa nibble format to an IP string."""
    name = record_name.lower().rstrip(".")
    try:
        if name.endswith(".in-addr.arpa"):
            octets = name[: -len(".in-addr.arpa")].split(".")
            if len(octets) != 4:
                return None
            return ".".join(reversed(octets))
        if name.endswith(".ip6.arpa"):
            nibbles = name[: -len(".ip6.arpa")].split(".")
            if len(nibbles) != 32:
                return None
            hexstr = "".join(reversed(nibbles))
            return str(ipaddress.ip_address(int(hexstr, 16)))
    except ValueError:
        return None
    return None


class DnsSync:
    name = "dns"

    def __init__(self, ctx: Context):
        self.ctx = ctx

    async def run(self) -> None:
        sites = [s for s in self.ctx.sites if s.technitium is not None and s.config.dns_enabled]
        if not sites:
            log.info("no sites with Technitium DNS configured")
            return

        forward: dict[str, str] = {}  # ip -> fqdn (A/AAAA)
        ptr: dict[str, str] = {}  # ip -> fqdn (PTR)
        for site in sites:
            started = time.monotonic()
            try:
                count = await self._collect_site(site, forward, ptr)
                await self.ctx.status.record(
                    self.name,
                    site.config.id,
                    True,
                    f"{count} records collected",
                    time.monotonic() - started,
                )
            except Exception as exc:
                log.exception("dns collection failed for site", site=site.config.id)
                await self.ctx.status.record(
                    self.name, site.config.id, False, str(exc), time.monotonic() - started
                )

        log.info("dns records collected", a_aaaa=len(forward), ptr=len(ptr))
        await asyncio.to_thread(self._reconcile, forward, ptr)

    async def _collect_site(self, site, forward: dict[str, str], ptr: dict[str, str]) -> int:
        count = 0
        zones = await site.technitium.list_zones()
        for zone in zones:
            zone_name = zone.get("name", "")
            if zone.get("type") not in ("Primary", "Forwarder", "Stub", "Secondary"):
                continue
            if zone_name in self.ctx.config.dns.zones_exclude:
                continue
            if zone.get("disabled"):
                continue
            try:
                records = await site.technitium.get_zone_records(zone_name)
            except Exception as exc:
                log.warning("failed to read zone", zone=zone_name, error=str(exc))
                continue
            for record in records:
                rtype = record.get("type")
                rdata = record.get("rData", {})
                name = sanitize_dns_name(record.get("name"))
                if rtype in ("A", "AAAA"):
                    ip = rdata.get("ipAddress")
                    if ip and name:
                        forward.setdefault(ip, name)
                        count += 1
                elif rtype == "PTR":
                    target = sanitize_dns_name(rdata.get("ptrName"))
                    ip = ptr_name_to_ip(record.get("name", ""))
                    if ip and target:
                        ptr.setdefault(ip, target)
                        count += 1
        return count

    def _reconcile(self, forward: dict[str, str], ptr: dict[str, str]) -> None:
        nb = self.ctx.netbox
        with nb.lock:
            all_ips = list(nb.api.ipam.ip_addresses.all())

        known_hosts = set()
        for obj in all_ips:
            host = str(obj.address).split("/")[0]
            known_hosts.add(host)
            desired = forward.get(host) or ptr.get(host)
            current = (obj.dns_name or "").rstrip(".").lower()
            if desired and current != desired:
                nb.update(obj, {"dns_name": desired}, reason="dns sync")
                if nb.is_managed(obj):
                    nb.journal(obj, f"dns_name set to {desired} from Technitium")
            elif not desired and current:
                # dns_name in NetBox but no DNS record anymore -> drift, report only
                log.warning(
                    "dns drift: NetBox dns_name has no DNS record",
                    address=host,
                    dns_name=current,
                )

        # DNS records pointing at IPs NetBox doesn't know about
        for ip, fqdn in forward.items():
            if ip not in known_hosts:
                log.warning("dns drift: DNS record for IP unknown to NetBox", ip=ip, fqdn=fqdn)
