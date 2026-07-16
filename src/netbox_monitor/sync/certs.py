"""SSL certificate tracking: probe TLS ports on every host with a primary IP,
record cert expiry/issuer/CN as custom fields, and warn via tags:
``cert-expiring`` (< N days) and ``cert-expired``.

Alerting is tag-based for now; a unified notification system is a planned
follow-up (see README backlog).
"""

from __future__ import annotations

import asyncio
import ssl
from datetime import UTC, datetime
from typing import Any

import structlog
from cryptography import x509
from cryptography.x509.oid import NameOID

from netbox_monitor.clients.netbox import (
    CERT_EXPIRED_TAG_SLUG,
    CERT_EXPIRING_TAG_SLUG,
)
from netbox_monitor.context import Context

log = structlog.get_logger(__name__)


async def fetch_cert(host: str, port: int, timeout: float) -> x509.Certificate | None:
    """Grab the peer certificate without verification (we document, not trust)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context), timeout=timeout
        )
    except Exception:
        return None
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        if not der:
            return None
        return x509.load_der_x509_certificate(der)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _name_attr(name: x509.Name, oid: Any) -> str:
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else ""


class CertSync:
    name = "certs"

    def __init__(self, ctx: Context):
        self.ctx = ctx

    async def run(self) -> None:
        hosts = await asyncio.to_thread(self._hosts_with_ips)
        if not hosts:
            log.info("no hosts with primary IPs to probe")
            return
        cfg = self.ctx.config.certs
        semaphore = asyncio.Semaphore(cfg.concurrency)

        async def probe(obj: Any, ip: str) -> None:
            async with semaphore:
                certs = []
                for port in cfg.ports:
                    cert = await fetch_cert(ip, port, cfg.timeout)
                    if cert is not None:
                        certs.append(cert)
                await self._apply(obj, certs)

        await asyncio.gather(*(probe(obj, ip) for obj, ip in hosts))
        log.info("certificate pass complete", hosts=len(hosts))

    def _hosts_with_ips(self) -> list[tuple[Any, str]]:
        nb = self.ctx.netbox
        hosts: list[tuple[Any, str]] = []
        with nb.lock:
            devices = list(nb.api.dcim.devices.filter(has_primary_ip=True))
            vms = list(nb.api.virtualization.virtual_machines.filter(has_primary_ip=True))
        for obj in devices + vms:
            primary = getattr(obj, "primary_ip4", None) or getattr(obj, "primary_ip", None)
            if primary:
                hosts.append((obj, str(primary.address).split("/")[0]))
        return hosts

    async def _apply(self, obj: Any, certs: list[x509.Certificate]) -> None:
        nb = self.ctx.netbox
        if not certs:
            return  # nothing listening on TLS ports; leave any manual data alone
        # track the certificate closest to expiry
        cert = min(certs, key=lambda c: c.not_valid_after_utc)
        expiry = cert.not_valid_after_utc
        issuer = _name_attr(cert.issuer, NameOID.COMMON_NAME) or _name_attr(
            cert.issuer, NameOID.ORGANIZATION_NAME
        )
        cn = _name_attr(cert.subject, NameOID.COMMON_NAME)
        days_left = (expiry - datetime.now(UTC)).days

        def write() -> None:
            nb.set_custom_fields(
                obj,
                cert_expiry=expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
                cert_issuer=issuer[:200],
                cert_cn=cn[:200],
            )
            slugs = nb.obj_tag_slugs(obj)
            if days_left < 0:
                nb.add_tags(obj, CERT_EXPIRED_TAG_SLUG)
                nb.remove_tags(obj, CERT_EXPIRING_TAG_SLUG)
                if CERT_EXPIRED_TAG_SLUG not in slugs:
                    nb.journal(
                        obj,
                        f"TLS certificate EXPIRED {abs(days_left)} days ago (CN {cn})",
                        kind="danger",
                    )
            elif days_left <= self.ctx.config.certs.expiring_days:
                nb.add_tags(obj, CERT_EXPIRING_TAG_SLUG)
                nb.remove_tags(obj, CERT_EXPIRED_TAG_SLUG)
                if CERT_EXPIRING_TAG_SLUG not in slugs:
                    nb.journal(
                        obj,
                        f"TLS certificate expires in {days_left} days (CN {cn})",
                        kind="warning",
                    )
            else:
                nb.remove_tags(obj, CERT_EXPIRING_TAG_SLUG, CERT_EXPIRED_TAG_SLUG)

        await asyncio.to_thread(write)
