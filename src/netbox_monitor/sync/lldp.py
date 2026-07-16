"""LLDP topology sync: poll switches tagged ``lldp-source`` in NetBox, resolve
credentials from the netbox-secrets plugin (config fallback), and document
neighbor relationships as NetBox cables tagged ``src:lldp``.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from netbox_monitor.clients.netbox import MANAGED_TAG_SLUG, NetBoxClient, slugify
from netbox_monitor.clients.secrets import DeviceSecrets, SecretsClient
from netbox_monitor.config import LldpFallbackCred
from netbox_monitor.context import Context
from netbox_monitor.lldp import LldpNeighbor, snmp_driver, unifi_ssh_driver
from netbox_monitor.oui import normalize_mac

log = structlog.get_logger(__name__)

SRC = "src-lldp"


class LldpSync:
    name = "lldp"

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self._secrets: SecretsClient | None = None
        if ctx.config.lldp.secrets_private_key:
            self._secrets = SecretsClient(
                ctx.config.netbox.url,
                ctx.config.netbox.token,
                ctx.config.lldp.secrets_private_key,
                verify_ssl=ctx.config.netbox.verify_ssl,
            )

    async def run(self) -> None:
        cfg = self.ctx.config.lldp
        nb = self.ctx.netbox
        tag_slug = slugify(cfg.source_tag)

        switches = await asyncio.to_thread(nb.filter_tagged, nb.api.dcim.devices, tag_slug)
        if not switches:
            log.info("no switches tagged for LLDP", tag=tag_slug)
            return

        for switch in switches:
            try:
                await self._poll_switch(switch)
            except Exception:
                log.exception("lldp poll failed", switch=switch.name)

    # ---------------------------------------------------------------- polling

    async def _poll_switch(self, switch: Any) -> None:
        cfg = self.ctx.config.lldp
        primary = getattr(switch, "primary_ip4", None) or getattr(switch, "primary_ip", None)
        if not primary:
            log.warning("switch has no primary IP; skipping", switch=switch.name)
            return
        host = str(primary.address).split("/")[0]
        platform = getattr(getattr(switch, "platform", None), "slug", "") or ""
        driver = cfg.platform_drivers.get(platform)
        if driver is None:
            driver = "unifi-ssh" if "unifi" in platform else "snmp"

        secrets = DeviceSecrets()
        if self._secrets:
            try:
                secrets = await self._secrets.get_device_secrets(switch.id)
            except Exception as exc:
                log.warning("secrets lookup failed", switch=switch.name, error=str(exc))
        fallback = cfg.fallback_creds.get(platform, LldpFallbackCred())

        if driver == "unifi-ssh":
            username = secrets.ssh_username or fallback.username
            password = secrets.ssh_password or fallback.password
            if not username or not password:
                log.warning("no SSH credentials for switch", switch=switch.name)
                return
            neighbors = await unifi_ssh_driver.collect(host, username, password)
        else:
            community = secrets.snmp_community or fallback.community
            neighbors = await snmp_driver.collect(host, community)

        await asyncio.to_thread(self._reconcile, switch, neighbors)

    # ------------------------------------------------------------- reconcile

    def _reconcile(self, switch: Any, neighbors: list[LldpNeighbor]) -> None:
        nb = self.ctx.netbox
        for neighbor in neighbors:
            local_iface = self._local_interface(nb, switch, neighbor.local_port)
            if local_iface is None:
                continue
            remote_device = self._find_remote_device(nb, neighbor)
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
        with nb.lock:
            iface = nb.api.dcim.interfaces.get(device_id=switch.id, name=name)
        if iface is not None:
            return iface
        # additive: document the port LLDP told us about
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
            with nb.lock:
                ifaces = list(nb.api.dcim.interfaces.filter(mac_address=neighbor.chassis_mac))
            for iface in ifaces:
                if iface.device:
                    with nb.lock:
                        return nb.api.dcim.devices.get(iface.device.id)
        return None

    def _find_remote_interface(
        self, nb: NetBoxClient, device: Any, neighbor: LldpNeighbor
    ) -> Any | None:
        if neighbor.remote_port and not neighbor.remote_port_is_mac:
            with nb.lock:
                iface = nb.api.dcim.interfaces.get(device_id=device.id, name=neighbor.remote_port)
            if iface is not None:
                return iface
        if neighbor.remote_port and neighbor.remote_port_is_mac:
            mac = normalize_mac(neighbor.remote_port)
            if mac:
                with nb.lock:
                    matches = list(
                        nb.api.dcim.interfaces.filter(device_id=device.id, mac_address=mac)
                    )
                if matches:
                    return matches[0]
        # single-interface hosts (our discovered devices): the only port is the one
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
            return  # already documented
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
