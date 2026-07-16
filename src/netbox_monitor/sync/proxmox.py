"""Proxmox sync: mirror PVE clusters, nodes, VMs and LXC containers into NetBox's
virtualization model (Cluster / Device / VirtualMachine / VMInterface / IPAddress).
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

import structlog

from netbox_monitor.clients.netbox import MANAGED_TAG_SLUG, STALE_TAG_SLUG, NetBoxClient
from netbox_monitor.clients.proxmox import ProxmoxClient
from netbox_monitor.context import Context
from netbox_monitor.sync.common import now_iso, set_interface_mac, upsert_ip

log = structlog.get_logger(__name__)

SRC = "src-proxmox"

STATUS_MAP = {"running": "active", "stopped": "offline", "paused": "paused"}


class ProxmoxSync:
    name = "proxmox"

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self._disk_in_mb: bool | None = None

    async def run(self) -> None:
        sites = [s for s in self.ctx.sites if s.config.proxmox and s.config.proxmox_enabled]
        if not sites:
            log.info("no sites with proxmox instances configured")
            return
        for site in sites:
            started = time.monotonic()
            errors = []
            for instance in site.config.proxmox:
                try:
                    await asyncio.to_thread(self._sync_instance, instance, site.netbox_site_id)
                except Exception as exc:
                    errors.append(f"{instance.host}: {exc}")
                    log.exception("proxmox instance sync failed", host=instance.host)
            await self.ctx.status.record(
                self.name,
                site.config.id,
                not errors,
                "; ".join(errors) or f"{len(site.config.proxmox)} instance(s) synced",
                time.monotonic() - started,
            )

    # ---------------------------------------------------------------- helpers

    def _disk_unit_mb(self, nb: NetBoxClient) -> bool:
        """NetBox >= 4.1 stores VM disk in MB, older versions in GB."""
        if self._disk_in_mb is None:
            try:
                major, minor = (int(x) for x in str(nb.api.version).split(".")[:2])
                self._disk_in_mb = (major, minor) >= (4, 1)
            except Exception:
                self._disk_in_mb = True
        return self._disk_in_mb

    # ------------------------------------------------------------------ sync

    def _sync_instance(self, instance_cfg: Any, site_id: int | None) -> None:
        nb = self.ctx.netbox
        client = ProxmoxClient(instance_cfg)
        cluster_name = client.cluster_name()
        log.info("syncing proxmox", host=instance_cfg.host, cluster=cluster_name)

        cluster_type = nb.ensure(
            nb.api.virtualization.cluster_types,
            {"slug": "proxmox-ve"},
            {"name": "Proxmox VE"},
        )
        cluster_defaults: dict[str, Any] = {
            "type": cluster_type.id if cluster_type else None,
            "status": "active",
            "tags": nb.tag_ids(MANAGED_TAG_SLUG, SRC),
        }
        if site_id is not None:
            cluster_defaults["scope_type"] = "dcim.site"
            cluster_defaults["scope_id"] = site_id
        cluster = nb.ensure(
            nb.api.virtualization.clusters, {"name": cluster_name}, cluster_defaults
        )
        if cluster is None:  # dry-run and cluster missing
            log.info("dry-run: cluster not present; skipping detail sync", cluster=cluster_name)
            return

        manufacturer = nb.ensure(
            nb.api.dcim.manufacturers, {"slug": "proxmox"}, {"name": "Proxmox"}
        )
        node_type = nb.ensure(
            nb.api.dcim.device_types,
            {"slug": "pve-node"},
            {
                "manufacturer": manufacturer.id if manufacturer else None,
                "model": "PVE node",
                "u_height": 0,
            },
        )

        node_devices: dict[str, Any] = {}
        seen_vm_names: set[str] = set()
        for node in client.nodes():
            device = self._sync_node(nb, node, cluster, node_type, site_id)
            if device is not None:
                node_devices[node["node"]] = device

        for node in client.nodes():
            node_name = node["node"]
            if node.get("status") != "online":
                continue
            for vm in client.qemu_vms(node_name):
                seen_vm_names.add(vm.get("name", str(vm["vmid"])))
                self._sync_guest(
                    nb, client, cluster, node_devices.get(node_name), node_name, "qemu", vm
                )
            for ct in client.lxc_containers(node_name):
                seen_vm_names.add(ct.get("name", str(ct["vmid"])))
                self._sync_guest(
                    nb, client, cluster, node_devices.get(node_name), node_name, "lxc", ct
                )

        self._mark_vanished(nb, cluster, seen_vm_names)

    def _sync_node(
        self, nb: NetBoxClient, node: dict, cluster: Any, node_type: Any, site_id: int | None
    ) -> Any:
        if site_id is None:
            log.warning("no NetBox site resolved for proxmox node; skipping", node=node["node"])
            return None
        status = "active" if node.get("status") == "online" else "offline"
        device = nb.ensure(
            nb.api.dcim.devices,
            {"name": node["node"]},
            {
                "role": nb.refs.get("role_hypervisor"),
                "device_type": node_type.id if node_type else None,
                "site": site_id,
                "cluster": cluster.id,
                "status": status,
                "tags": nb.tag_ids(MANAGED_TAG_SLUG, SRC),
                "custom_fields": {"last_seen": now_iso()},
            },
        )
        if device is None:
            return None
        updates = {}
        if getattr(device, "cluster", None) is None:
            updates["cluster"] = cluster.id
        current_status = getattr(device.status, "value", str(device.status))
        if nb.is_managed(device, SRC) and current_status != status:
            updates["status"] = status
            updates["custom_fields"] = {
                **dict(device.custom_fields or {}),
                "last_seen": now_iso(),
            }
        if updates:
            nb.update(device, updates, reason="proxmox node sync")
        return device

    def _sync_guest(
        self,
        nb: NetBoxClient,
        client: ProxmoxClient,
        cluster: Any,
        node_device: Any,
        node_name: str,
        kind: str,
        guest: dict,
    ) -> None:
        vmid = guest["vmid"]
        name = guest.get("name") or f"{kind}-{vmid}"
        status = STATUS_MAP.get(guest.get("status", ""), "offline")
        memory_mb = int(guest.get("maxmem", 0) / 1048576) or None
        vcpus = guest.get("maxcpu") or guest.get("cpus") or None
        disk_bytes = guest.get("maxdisk") or 0
        disk = (
            int(disk_bytes / 1048576) if self._disk_unit_mb(nb) else int(disk_bytes / 1073741824)
        ) or None

        with nb.lock:
            vm = nb.api.virtualization.virtual_machines.get(name=name, cluster_id=cluster.id)
        payload = {
            "status": status,
            "vcpus": vcpus,
            "memory": memory_mb,
            "disk": disk,
            "device": node_device.id if node_device else None,
        }
        if vm is None:
            vm = nb.create(
                nb.api.virtualization.virtual_machines,
                name=name,
                cluster=cluster.id,
                tags=nb.tag_ids(MANAGED_TAG_SLUG, SRC),
                comments=f"Proxmox {kind} vmid {vmid} on {node_name}",
                custom_fields={"last_seen": now_iso()},
                **payload,
            )
            if vm is None:
                return
        else:
            updates = {}
            for field, desired in payload.items():
                if desired is None:
                    continue
                current = getattr(vm, field, None)
                current = getattr(current, "value", None) or getattr(current, "id", None) or current
                if field == "status":
                    current = getattr(vm.status, "value", str(vm.status))
                if current != desired:
                    updates[field] = desired
            if updates and nb.is_managed(vm, SRC):
                updates["custom_fields"] = {
                    **dict(vm.custom_fields or {}),
                    "last_seen": now_iso(),
                }
                nb.update(vm, updates, reason="proxmox guest sync")
            if nb.is_managed(vm, SRC) and STALE_TAG_SLUG in nb.obj_tag_slugs(vm):
                nb.remove_tags(vm, STALE_TAG_SLUG)

        # interfaces + IPs
        try:
            config = client.guest_config(node_name, kind, vmid)
        except Exception as exc:
            log.debug("guest config unavailable", vmid=vmid, error=str(exc))
            return
        macs = client.parse_net_devices(config)
        iface_objs: dict[str, Any] = {}
        for net_name, mac in macs.items():
            iface = nb.ensure(
                nb.api.virtualization.interfaces,
                {"virtual_machine_id": vm.id, "name": net_name},
                {
                    "virtual_machine": vm.id,
                    "tags": nb.tag_ids(MANAGED_TAG_SLUG, SRC),
                },
            )
            if iface is not None:
                set_interface_mac(nb, iface, mac, object_type="virtualization.vminterface")
                iface_objs[net_name] = iface

        ips: list[str] = []
        if kind == "qemu" and guest.get("status") == "running":
            for agent_iface in client.qemu_agent_interfaces(node_name, vmid):
                for addr in agent_iface.get("ip-addresses", []) or []:
                    ip = addr.get("ip-address", "")
                    try:
                        parsed = ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    if parsed.is_loopback or parsed.is_link_local:
                        continue
                    ips.append(ip)
        elif kind == "lxc":
            ips.extend(cidr.split("/")[0] for cidr in client.parse_lxc_ips(config))

        first_iface = next(iter(iface_objs.values()), None)
        primary_set = getattr(vm, "primary_ip4", None) is not None
        for ip in ips:
            if ipaddress.ip_address(ip).version != 4:
                continue
            ip_obj = upsert_ip(
                nb,
                ip,
                source_slug=SRC,
                description=f"Proxmox guest {name}",
                assigned_object_type="virtualization.vminterface" if first_iface else None,
                assigned_object_id=first_iface.id if first_iface else None,
            )
            if (
                ip_obj is not None
                and not primary_set
                and first_iface is not None
                and getattr(ip_obj, "assigned_object_id", None) == first_iface.id
            ):
                nb.update(vm, {"primary_ip4": ip_obj.id}, reason="set VM primary IP")
                primary_set = True
            elif ip_obj is not None and not primary_set:
                # IP exists but belongs elsewhere (e.g. its DHCP lease record);
                # don't hijack it as this VM's primary
                log.info("VM IP not assigned to its interface; primary not set", vm=name, ip=ip)

    def _mark_vanished(self, nb: NetBoxClient, cluster: Any, seen: set[str]) -> None:
        existing = nb.filter_tagged(
            nb.api.virtualization.virtual_machines, SRC, cluster_id=cluster.id
        )
        for vm in existing:
            if vm.name in seen:
                continue
            if STALE_TAG_SLUG in nb.obj_tag_slugs(vm):
                continue
            log.warning("VM vanished from Proxmox; tagging stale", vm=vm.name)
            nb.add_tags(vm, STALE_TAG_SLUG)
            nb.update(vm, {"status": "offline"}, reason="VM no longer present in Proxmox")
            nb.journal(vm, "VM no longer exists in Proxmox; tagged stale", kind="warning")
