"""Thin synchronous wrapper around proxmoxer for one PVE instance.

All methods are blocking — call via ``asyncio.to_thread``.
"""

from __future__ import annotations

import re
from typing import Any

import structlog
from proxmoxer import ProxmoxAPI

from netbox_monitor.config import ProxmoxInstance
from netbox_monitor.oui import normalize_mac

log = structlog.get_logger(__name__)

_NET_MAC_RE = re.compile(r"\b(?:virtio|e1000e?|vmxnet3|rtl8139|hwaddr)=([0-9A-Fa-f:]{17})")


class ProxmoxClient:
    def __init__(self, config: ProxmoxInstance):
        self.config = config
        self.api = ProxmoxAPI(
            config.host,
            port=config.port,
            user=config.user,
            token_name=config.token_name,
            token_value=config.token_value,
            verify_ssl=config.verify_ssl,
        )

    def cluster_name(self) -> str:
        if self.config.cluster_name:
            return self.config.cluster_name
        try:
            for entry in self.api.cluster.status.get():
                if entry.get("type") == "cluster":
                    return entry["name"]
        except Exception as exc:
            log.debug("cluster status unavailable", host=self.config.host, error=str(exc))
        return self.config.host

    def nodes(self) -> list[dict[str, Any]]:
        return self.api.nodes.get()

    def qemu_vms(self, node: str) -> list[dict[str, Any]]:
        return self.api.nodes(node).qemu.get()

    def lxc_containers(self, node: str) -> list[dict[str, Any]]:
        return self.api.nodes(node).lxc.get()

    def guest_config(self, node: str, kind: str, vmid: int) -> dict[str, Any]:
        return getattr(self.api.nodes(node), kind)(vmid).config.get()

    def qemu_agent_interfaces(self, node: str, vmid: int) -> list[dict[str, Any]]:
        """QEMU guest agent network interfaces; [] if agent not running."""
        try:
            resp = self.api.nodes(node).qemu(vmid).agent("network-get-interfaces").get()
            return resp.get("result", [])
        except Exception:
            return []

    @staticmethod
    def parse_net_devices(config: dict[str, Any]) -> dict[str, str]:
        """Extract {netN: mac} from a QEMU/LXC guest config."""
        devices: dict[str, str] = {}
        for key, value in config.items():
            if re.fullmatch(r"net\d+", key) and isinstance(value, str):
                match = _NET_MAC_RE.search(value)
                if match:
                    mac = normalize_mac(match.group(1))
                    if mac:
                        devices[key] = mac
        return devices

    @staticmethod
    def parse_lxc_ips(config: dict[str, Any]) -> list[str]:
        """Extract static IPs (CIDR) from LXC netN config lines."""
        ips: list[str] = []
        for key, value in config.items():
            if re.fullmatch(r"net\d+", key) and isinstance(value, str):
                for m in re.finditer(r"\bip=([0-9.]+/\d+)", value):
                    ips.append(m.group(1))
        return ips
