"""Shared runtime context handed to every sync module."""

from __future__ import annotations

from dataclasses import dataclass

from netbox_monitor.clients.netbox import NetBoxClient
from netbox_monitor.clients.technitium import TechnitiumClient
from netbox_monitor.config import AppConfig
from netbox_monitor.oui import OuiDB
from netbox_monitor.state import StateDB


@dataclass
class Context:
    config: AppConfig
    netbox: NetBoxClient
    technitium: TechnitiumClient
    state: StateDB
    oui: OuiDB
