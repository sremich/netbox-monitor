"""SNMP LLDP driver: walk the standard LLDP-MIB remote table (works on most
managed switches with SNMP + LLDP enabled).
"""

from __future__ import annotations

import structlog
from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    bulk_walk_cmd,
)

from netbox_monitor.lldp import LldpNeighbor
from netbox_monitor.oui import normalize_mac

log = structlog.get_logger(__name__)

OID_LOC_PORT_ID = "1.0.8802.1.1.2.1.3.7.1.3"  # lldpLocPortId, index: localPortNum
OID_REM_BASE = "1.0.8802.1.1.2.1.4.1.1"  # lldpRemTable, index: time,localPortNum,idx
COL_CHASSIS_SUBTYPE = 4
COL_CHASSIS_ID = 5
COL_PORT_SUBTYPE = 6
COL_PORT_ID = 7
COL_SYSNAME = 9

MAC_SUBTYPE = 4  # chassis/port id subtype "macAddress"
IFNAME_SUBTYPE = 5  # port id subtype "interfaceName"


def _decode(value: object, as_mac_if_binary: bool = False) -> str:
    raw = bytes(value) if hasattr(value, "asOctets") or isinstance(value, bytes) else None
    if hasattr(value, "asOctets"):
        raw = value.asOctets()
    if raw is not None:
        if as_mac_if_binary and len(raw) == 6:
            return ":".join(f"{b:02X}" for b in raw)
        try:
            return raw.decode("utf-8").strip("\x00").strip()
        except UnicodeDecodeError:
            return ":".join(f"{b:02X}" for b in raw)
    return str(value)


async def _walk(host: str, community: str, oid: str) -> list[tuple[str, object]]:
    engine = SnmpEngine()
    target = await UdpTransportTarget.create((host, 161), timeout=3, retries=1)
    results: list[tuple[str, object]] = []
    iterator = bulk_walk_cmd(
        engine,
        CommunityData(community, mpModel=1),
        target,
        ContextData(),
        0,
        25,
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False,
    )
    async for error_indication, error_status, _error_index, var_binds in iterator:
        if error_indication or error_status:
            raise RuntimeError(str(error_indication or error_status))
        for var_bind in var_binds:
            results.append((str(var_bind[0]), var_bind[1]))
    return results


async def collect(host: str, community: str) -> list[LldpNeighbor]:
    # local port number -> port id (usually the ifName)
    local_ports: dict[int, str] = {}
    for oid, value in await _walk(host, community, OID_LOC_PORT_ID):
        port_num = int(oid.rsplit(".", 1)[1])
        local_ports[port_num] = _decode(value)

    # remote table rows grouped by (localPortNum, index)
    rows: dict[tuple[int, int], dict[int, object]] = {}
    base_len = len(OID_REM_BASE.split("."))
    for oid, value in await _walk(host, community, OID_REM_BASE):
        # OID layout: <base>.<column>.<timeMark>.<localPortNum>.<index>
        parts = oid.split(".")
        column = int(parts[base_len])
        local_port_num = int(parts[base_len + 2])
        index = int(parts[base_len + 3])
        rows.setdefault((local_port_num, index), {})[column] = value

    neighbors: list[LldpNeighbor] = []
    for (local_port_num, _), columns in rows.items():
        chassis_subtype = int(columns.get(COL_CHASSIS_SUBTYPE, 0) or 0)
        port_subtype = int(columns.get(COL_PORT_SUBTYPE, 0) or 0)
        chassis_raw = columns.get(COL_CHASSIS_ID)
        chassis_mac = None
        if chassis_raw is not None and chassis_subtype == MAC_SUBTYPE:
            chassis_mac = normalize_mac(_decode(chassis_raw, as_mac_if_binary=True))
        port_raw = columns.get(COL_PORT_ID)
        remote_port = _decode(port_raw, as_mac_if_binary=True) if port_raw is not None else None
        sysname = _decode(columns[COL_SYSNAME]) if COL_SYSNAME in columns else None
        neighbors.append(
            LldpNeighbor(
                local_port=local_ports.get(local_port_num, f"port{local_port_num}"),
                chassis_mac=chassis_mac,
                sysname=sysname or None,
                remote_port=remote_port,
                remote_port_is_mac=port_subtype == MAC_SUBTYPE
                or bool(remote_port and normalize_mac(remote_port)),
            )
        )
    log.info("snmp lldp neighbors collected", host=host, count=len(neighbors))
    return neighbors
