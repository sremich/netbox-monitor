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
OID_REM_MAN_ADDR = "1.0.8802.1.1.2.1.4.2.1"  # lldpRemManAddrTable
COL_CHASSIS_SUBTYPE = 4
COL_CHASSIS_ID = 5
COL_PORT_SUBTYPE = 6
COL_PORT_ID = 7
COL_SYSNAME = 9
COL_SYSDESC = 10
COL_CAP_ENABLED = 12  # lldpRemSysCapEnabled, a 1-2 byte bitmap (BER MSB-first)

MAC_SUBTYPE = 4  # chassis/port id subtype "macAddress"
IFNAME_SUBTYPE = 5  # port id subtype "interfaceName"
MAN_ADDR_IPV4_SUBTYPE = 1  # lldpRemManAddrSubtype for IPv4

# lldpRemSysCapEnabled bit positions (RFC/IEEE order, MSB of first octet = Other)
_CAP_BITS = [
    "other",
    "repeater",
    "bridge",
    "wlan-ap",
    "router",
    "telephone",
    "docsis",
    "station",
]


def _decode_caps(value: object) -> set[str]:
    raw = value.asOctets() if hasattr(value, "asOctets") else bytes(value or b"")
    if not raw:
        return set()
    bits = int.from_bytes(raw[:2], "big")
    width = len(raw[:2]) * 8
    caps: set[str] = set()
    for i, name in enumerate(_CAP_BITS):
        # bit i counts from the most-significant bit of the field
        if bits & (1 << (width - 1 - i)):
            caps.add(name)
    return caps


def _man_addr_from_oid(oid: str, base_len: int) -> str | None:
    """The management address is encoded in the lldpRemManAddrTable OID index:
    ...<localPortNum>.<index>.<addrSubtype>.<addrLen>.<addr bytes>."""
    parts = [int(p) for p in oid.split(".")[base_len:]]
    # find the subtype/len/addr tail: subtype, len, then len address octets
    for i in range(len(parts) - 2):
        subtype, length = parts[i], parts[i + 1]
        if subtype == MAN_ADDR_IPV4_SUBTYPE and length == 4 and i + 2 + 4 <= len(parts) + 1:
            octets = parts[i + 2 : i + 2 + 4]
            if len(octets) == 4 and all(0 <= o <= 255 for o in octets):
                return ".".join(str(o) for o in octets)
    return None


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
        name = _decode(value)
        # some switches report a binary/MAC port id that decodes to junk; fall back
        if not name or not all(32 <= ord(ch) < 127 for ch in name):
            name = f"port{port_num}"
        local_ports[port_num] = name

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

    # management addresses, keyed by (localPortNum, index) from the OID
    man_addrs: dict[tuple[int, int], str] = {}
    man_base_len = len(OID_REM_MAN_ADDR.split("."))
    try:
        for oid, _value in await _walk(host, community, OID_REM_MAN_ADDR):
            # index after base: <column>.<timeMark>.<localPortNum>.<remIndex>.<addr...>
            idx_parts = oid.split(".")[man_base_len:]
            if len(idx_parts) >= 4:
                key = (int(idx_parts[2]), int(idx_parts[3]))
                addr = _man_addr_from_oid(oid, man_base_len)
                if addr and key not in man_addrs:
                    man_addrs[key] = addr
    except Exception as exc:
        log.debug("lldpRemManAddr walk failed", host=host, error=str(exc))

    neighbors: list[LldpNeighbor] = []
    for (local_port_num, index), columns in rows.items():
        chassis_subtype = int(columns.get(COL_CHASSIS_SUBTYPE, 0) or 0)
        port_subtype = int(columns.get(COL_PORT_SUBTYPE, 0) or 0)
        chassis_raw = columns.get(COL_CHASSIS_ID)
        chassis_mac = None
        if chassis_raw is not None:
            if chassis_subtype == MAC_SUBTYPE:
                chassis_mac = normalize_mac(_decode(chassis_raw, as_mac_if_binary=True))
            else:
                # some switches (e.g. Cisco Small Business) advertise the chassis
                # MAC as a text string under a non-mac subtype
                chassis_mac = normalize_mac(_decode(chassis_raw))
        port_raw = columns.get(COL_PORT_ID)
        remote_port = _decode(port_raw, as_mac_if_binary=True) if port_raw is not None else None
        sysname = _decode(columns[COL_SYSNAME]) if COL_SYSNAME in columns else None
        sys_descr = _decode(columns[COL_SYSDESC]) if COL_SYSDESC in columns else None
        caps = _decode_caps(columns[COL_CAP_ENABLED]) if COL_CAP_ENABLED in columns else set()
        neighbors.append(
            LldpNeighbor(
                local_port=local_ports.get(local_port_num, f"port{local_port_num}"),
                chassis_mac=chassis_mac,
                sysname=sysname or None,
                remote_port=remote_port,
                remote_port_is_mac=port_subtype == MAC_SUBTYPE
                or bool(remote_port and normalize_mac(remote_port)),
                mgmt_ip=man_addrs.get((local_port_num, index)),
                capabilities=caps,
                sys_descr=sys_descr or None,
            )
        )
    log.info("snmp lldp neighbors collected", host=host, count=len(neighbors))
    return neighbors
