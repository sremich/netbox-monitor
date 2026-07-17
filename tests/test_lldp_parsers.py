"""LLDP driver parsers. The MikroTik fixture is real output captured from a
CRS309 during development; the others are representative vendor formats."""

from netbox_monitor.lldp import LldpNeighbor
from netbox_monitor.lldp.cisco_ssh_driver import parse_lldp_detail
from netbox_monitor.lldp.mikrotik_ssh_driver import parse_ip_neighbor

# --- real captured MikroTik /ip neighbor print detail (trimmed) ---
MIKROTIK = """
 0 interface=sfp-sfpplus2,Native address=10.200.11.91 address4=10.200.11.91
   address6=fe80::5a47:caff:fe73:37ef mac-address=58:47:CA:73:37:EF
   identity="pve01.remichnet.com" platform="Debian" version="" unpack=none
   age=2s ipv6=yes interface-name="enp2s0"
   system-description="Debian GNU/Linux 13 (trixie) Linux 6.17.2-2-pve"
   system-caps=bridge,wlan-ap,router,station-only
   system-caps-enabled=bridge,wlan-ap discovered-by=lldp

 1 interface=sfp-sfpplus1 address4=10.200.11.5 mac-address=24:A4:3C:00:11:22
   identity="core-cisco" platform="Cisco" version="15.2"
   system-description="Cisco IOS Software, C3560CX"
   system-caps=bridge,router system-caps-enabled=bridge,router discovered-by=lldp

 2 interface=ether1 address=10.200.11.250 mac-address=aa:bb:cc:dd:ee:ff
   identity="mndp-only" discovered-by=mndp
"""


def test_mikrotik_parses_real_output():
    neighbors = parse_ip_neighbor(MIKROTIK)
    # the pure-MNDP entry (#2) is filtered out
    assert len(neighbors) == 2
    by_ip = {n.mgmt_ip: n for n in neighbors}

    pve = by_ip["10.200.11.91"]
    assert pve.local_port == "sfp-sfpplus2"
    assert pve.chassis_mac == "58:47:CA:73:37:EF"
    assert pve.sysname == "pve01.remichnet.com"
    assert pve.remote_port == "enp2s0"
    assert "bridge" in pve.capabilities
    assert "Debian" in pve.sys_descr
    # Debian host: advertises bridge but is NOT a crawlable switch
    assert pve.is_crawlable_switch() is False

    cisco = by_ip["10.200.11.5"]
    assert cisco.chassis_mac == "24:A4:3C:00:11:22"
    assert "bridge" in cisco.capabilities
    # Cisco: bridge + vendor signature -> crawlable
    assert cisco.is_crawlable_switch() is True


CISCO_DETAIL = """
------------------------------------------------
Local Intf: Gi1/0/1
Chassis id: 24a4.3c00.aabb
Port id: GigabitEthernet0/24
Port Description: uplink-to-core
System Name: access-sw-2
System Description:
Cisco IOS Software, C2960X Software
Time remaining: 97 seconds
System Capabilities: B,R
Enabled Capabilities: B
Management Addresses:
    IP: 10.200.11.8
------------------------------------------------
Local Intf: Gi1/0/2
Chassis id: 0011.2233.4455
Port id: 5
System Name: some-ap
Enabled Capabilities: W
Management Addresses:
    IP: 10.200.20.9
"""


def test_cisco_detail_parses():
    neighbors = parse_lldp_detail(CISCO_DETAIL)
    assert len(neighbors) == 2
    sw = neighbors[0]
    assert sw.local_port == "Gi1/0/1"
    assert sw.chassis_mac == "24:A4:3C:00:AA:BB"
    assert sw.remote_port == "GigabitEthernet0/24"
    assert sw.sysname == "access-sw-2"
    assert sw.mgmt_ip == "10.200.11.8"
    assert "bridge" in sw.capabilities
    assert sw.is_crawlable_switch() is True  # Cisco IOS descr

    ap = neighbors[1]
    assert ap.mgmt_ip == "10.200.20.9"
    assert "wlan-ap" in ap.capabilities
    assert ap.is_crawlable_switch() is False  # no bridge cap


def test_arista_json_parses():
    import json

    from netbox_monitor.lldp.arista_ssh_driver import parse_lldp_json

    payload = json.dumps(
        {
            "lldpNeighbors": {
                "Ethernet1": {
                    "lldpNeighborInfo": [
                        {
                            "chassisId": "001c.7300.aabb",
                            "systemName": "spine1",
                            "systemDescription": "Arista Networks EOS 4.30",
                            "portId": "Ethernet49",
                            "systemCapabilities": {"bridge": True, "router": True},
                            "managementAddresses": [
                                {"addressType": "ipv4", "address": "10.200.11.20"}
                            ],
                        }
                    ]
                }
            }
        }
    )
    neighbors = parse_lldp_json(payload)
    assert len(neighbors) == 1
    n = neighbors[0]
    assert n.local_port == "Ethernet1"
    assert n.chassis_mac == "00:1C:73:00:AA:BB"
    assert n.mgmt_ip == "10.200.11.20"
    assert n.capabilities == {"bridge", "router"}
    assert n.is_crawlable_switch() is True


def test_snmp_sg300_encoding(monkeypatch):
    """Regression for the real Cisco SG300-10: chassis MAC advertised as an ASCII
    string (not binary), and the mgmt-address OID index (captured live)."""
    import asyncio

    from netbox_monitor.lldp import snmp_driver

    class Oct:
        def __init__(self, b):
            self._b = b if isinstance(b, bytes) else b.encode()

        def asOctets(self):
            return self._b

        def __bytes__(self):
            return self._b

    REM = snmp_driver.OID_REM_BASE
    LOC = snmp_driver.OID_LOC_PORT_ID
    MAN = snmp_driver.OID_REM_MAN_ADDR
    walks = {
        LOC: [(f"{LOC}.58", Oct("gi10"))],
        REM: [
            (f"{REM}.4.0.58.51", 7),  # chassisSubtype = local(7)
            (f"{REM}.5.0.58.51", Oct("1c:0b:8b:16:79:60")),  # chassisId as text
            (f"{REM}.6.0.58.51", 3),  # portSubtype = mac
            (f"{REM}.7.0.58.51", Oct(bytes.fromhex("1c0b8b167960"))),
            (f"{REM}.9.0.58.51", Oct("RemichNet-Unifi-UK")),
            (f"{REM}.10.0.58.51", Oct("Debian GNU/Linux 11 ui-ipq9574")),
            (f"{REM}.12.0.58.51", Oct(b"\x28\x00")),  # caps: bridge + router
        ],
        MAN: [(f"{MAN}.3.0.58.51.1.4.10.200.1.1", 2)],
    }

    async def fake_walk(engine, host, community, oid):
        return walks.get(oid, [])

    monkeypatch.setattr(snmp_driver, "_walk", fake_walk)
    neighbors = asyncio.run(snmp_driver.collect("10.200.11.5", "public"))
    assert len(neighbors) == 1
    n = neighbors[0]
    assert n.local_port == "gi10"
    assert n.chassis_mac == "1C:0B:8B:16:79:60"  # parsed from the ASCII-string chassis id
    assert n.mgmt_ip == "10.200.1.1"  # mgmt-address OID index parsed correctly
    assert n.capabilities == {"bridge", "router"}
    assert n.is_crawlable_switch() is True  # "Unifi" in sysname + mgmt IP


def test_vendor_signature_gate():
    # a NAS advertising bridge but no switch vendor -> not crawlable
    nas = LldpNeighbor(
        local_port="e1",
        chassis_mac="aa:bb:cc:00:00:01",
        mgmt_ip="10.0.0.9",
        capabilities={"bridge"},
        sys_descr="Synology DSM",
        sysname="nas",
    )
    assert nas.is_crawlable_switch() is False
    # same but MikroTik -> crawlable
    sw = LldpNeighbor(
        local_port="e1",
        chassis_mac="aa:bb:cc:00:00:02",
        mgmt_ip="10.0.0.10",
        capabilities={"bridge"},
        sys_descr="RouterOS 7.21",
        sysname="sw",
    )
    assert sw.is_crawlable_switch() is True
