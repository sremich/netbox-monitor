import json

from netbox_monitor.lldp.unifi_ssh_driver import parse_lldpcli_json

SAMPLE_DICT_STYLE = {
    "lldp": {
        "interface": {
            "eth10": {
                "via": "LLDP",
                "chassis": {
                    "pve1": {
                        "id": {"type": "mac", "value": "bc:24:11:aa:bb:cc"},
                        "descr": "Debian GNU/Linux",
                    }
                },
                "port": {"id": {"type": "ifname", "value": "enp2s0"}, "descr": "enp2s0"},
            }
        }
    }
}

SAMPLE_LIST_STYLE = {
    "lldp": {
        "interface": [
            {
                "eth1": {
                    "chassis": {
                        "id": {"type": "mac", "value": "24:a4:3c:00:11:22"},
                        "name": "switch-basement",
                    },
                    "port": {
                        "id": {"type": "mac", "value": "24:a4:3c:00:11:23"},
                        "descr": "Port 5",
                    },
                }
            }
        ]
    }
}


def test_parse_dict_style():
    neighbors = parse_lldpcli_json(json.dumps(SAMPLE_DICT_STYLE))
    assert len(neighbors) == 1
    n = neighbors[0]
    assert n.local_port == "eth10"
    assert n.sysname == "pve1"
    assert n.chassis_mac == "BC:24:11:AA:BB:CC"
    assert n.remote_port == "enp2s0"
    assert n.remote_port_is_mac is False


def test_parse_list_style_prefers_port_descr():
    neighbors = parse_lldpcli_json(json.dumps(SAMPLE_LIST_STYLE))
    assert len(neighbors) == 1
    n = neighbors[0]
    assert n.local_port == "eth1"
    assert n.sysname == "switch-basement"
    assert n.chassis_mac == "24:A4:3C:00:11:22"
    assert n.remote_port == "Port 5"
    assert n.remote_port_is_mac is False
