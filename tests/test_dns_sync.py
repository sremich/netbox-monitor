from netbox_monitor.sync.dns import DnsSync, ptr_name_to_ip


def test_ptr_v4():
    assert ptr_name_to_ip("150.10.200.10.in-addr.arpa") == "10.200.10.150"


def test_ptr_v4_trailing_dot():
    assert ptr_name_to_ip("5.0.0.10.IN-ADDR.ARPA.") == "10.0.0.5"


def test_ptr_v6():
    name = "b.a.9.8.7.6.5.4.3.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    assert ptr_name_to_ip(name) == "2001:db8::123:4567:89ab"


def test_ptr_invalid():
    assert ptr_name_to_ip("garbage.example.com") is None
    assert ptr_name_to_ip("1.2.3.in-addr.arpa") is None


def test_dns_sets_dns_name(ctx):
    ip = ctx.netbox.api.ipam.ip_addresses.create(
        address="10.200.11.2/24", status="active", dns_name="", tags=[]
    )
    sync = DnsSync(ctx)
    sync._reconcile({"10.200.11.2": "dns.home.lan"}, {})
    assert ip.dns_name == "dns.home.lan"


def test_dns_ptr_fallback(ctx):
    ip = ctx.netbox.api.ipam.ip_addresses.create(
        address="10.200.11.9/24", status="active", dns_name="", tags=[]
    )
    sync = DnsSync(ctx)
    sync._reconcile({}, {"10.200.11.9": "printer.home.lan"})
    assert ip.dns_name == "printer.home.lan"
