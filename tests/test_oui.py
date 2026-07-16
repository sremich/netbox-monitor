from netbox_monitor.oui import OuiDB, normalize_mac


def test_normalize_formats():
    assert normalize_mac("24-A4-3C-AA-BB-CC") == "24:A4:3C:AA:BB:CC"
    assert normalize_mac("24a4.3caa.bbcc") == "24:A4:3C:AA:BB:CC"
    assert normalize_mac("24:a4:3c:aa:bb:cc") == "24:A4:3C:AA:BB:CC"
    assert normalize_mac("not-a-mac") is None
    assert normalize_mac("") is None


def test_builtin_lookup(tmp_path):
    db = OuiDB(tmp_path)
    assert db.lookup("B8:27:EB:11:22:33") == "Raspberry Pi Foundation"
    assert db.lookup("24-A4-3C-00-00-01") == "Ubiquiti Inc"


def test_locally_administered(tmp_path):
    db = OuiDB(tmp_path)
    assert "Locally administered" in db.lookup("02:00:00:11:22:33")


def test_unknown(tmp_path):
    db = OuiDB(tmp_path)
    assert db.lookup("F0-F0-F0-11-22-33") is None
