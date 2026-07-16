import pytest

from netbox_monitor.state import StateDB


@pytest.fixture
async def state(tmp_path):
    db = StateDB(tmp_path / "state.db")
    await db.open()
    yield db
    await db.close()


async def test_record_check_up_down(state):
    s1 = await state.record_check("device:1", up=True, now=1000.0)
    assert s1.last_seen == 1000.0 and s1.is_up

    s2 = await state.record_check("device:1", up=False, now=1300.0)
    assert s2.last_seen == 1000.0  # unchanged while down
    assert not s2.is_up

    s3 = await state.record_check("device:1", up=True, now=1400.0)
    assert s3.last_seen == 1400.0


async def test_stale_flag_cleared_on_recovery(state):
    await state.record_check("device:2", up=False, now=100.0)
    await state.set_stale("device:2", True)
    assert (await state.get_host("device:2")).is_stale

    updated = await state.record_check("device:2", up=True, now=200.0)
    assert updated.is_stale is False


async def test_kv_roundtrip(state):
    assert await state.get_kv("missing") is None
    await state.set_kv("k", "v")
    assert await state.get_kv("k") == "v"
    await state.delete_kv("k")
    assert await state.get_kv("k") is None
