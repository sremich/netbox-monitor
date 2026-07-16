"""Local SQLite state: last-seen tracking for availability, misc key/value."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

import aiosqlite

_SCHEMA = """
CREATE TABLE IF NOT EXISTS host_state (
    key TEXT PRIMARY KEY,
    last_seen REAL,
    last_checked REAL,
    is_up INTEGER NOT NULL DEFAULT 0,
    is_stale INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


@dataclass
class HostState:
    key: str
    last_seen: float | None
    last_checked: float | None
    is_up: bool
    is_stale: bool


class StateDB:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._db: aiosqlite.Connection | None = None

    async def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self.path)
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    @property
    def db(self) -> aiosqlite.Connection:
        assert self._db is not None, "StateDB not opened"
        return self._db

    async def get_host(self, key: str) -> HostState | None:
        async with self.db.execute(
            "SELECT key, last_seen, last_checked, is_up, is_stale FROM host_state WHERE key=?",
            (key,),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        return HostState(row[0], row[1], row[2], bool(row[3]), bool(row[4]))

    async def record_check(self, key: str, up: bool, now: float | None = None) -> HostState:
        """Record a ping result; returns the updated state (stale flag NOT decided here)."""
        now = now or time.time()
        prev = await self.get_host(key)
        last_seen = now if up else (prev.last_seen if prev else None)
        is_stale = prev.is_stale if prev else False
        if up:
            is_stale = False
        await self.db.execute(
            "INSERT INTO host_state(key, last_seen, last_checked, is_up, is_stale)"
            " VALUES(?,?,?,?,?)"
            " ON CONFLICT(key) DO UPDATE SET last_seen=excluded.last_seen,"
            " last_checked=excluded.last_checked, is_up=excluded.is_up, is_stale=excluded.is_stale",
            (key, last_seen, now, int(up), int(is_stale)),
        )
        await self.db.commit()
        return HostState(key, last_seen, now, up, is_stale)

    async def set_stale(self, key: str, stale: bool) -> None:
        await self.db.execute("UPDATE host_state SET is_stale=? WHERE key=?", (int(stale), key))
        await self.db.commit()

    async def forget_host(self, key: str) -> None:
        await self.db.execute("DELETE FROM host_state WHERE key=?", (key,))
        await self.db.commit()

    async def get_kv(self, key: str) -> str | None:
        async with self.db.execute("SELECT value FROM kv WHERE key=?", (key,)) as cur:
            row = await cur.fetchone()
        return row[0] if row else None

    async def delete_kv(self, key: str) -> None:
        await self.db.execute("DELETE FROM kv WHERE key=?", (key,))
        await self.db.commit()

    async def set_kv(self, key: str, value: str) -> None:
        await self.db.execute(
            "INSERT INTO kv(key, value) VALUES(?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        await self.db.commit()

    async def list_kv(self, prefix: str) -> dict[str, str]:
        async with self.db.execute(
            "SELECT key, value FROM kv WHERE key LIKE ?", (prefix + "%",)
        ) as cur:
            rows = await cur.fetchall()
        return {row[0]: row[1] for row in rows}
