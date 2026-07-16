"""Status registry: last run/result per module (and per site), backed by the
state DB so the dashboard survives restarts."""

from __future__ import annotations

import json
import time
from typing import Any

import structlog

from netbox_monitor.state import StateDB

log = structlog.get_logger(__name__)

PREFIX = "status:"


class StatusRegistry:
    def __init__(self, state: StateDB):
        self.state = state

    async def record(
        self,
        module: str,
        scope: str,
        ok: bool,
        message: str = "",
        duration: float | None = None,
    ) -> None:
        payload = {
            "ts": time.time(),
            "ok": ok,
            "message": message[:500],
            "duration": round(duration, 2) if duration is not None else None,
        }
        try:
            await self.state.set_kv(f"{PREFIX}{module}:{scope}", json.dumps(payload))
        except Exception as exc:
            log.debug("status record failed", module=module, error=str(exc))

    async def snapshot(self) -> dict[str, dict[str, Any]]:
        """{module: {scope: {ts, ok, message, duration}}}"""
        raw = await self.state.list_kv(PREFIX)
        result: dict[str, dict[str, Any]] = {}
        for key, value in raw.items():
            _, module, scope = key.split(":", 2)
            try:
                result.setdefault(module, {})[scope] = json.loads(value)
            except json.JSONDecodeError:
                continue
        return result
