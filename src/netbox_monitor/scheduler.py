"""Simple asyncio scheduler: each sync module runs on its own interval loop."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import structlog

log = structlog.get_logger(__name__)


@dataclass
class SyncModule:
    name: str
    interval: int
    run: Callable[[], Awaitable[None]]


async def _loop(module: SyncModule, stop: asyncio.Event) -> None:
    # small startup jitter so loops don't all hit the APIs at once
    await asyncio.sleep(random.uniform(0, min(10, module.interval / 4)))
    while not stop.is_set():
        started = time.monotonic()
        try:
            log.info("sync starting", module=module.name)
            await module.run()
            log.info(
                "sync finished",
                module=module.name,
                duration=round(time.monotonic() - started, 2),
            )
        except Exception:
            log.exception("sync failed", module=module.name)
        delay = max(5.0, module.interval - (time.monotonic() - started))
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
        except TimeoutError:
            pass


async def run_scheduler(modules: list[SyncModule], stop: asyncio.Event) -> None:
    tasks = [asyncio.create_task(_loop(m, stop), name=f"sync-{m.name}") for m in modules]
    log.info("scheduler running", modules=[m.name for m in modules])
    await stop.wait()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
