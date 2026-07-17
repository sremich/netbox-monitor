"""Scheduler + engine.

Each sync module runs on its own asyncio interval loop. The Engine wraps the
scheduler: it (re)builds the runtime Context from the SettingsStore and
gracefully restarts all loops whenever the settings generation changes
(config edited in the web UI). ``Engine.run_now(module)`` fires a module
immediately.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import structlog

from netbox_monitor.settings_store import SettingsStore
from netbox_monitor.state import StateDB
from netbox_monitor.status import StatusRegistry

log = structlog.get_logger(__name__)


@dataclass
class SyncModule:
    name: str
    interval: int
    run: Callable[[], Awaitable[None]]


async def _wait_any(*events: asyncio.Event, timeout: float | None = None) -> None:
    waiters = [asyncio.create_task(e.wait()) for e in events]
    try:
        await asyncio.wait(waiters, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for w in waiters:
            w.cancel()


async def _loop(
    module: SyncModule,
    stop: asyncio.Event,
    reload_evt: asyncio.Event,
    trigger: asyncio.Event,
    status: StatusRegistry,
) -> None:
    # small startup jitter so loops don't all hit the APIs at once
    await _wait_any(
        stop, reload_evt, trigger, timeout=random.uniform(0, min(10, module.interval / 4))
    )
    while not stop.is_set() and not reload_evt.is_set():
        trigger.clear()
        started = time.monotonic()
        try:
            log.info("sync starting", module=module.name)
            await module.run()
            duration = time.monotonic() - started
            log.info("sync finished", module=module.name, duration=round(duration, 2))
            await status.record(module.name, "_run", True, "ok", duration)
        except Exception as exc:
            duration = time.monotonic() - started
            log.exception("sync failed", module=module.name)
            await status.record(module.name, "_run", False, str(exc), duration)
        delay = max(5.0, module.interval - (time.monotonic() - started))
        await _wait_any(stop, reload_evt, trigger, timeout=delay)


async def run_scheduler(
    modules: list[SyncModule],
    stop: asyncio.Event,
    reload_evt: asyncio.Event,
    triggers: dict[str, asyncio.Event],
    status: StatusRegistry,
) -> None:
    tasks = [
        asyncio.create_task(
            _loop(m, stop, reload_evt, triggers[m.name], status), name=f"sync-{m.name}"
        )
        for m in modules
    ]
    log.info("scheduler running", modules=[m.name for m in modules])
    await _wait_any(stop, reload_evt)
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


class Engine:
    """Owns the runtime Context and the scheduler; rebuilds on settings changes."""

    def __init__(
        self,
        store: SettingsStore,
        state: StateDB,
        status: StatusRegistry,
        dry_run_override: bool | None = None,
    ):
        self.store = store
        self.state = state
        self.status = status
        self.dry_run_override = dry_run_override
        self.triggers: dict[str, asyncio.Event] = {}

    def run_now(self, module: str) -> bool:
        trigger = self.triggers.get(module)
        if trigger is None:
            return False
        trigger.set()
        return True

    async def _watch_generation(
        self, generation: int, reload_evt: asyncio.Event, stop: asyncio.Event
    ) -> None:
        while not stop.is_set() and self.store.generation == generation:
            await _wait_any(stop, timeout=2.0)
        reload_evt.set()

    async def run(self, stop: asyncio.Event) -> None:
        from netbox_monitor.bootstrap import bootstrap
        from netbox_monitor.context import build_context
        from netbox_monitor.sync import build_modules

        while not stop.is_set():
            generation = self.store.generation
            config = self.store.get()
            reload_evt = asyncio.Event()
            watcher = asyncio.create_task(self._watch_generation(generation, reload_evt, stop))

            if not config.netbox.configured:
                log.warning("NetBox not configured; sync engine idle (configure via web UI)")
                await _wait_any(stop, reload_evt)
                watcher.cancel()
                continue

            ctx = await build_context(
                config, self.state, self.status, dry_run_override=self.dry_run_override
            )
            try:
                await asyncio.to_thread(bootstrap, ctx.netbox, config)
            except Exception:
                log.exception("bootstrap failed; engine idle until settings change")
                await _wait_any(stop, reload_evt)
                watcher.cancel()
                await ctx.close()
                continue

            modules = build_modules(ctx)
            self.triggers = {m.name: asyncio.Event() for m in modules}
            if modules:
                await run_scheduler(modules, stop, reload_evt, self.triggers, self.status)
            else:
                log.warning("no sync modules enabled")
                await _wait_any(stop, reload_evt)
            watcher.cancel()
            # drop the now-orphaned trigger events so a stale run_now() during the
            # rebuild reports "not scheduled" instead of falsely succeeding
            self.triggers = {}
            await ctx.close()
            if reload_evt.is_set() and not stop.is_set():
                log.info("settings changed; rebuilding sync engine")
