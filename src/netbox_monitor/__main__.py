"""Entrypoint: settings store + sync engine + web UI in one asyncio process."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
import sys

import structlog

from netbox_monitor.logging_setup import setup_logging
from netbox_monitor.scheduler import Engine
from netbox_monitor.settings_store import SettingsStore
from netbox_monitor.state import StateDB
from netbox_monitor.status import StatusRegistry

log = structlog.get_logger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="netbox-monitor")
    parser.add_argument(
        "-c",
        "--config",
        default="config.yaml",
        help="legacy YAML config; imported into data/settings.json on first start",
    )
    parser.add_argument(
        "--data-dir", default="data", help="directory for settings.json / state.db / caches"
    )
    parser.add_argument(
        "--once",
        metavar="MODULE",
        help="run a single sync module once and exit (e.g. dhcp, dns, discovery, "
        "availability, proxmox, lldp, certs)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="log intended NetBox writes without executing"
    )
    parser.add_argument("--no-webui", action="store_true", help="disable the web UI")
    return parser.parse_args(argv)


async def run_once(
    args: argparse.Namespace, store: SettingsStore, state: StateDB, status: StatusRegistry
) -> int:
    from netbox_monitor.bootstrap import bootstrap
    from netbox_monitor.context import build_context
    from netbox_monitor.sync import build_modules

    config = store.get()
    if not config.netbox.configured:
        log.error("NetBox is not configured; set it up via the web UI or config.yaml")
        return 1
    ctx = await build_context(
        config, state, status, dry_run_override=True if args.dry_run else None
    )
    try:
        await asyncio.to_thread(bootstrap, ctx.netbox, config)
        modules = {m.name: m for m in build_modules(ctx)}
        if args.once not in modules:
            log.error("unknown module", requested=args.once, available=sorted(modules))
            return 1
        await modules[args.once].run()
        return 0
    finally:
        await ctx.close()


async def async_main(args: argparse.Namespace) -> int:
    store = SettingsStore.bootstrap(args.data_dir, args.config)
    config = store.get()
    setup_logging(config.log_level)
    if args.dry_run or config.dry_run:
        log.warning("DRY RUN mode: no changes will be written to NetBox")

    state = StateDB(f"{args.data_dir}/state.db")
    await state.open()
    status = StatusRegistry(state)

    try:
        if args.once:
            return await run_once(args, store, state, status)

        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in ("SIGINT", "SIGTERM"):
            if hasattr(signal, sig):
                with contextlib.suppress(NotImplementedError):  # Windows
                    loop.add_signal_handler(getattr(signal, sig), stop.set)

        engine = Engine(store, state, status, dry_run_override=True if args.dry_run else None)
        tasks = [asyncio.create_task(engine.run(stop), name="engine")]

        webui_cfg = store.get().webui
        server = None
        if webui_cfg.enabled and not args.no_webui:
            import uvicorn

            from netbox_monitor.webui.app import create_app

            app = create_app(store, engine, status)
            server = uvicorn.Server(
                uvicorn.Config(
                    app,
                    host=webui_cfg.host,
                    port=webui_cfg.port,
                    log_level="warning",
                )
            )
            log.info("web UI listening", url=f"http://{webui_cfg.host}:{webui_cfg.port}")
            tasks.append(asyncio.create_task(server.serve(), name="webui"))

        await stop.wait()
        if server is not None:
            server.should_exit = True
        await asyncio.gather(*tasks, return_exceptions=True)
        return 0
    except KeyboardInterrupt:
        return 130
    finally:
        await state.close()


def main() -> None:
    args = parse_args()
    try:
        sys.exit(asyncio.run(async_main(args)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
