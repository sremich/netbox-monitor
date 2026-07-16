"""Entrypoint: load config, bootstrap NetBox, run the sync scheduler."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
import sys

import structlog

from netbox_monitor.bootstrap import bootstrap
from netbox_monitor.clients.netbox import NetBoxClient
from netbox_monitor.clients.technitium import TechnitiumClient
from netbox_monitor.config import load_config
from netbox_monitor.context import Context
from netbox_monitor.logging_setup import setup_logging
from netbox_monitor.oui import OuiDB
from netbox_monitor.scheduler import run_scheduler
from netbox_monitor.state import StateDB
from netbox_monitor.sync import build_modules

log = structlog.get_logger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="netbox-monitor")
    parser.add_argument("-c", "--config", default="config.yaml", help="path to config.yaml")
    parser.add_argument(
        "--once",
        metavar="MODULE",
        help="run a single sync module once and exit (e.g. dhcp, dns, discovery, "
        "availability, proxmox, lldp, certs)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="log intended NetBox writes without executing"
    )
    return parser.parse_args(argv)


async def async_main(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    if args.dry_run:
        config.dry_run = True
    setup_logging(config.log_level)
    if config.dry_run:
        log.warning("DRY RUN mode: no changes will be written to NetBox")

    netbox = NetBoxClient(config.netbox, dry_run=config.dry_run)
    technitium = TechnitiumClient(config.technitium)
    state = StateDB(config.state_db_path)
    await state.open()
    oui = OuiDB(config.data_dir)

    try:
        await asyncio.to_thread(bootstrap, netbox, config)
        ctx = Context(config=config, netbox=netbox, technitium=technitium, state=state, oui=oui)
        modules = build_modules(ctx)
        if not modules:
            log.error("no sync modules enabled; check config")
            return 1

        if args.once:
            wanted = {m.name: m for m in modules}
            if args.once not in wanted:
                log.error("unknown module", requested=args.once, available=sorted(wanted))
                return 1
            await wanted[args.once].run()
            return 0

        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in ("SIGINT", "SIGTERM"):
            if hasattr(signal, sig):
                with contextlib.suppress(NotImplementedError):  # Windows
                    loop.add_signal_handler(getattr(signal, sig), stop.set)
        await run_scheduler(modules, stop)
        return 0
    finally:
        await technitium.close()
        await state.close()


def main() -> None:
    args = parse_args()
    try:
        sys.exit(asyncio.run(async_main(args)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
