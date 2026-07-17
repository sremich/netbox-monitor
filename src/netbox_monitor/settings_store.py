"""Runtime-editable settings store.

The live configuration is ``data/settings.json``, written atomically and mode
0600 — it holds API tokens in the clear. On first start it is seeded from
``config.yaml`` (with env interpolation) when present. Every successful update
bumps ``generation``; the scheduler watches this to gracefully rebuild the sync
loops without a process restart.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import shutil
import threading
from pathlib import Path

import structlog

from netbox_monitor.config import (
    CONFIG_SCHEMA_VERSION,
    AppConfig,
    _detect_schema,
    config_from_raw,
    load_config,
)

log = structlog.get_logger(__name__)


def _restrict(path: Path) -> None:
    """Best-effort chmod 0600 — settings.json holds plaintext API tokens.

    Suppressed on failure: Windows only maps the read-only bit, and some mounted
    filesystems reject chmod outright. Neither is worth refusing to start over.
    """
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


class SettingsStore:
    def __init__(self, path: Path, config: AppConfig):
        self.path = path
        self._config = config
        self._lock = threading.Lock()
        self.generation = 0

    # ------------------------------------------------------------- lifecycle

    @classmethod
    def bootstrap(cls, data_dir: str | Path, config_yaml: str | Path | None) -> SettingsStore:
        data_dir = Path(data_dir)
        path = data_dir / "settings.json"
        if path.exists():
            # existing deployments were written before we restricted the mode, and
            # would otherwise stay world-readable until the next save
            _restrict(path)
            raw = json.loads(path.read_text(encoding="utf-8"))
            found = _detect_schema(raw)
            config = config_from_raw(raw)  # migrates; raises if written by a newer build
            log.info("settings loaded", path=str(path), sites=[s.id for s in config.sites])
            store = cls(path, config)
            if found != CONFIG_SCHEMA_VERSION:
                # upgrade the file in place so this runs once, not every boot
                log.info(
                    "migrated settings to current schema", was=found, now=CONFIG_SCHEMA_VERSION
                )
                store._persist()
        elif config_yaml and Path(config_yaml).exists():
            config = load_config(config_yaml)
            log.info(
                "importing legacy config.yaml into settings store",
                source=str(config_yaml),
                sites=[s.id for s in config.sites],
            )
            store = cls(path, config)
            store._persist()
        else:
            log.warning("no configuration found; starting unconfigured (use the web UI)")
            store = cls(path, AppConfig())
            store._persist()

        # allow bootstrapping the UI password from the environment
        env_password = os.environ.get("WEBUI_PASSWORD")
        if env_password and not store._config.webui.password_hash:
            from netbox_monitor.webui.auth import hash_password

            store.update_field(
                lambda c: setattr(c.webui, "password_hash", hash_password(env_password))
            )
        if not store._config.webui.session_secret:
            store.update_field(lambda c: setattr(c.webui, "session_secret", secrets.token_hex(32)))
        return store

    # -------------------------------------------------------------- accessors

    def get(self) -> AppConfig:
        with self._lock:
            return self._config.model_copy(deep=True)

    def replace(self, config: AppConfig, *, backup: bool = False) -> Path | None:
        """Validate and persist a whole new config; bumps generation.

        ``backup`` copies the current settings.json to settings.json.bak first and
        returns its path — used by config import, so a bad restore is recoverable.
        It is one call rather than a separate ``backup_current()`` because the lock
        is not reentrant, and two acquisitions would race.
        """
        with self._lock:
            backup_path = self._backup_unlocked() if backup else None
            self._config = AppConfig.model_validate(config.model_dump())
            self._persist()
            self.generation += 1
        log.info("settings updated", generation=self.generation, backup=str(backup_path or ""))
        return backup_path

    def update_field(self, mutator) -> None:
        """Apply ``mutator(config)`` to a copy, validate, persist, bump generation."""
        with self._lock:
            candidate = self._config.model_copy(deep=True)
            mutator(candidate)
            self._config = AppConfig.model_validate(candidate.model_dump())
            self._persist()
            self.generation += 1

    # --------------------------------------------------------------- internal

    def _backup_unlocked(self) -> Path | None:
        """Copy the live settings.json aside. Caller must hold the lock."""
        if not self.path.exists():
            return None
        backup_path = self.path.with_suffix(".json.bak")
        shutil.copy2(self.path, backup_path)
        _restrict(backup_path)
        return backup_path

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._config.model_dump(mode="json"), indent=2), encoding="utf-8")
        # restrict *before* the rename: chmod-ing the target afterwards leaves a
        # window where the tokens are world-readable, and a crash in that window
        # leaves them that way for good.
        _restrict(tmp)
        os.replace(tmp, self.path)
