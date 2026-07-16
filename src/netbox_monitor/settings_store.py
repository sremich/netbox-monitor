"""Runtime-editable settings store.

The live configuration is ``data/settings.json``, written atomically. On first
start it is seeded from ``config.yaml`` (with env interpolation) when present.
Every successful update bumps ``generation``; the scheduler watches this to
gracefully rebuild the sync loops without a process restart.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from pathlib import Path

import structlog

from netbox_monitor.config import AppConfig, load_config

log = structlog.get_logger(__name__)


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
            config = AppConfig.model_validate(json.loads(path.read_text(encoding="utf-8")))
            log.info("settings loaded", path=str(path), sites=[s.id for s in config.sites])
            store = cls(path, config)
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

    def replace(self, config: AppConfig) -> None:
        """Validate and persist a whole new config; bumps generation."""
        with self._lock:
            self._config = AppConfig.model_validate(config.model_dump())
            self._persist()
            self.generation += 1
        log.info("settings updated", generation=self.generation)

    def update_field(self, mutator) -> None:
        """Apply ``mutator(config)`` to a copy, validate, persist, bump generation."""
        with self._lock:
            candidate = self._config.model_copy(deep=True)
            mutator(candidate)
            self._config = AppConfig.model_validate(candidate.model_dump())
            self._persist()
            self.generation += 1

    # --------------------------------------------------------------- internal

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._config.model_dump(mode="json"), indent=2), encoding="utf-8")
        os.replace(tmp, self.path)
