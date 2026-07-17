"""Portable configuration export / import.

Produces a single self-describing JSON envelope that carries the whole config
between instances (or into cold storage), in one of two modes:

* **encrypted** — passphrase-protected, contains every credential. The real
  transfer/backup format.
* **redacted** — no passphrase, every secret replaced by ``__REDACTED__``. Safe
  to diff, share, or attach to a bug report. On import a redacted value means
  *keep whatever the target already has*, mirroring the "blank field = keep
  stored value" convention the settings UI already uses.

The ``webui`` section is **never exported**: importing must not change how you
log in (nor lock you out), and ``session_secret`` in an export would let anyone
holding the file forge session cookies against the instance it came from.

``proxmox[*].token_name`` is deliberately *not* treated as a secret — it names a
token rather than authenticating with it, and keeping it makes a redacted export
diffable. ``lldp.secrets_private_key`` is likewise a *path*, not key material.

Crypto: scrypt (parameters recorded in the envelope) + AES-256-GCM, with the
canonical header as associated data — so tampering with ``config_schema`` to
dodge the version check, or with the KDF parameters, fails authentication rather
than being honoured.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from netbox_monitor import __version__
from netbox_monitor.config import (
    CONFIG_SCHEMA_VERSION,
    AppConfig,
    ConfigSchemaTooNewError,
    migrate_to_current,
)

log = structlog.get_logger(__name__)

FORMAT = "netbox-monitor-config"
FORMAT_VERSION = 1
REDACTED = "__REDACTED__"
MIN_PASSPHRASE = 12

#: Every secret-bearing field, as a path through the *serialized* config.
#: ``*`` matches every element of a list or every value of a dict.
#: A new secret field MUST be added here — tests/test_config_transfer.py walks the
#: model and fails until it is classified.
SECRET_PATHS: tuple[tuple[str, ...], ...] = (
    ("netbox", "token"),
    ("sites", "*", "technitium", "token"),
    ("sites", "*", "proxmox", "*", "token_value"),
    ("sites", "*", "lldp", "snmp_community"),
    ("sites", "*", "lldp", "ssh_password"),
    ("lldp", "credentials", "*", "password"),
    ("lldp", "credentials", "*", "snmp_community"),
    ("lldp", "fallback_creds", "*", "community"),
    ("lldp", "fallback_creds", "*", "password"),
)

#: How to line up list elements between an incoming config and the current one.
#: Identity, never index: a reordered export must not attach one host's token to
#: another host.
LIST_KEYS: dict[tuple[str, ...], str] = {
    ("sites",): "id",
    ("sites", "*", "proxmox"): "host",
    ("lldp", "credentials"): "name",
}

# scrypt ceilings, enforced on read: an envelope claiming n=2**30 would otherwise
# be a one-request OOM.
_MAX_N = 1 << 20
_MAX_R = 32
_MAX_P = 16
_KEY_LEN = 32

_SCRYPT_N = 1 << 15
_SCRYPT_R = 8
_SCRYPT_P = 1


class ConfigTransferError(RuntimeError):
    """Base for every export/import failure."""


class BadPassphrase(ConfigTransferError):
    """Wrong passphrase, or the payload was tampered with (indistinguishable)."""


class UnsupportedFormat(ConfigTransferError):
    """Not a netbox-monitor config export, or a format this build can't read."""


@dataclass(frozen=True)
class ImportResult:
    config: AppConfig
    encrypted: bool
    source_app_version: str
    source_schema: int
    migrated_from: int | None  # None when the payload was already current
    unresolved_secrets: tuple[str, ...]  # dotted paths left blank


# --------------------------------------------------------------- traversal


def _walk(node: Any, path: tuple[str, ...], visit: Callable[[dict, str], None]) -> None:
    """Call ``visit(container, key)`` for every leaf matching ``path``."""
    if not path:
        return
    head, rest = path[0], path[1:]
    if head == "*":
        children = (
            node
            if isinstance(node, list)
            else list(node.values())
            if isinstance(node, dict)
            else []
        )
        for child in children:
            _walk(child, rest, visit)
        return
    if not isinstance(node, dict) or head not in node:
        return
    if rest:
        _walk(node[head], rest, visit)
    else:
        visit(node, head)


def redact(data: dict) -> dict:
    """Replace every populated secret with the sentinel (in place, returns data)."""

    def hide(container: dict, key: str) -> None:
        if container.get(key):  # leave empty values empty — nothing to hide
            container[key] = REDACTED

    for path in SECRET_PATHS:
        _walk(data, path, hide)
    return data


def _counterpart(item: Any, current: Any, key: str | None) -> Any:
    """The element of the ``current`` list matching ``item`` by its identity key."""
    if key is None or not isinstance(item, dict) or not isinstance(current, list):
        return None
    wanted = item.get(key)
    if wanted is None:
        return None
    return next((c for c in current if isinstance(c, dict) and c.get(key) == wanted), None)


def merge_redacted(incoming: dict, current: dict) -> tuple[dict, list[str]]:
    """Replace every ``__REDACTED__`` leaf in ``incoming`` with the value ``current``
    holds at the same logical location.

    Returns ``(incoming, unresolved)``; ``unresolved`` lists dotted paths that had no
    counterpart in ``current``. Those are blanked rather than guessed — a wrong
    credential sent to a real host is worse than a missing one.
    """
    unresolved: list[str] = []

    def walk(inc: Any, cur: Any, path: tuple[str, ...], prefix: tuple[str, ...], trail: str):
        if not path:
            return
        head, rest = path[0], path[1:]

        if head == "*":
            key = LIST_KEYS.get(prefix)  # the container sits at `prefix`
            if isinstance(inc, list):
                for index, item in enumerate(inc):
                    ident = item.get(key) if key and isinstance(item, dict) else None
                    walk(
                        item,
                        _counterpart(item, cur, key),
                        rest,
                        prefix + ("*",),
                        f"{trail}[{ident if ident is not None else index}]",
                    )
            elif isinstance(inc, dict):  # keyed containers match on their own key
                for name, item in inc.items():
                    child = cur.get(name) if isinstance(cur, dict) else None
                    walk(item, child, rest, prefix + ("*",), f"{trail}[{name}]")
            return

        if not isinstance(inc, dict) or head not in inc:
            return
        label = f"{trail}.{head}" if trail else head

        if not rest:
            if inc.get(head) != REDACTED:
                return
            value = cur.get(head) if isinstance(cur, dict) else None
            if value:
                inc[head] = value
            else:
                inc[head] = ""
                unresolved.append(label)
            return

        walk(
            inc[head],
            cur.get(head) if isinstance(cur, dict) else None,
            rest,
            prefix + (head,),
            label,
        )

    for path in SECRET_PATHS:
        walk(incoming, current, path, (), "")
    return incoming, unresolved


# ------------------------------------------------------------------ crypto


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise UnsupportedFormat(f"{field} is missing or not a string")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise UnsupportedFormat(f"{field} is not valid base64") from exc


def _canonical_header(envelope: dict) -> bytes:
    """The envelope minus the ciphertext, canonically serialized — used as AEAD
    associated data so the header cannot be edited after the fact."""
    header = {k: v for k, v in envelope.items() if k != "ciphertext"}
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode()


def _derive(passphrase: str, salt: bytes, *, n: int, r: int, p: int, length: int) -> bytes:
    return Scrypt(salt=salt, length=length, n=n, r=r, p=p).derive(passphrase.encode())


def _check_kdf(kdf: Any) -> tuple[int, int, int, int, bytes]:
    if not isinstance(kdf, dict) or kdf.get("name") != "scrypt":
        raise UnsupportedFormat("unsupported key derivation function")
    try:
        n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
        length = int(kdf["length"])
    except (KeyError, TypeError, ValueError) as exc:
        raise UnsupportedFormat("malformed kdf parameters") from exc
    # bound the work *before* deriving
    if not (0 < n <= _MAX_N) or n & (n - 1):
        raise UnsupportedFormat("kdf parameter n out of range or not a power of two")
    if not (0 < r <= _MAX_R) or not (0 < p <= _MAX_P) or length != _KEY_LEN:
        raise UnsupportedFormat("kdf parameters out of range")
    return n, r, p, length, _unb64(kdf.get("salt"), "kdf.salt")


# ------------------------------------------------------------------ public


def export_filename(app_version: str, encrypted: bool, when: datetime | None = None) -> str:
    when = when or datetime.now(UTC)
    kind = "encrypted" if encrypted else "redacted"
    return f"netbox-monitor-config-{app_version}-{kind}-{when:%Y%m%d-%H%M}.json"


def export_config(
    config: AppConfig, *, passphrase: str | None, app_version: str = __version__
) -> bytes:
    """Serialize ``config`` into a transfer envelope.

    ``passphrase=None`` produces the redacted mode; a passphrase produces the
    encrypted mode. An empty string is an error rather than a silent downgrade to
    redacted — that would hand back a file the caller believes holds their tokens.
    """
    if passphrase is not None and len(passphrase) < MIN_PASSPHRASE:
        raise ConfigTransferError(f"passphrase must be at least {MIN_PASSPHRASE} characters")

    payload = config.model_dump(mode="json")
    payload.pop("webui", None)  # never leaves the instance
    payload["schema_version"] = CONFIG_SCHEMA_VERSION

    envelope: dict[str, Any] = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "app_version": app_version,
        "config_schema": CONFIG_SCHEMA_VERSION,
        "encrypted": passphrase is not None,
        "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    if passphrase is None:
        envelope["config"] = redact(payload)
        return json.dumps(envelope, indent=2).encode()

    salt, nonce = os.urandom(16), os.urandom(12)
    envelope["kdf"] = {
        "name": "scrypt",
        "n": _SCRYPT_N,
        "r": _SCRYPT_R,
        "p": _SCRYPT_P,
        "length": _KEY_LEN,
        "salt": _b64(salt),
    }
    envelope["cipher"] = {"name": "aes-256-gcm", "nonce": _b64(nonce)}
    key = _derive(passphrase, salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, length=_KEY_LEN)
    ciphertext = AESGCM(key).encrypt(
        nonce, json.dumps(payload).encode(), _canonical_header(envelope)
    )
    envelope["ciphertext"] = _b64(ciphertext)
    return json.dumps(envelope, indent=2).encode()


def peek(blob: bytes) -> dict:
    """The envelope header, without decrypting anything."""
    try:
        envelope = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UnsupportedFormat("not a JSON config export") from exc
    if not isinstance(envelope, dict) or envelope.get("format") != FORMAT:
        raise UnsupportedFormat("not a netbox-monitor config export")
    if int(envelope.get("format_version", 0)) > FORMAT_VERSION:
        raise UnsupportedFormat(
            f"export format version {envelope.get('format_version')} is newer than this "
            f"build supports ({FORMAT_VERSION}) — upgrade netbox-monitor"
        )
    return envelope


def import_config(blob: bytes, *, passphrase: str | None, current: AppConfig) -> ImportResult:
    """Parse, decrypt, migrate and merge an export into a usable config.

    ``current`` supplies the values behind redacted secrets and the ``webui``
    section; it is never mutated.
    """
    envelope = peek(blob)
    encrypted = bool(envelope.get("encrypted"))
    source_schema = int(envelope.get("config_schema", CONFIG_SCHEMA_VERSION))

    # refuse a newer schema from the cleartext header, before spending any KDF work
    if source_schema > CONFIG_SCHEMA_VERSION:
        raise ConfigSchemaTooNewError(source_schema, CONFIG_SCHEMA_VERSION)

    if encrypted:
        if not passphrase:
            raise ConfigTransferError("this export is encrypted — a passphrase is required")
        n, r, p, length, salt = _check_kdf(envelope.get("kdf"))
        cipher = envelope.get("cipher")
        if not isinstance(cipher, dict) or cipher.get("name") != "aes-256-gcm":
            raise UnsupportedFormat("unsupported cipher")
        nonce = _unb64(cipher.get("nonce"), "cipher.nonce")
        ciphertext = _unb64(envelope.get("ciphertext"), "ciphertext")
        key = _derive(passphrase, salt, n=n, r=r, p=p, length=length)
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, _canonical_header(envelope))
        except InvalidTag as exc:
            raise BadPassphrase("wrong passphrase, or the file is corrupt") from exc
        raw = json.loads(plaintext.decode())
    else:
        if passphrase:
            log.info("passphrase ignored: this export is not encrypted")
        raw = envelope.get("config")
        if not isinstance(raw, dict):
            raise UnsupportedFormat("export contains no config")

    payload_schema = int(raw.get("schema_version", source_schema))
    if payload_schema != source_schema:
        raise UnsupportedFormat(
            f"envelope declares schema {source_schema} but the config says {payload_schema}"
        )

    # Migrate BEFORE merging: SECRET_PATHS describes the *current* schema only, so
    # an older payload has to be brought up to it before its secrets can be located.
    raw = migrate_to_current(raw)
    current_dump = current.model_dump(mode="json")
    raw, unresolved = merge_redacted(raw, current_dump)

    # webui is instance-local. Belt and braces on top of the export-side pop: an
    # imported password_hash + session_secret would be an instant admin handover.
    raw["webui"] = current_dump["webui"]

    return ImportResult(
        config=AppConfig.model_validate(raw),
        encrypted=encrypted,
        source_app_version=str(envelope.get("app_version", "unknown")),
        source_schema=source_schema,
        migrated_from=source_schema if source_schema != CONFIG_SCHEMA_VERSION else None,
        unresolved_secrets=tuple(unresolved),
    )
