"""Client for the netbox-secrets plugin: fetch per-device credentials from NetBox.

Flow: POST our RSA private key to /api/plugins/secrets/session-keys/ to obtain a
session key, then read secrets with the X-Session-Key header so NetBox returns
plaintext values.

Convention (documented in README):
- secret role ``snmp``: plaintext is the SNMP community string
- secret role ``ssh``:  secret *name* is the SSH username, plaintext is the password
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx
import structlog

log = structlog.get_logger(__name__)


@dataclass
class DeviceSecrets:
    snmp_community: str | None = None
    ssh_username: str | None = None
    ssh_password: str | None = None


class SecretsClient:
    def __init__(self, netbox_url: str, token: str, private_key_path: str, verify_ssl: bool = True):
        self.base = netbox_url.rstrip("/")
        self.token = token
        self.private_key_path = private_key_path
        self._session_key: str | None = None
        self._client = httpx.AsyncClient(timeout=30.0, verify=verify_ssl)

    async def close(self) -> None:
        await self._client.aclose()

    @property
    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Token {self.token}"}

    async def _ensure_session_key(self) -> str:
        if self._session_key:
            return self._session_key
        private_key = Path(self.private_key_path).read_text(encoding="utf-8")
        resp = await self._client.post(
            f"{self.base}/api/plugins/secrets/session-keys/",
            headers=self._auth_headers,
            json={"private_key": private_key, "preserve_key": True},
        )
        resp.raise_for_status()
        self._session_key = resp.json()["session_key"]
        log.info("netbox-secrets session key obtained")
        return self._session_key

    async def get_device_secrets(self, device_id: int) -> DeviceSecrets:
        secrets = DeviceSecrets()
        try:
            session_key = await self._ensure_session_key()
        except FileNotFoundError:
            log.warning("secrets private key file missing", path=self.private_key_path)
            return secrets
        except httpx.HTTPError as exc:
            log.warning("netbox-secrets session key request failed", error=str(exc))
            return secrets

        resp = await self._client.get(
            f"{self.base}/api/plugins/secrets/secrets/",
            headers={**self._auth_headers, "X-Session-Key": session_key},
            params={
                "assigned_object_type": "dcim.device",
                "assigned_object_id": device_id,
            },
        )
        if resp.status_code == 403:
            # session key may have expired server-side; retry once with a fresh one
            self._session_key = None
            session_key = await self._ensure_session_key()
            resp = await self._client.get(
                f"{self.base}/api/plugins/secrets/secrets/",
                headers={**self._auth_headers, "X-Session-Key": session_key},
                params={
                    "assigned_object_type": "dcim.device",
                    "assigned_object_id": device_id,
                },
            )
        resp.raise_for_status()
        for secret in resp.json().get("results", []):
            role = (secret.get("role") or {}).get("slug", "")
            plaintext = secret.get("plaintext")
            if plaintext is None:
                continue
            if role == "snmp":
                secrets.snmp_community = plaintext
            elif role == "ssh":
                secrets.ssh_username = secret.get("name") or "admin"
                secrets.ssh_password = plaintext
        return secrets
