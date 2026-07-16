"""Shared SSH connection helper tolerant of legacy switch crypto.

Modern switches negotiate fine with asyncssh defaults. Older Cisco/Aruba gear
only offers deprecated kex/host-key/cipher/MAC algorithms; we retry those on a
handshake failure so a single helper works across the whole fabric.
"""

from __future__ import annotations

import asyncssh
import structlog

log = structlog.get_logger(__name__)

# broad legacy set observed on old Cisco IOS / ArubaOS-Switch
_LEGACY = dict(
    server_host_key_algs=[
        "ssh-ed25519",
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-rsa",
        "ssh-dss",
    ],
    kex_algs=[
        "curve25519-sha256",
        "ecdh-sha2-nistp256",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group-exchange-sha1",
    ],
    encryption_algs=[
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "3des-cbc",
    ],
    mac_algs=[
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-sha1",
        "hmac-md5",
    ],
)


async def legacy_connect(host: str, username: str, password: str, timeout: float = 10.0):
    """Open an SSH connection, retrying with legacy algorithms on handshake failure.

    Returns an ``asyncssh`` connection (use as an async context manager).
    """
    base = dict(
        known_hosts=None,  # switch host keys are unmanaged in a homelab
        username=username,
        password=password,
        connect_timeout=timeout,
    )
    try:
        return await asyncssh.connect(host, **base)
    except (asyncssh.Error, OSError) as exc:
        log.debug(
            "modern SSH handshake failed; retrying legacy algorithms", host=host, error=str(exc)
        )
        return await asyncssh.connect(host, **base, **_LEGACY)


async def run_command(conn, command: str, timeout: float = 20.0) -> str:
    """Run one command over an open connection and return combined stdout/stderr."""
    import asyncio

    result = await asyncio.wait_for(conn.run(command, check=False), timeout=timeout)
    return (result.stdout or "") + (result.stderr or "")
