"""Password hashing (stdlib PBKDF2) and signed session cookies."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from itsdangerous import BadSignature, URLSafeTimedSerializer

ITERATIONS = 300_000
SESSION_COOKIE = "nbm_session"
SESSION_MAX_AGE = 7 * 24 * 3600


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS).hex()
    return f"pbkdf2${ITERATIONS}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _scheme, iterations, salt, digest = stored.split("$")
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), int(iterations)
        ).hex()
        return hmac.compare_digest(candidate, digest)
    except (ValueError, AttributeError):
        return False


def make_session_token(secret: str) -> str:
    return URLSafeTimedSerializer(secret, salt="nbm-session").dumps({"auth": True})


def check_session_token(secret: str, token: str | None) -> bool:
    if not token:
        return False
    try:
        data = URLSafeTimedSerializer(secret, salt="nbm-session").loads(
            token, max_age=SESSION_MAX_AGE
        )
        return bool(data.get("auth"))
    except BadSignature:
        return False
