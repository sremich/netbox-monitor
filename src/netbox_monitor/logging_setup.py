"""Structured logging configuration."""

from __future__ import annotations

import logging
import re
import sys

import structlog

# defense-in-depth: scrub anything that looks like an inline secret from log output,
# regardless of which code path produced it (query params, headers, error strings).
# Two patterns keep it precise (no false positives on prose like "token was rotated"):
#   - key=value / key: value for known secret keys
#   - HTTP auth schemes: "Bearer <token>", "Token <token>"
_KV_RE = re.compile(
    r"(?i)(token|password|passwd|secret|community|api[_-]?key|session[_-]?key)"
    r"(\s*[=:]\s*)"
    r"([^\s,&'\"}\]]+)"
)
_SCHEME_RE = re.compile(r"(?i)\b(bearer|token)(\s+)([A-Za-z0-9._\-|!+/=]{8,})")


def _redact(value: str) -> str:
    value = _KV_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}***", value)
    value = _SCHEME_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}***", value)
    return value


def _redact_processor(_logger, _method, event_dict):
    for key, val in list(event_dict.items()):
        if isinstance(val, str) and ("=" in val or ":" in val or " " in val):
            event_dict[key] = _redact(val)
    return event_dict


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )
    # httpx logs full request URLs at INFO — those carry ?token=... query params
    # for the Technitium API. Silence it so secrets never reach the logs.
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            _redact_processor,
            structlog.dev.ConsoleRenderer()
            if sys.stdout.isatty()
            else structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )
