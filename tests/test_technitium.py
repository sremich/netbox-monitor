"""Technitium client: the token must never appear in a URL or in error messages,
and log output is redacted as defense-in-depth."""

import httpx
import pytest

from netbox_monitor.clients.technitium import TechnitiumClient, TechnitiumError
from netbox_monitor.config import TechnitiumConfig
from netbox_monitor.logging_setup import _redact, _redact_processor

TOKEN = "supersecrettoken1234567890abcdef"


def _client(handler) -> TechnitiumClient:
    c = TechnitiumClient(TechnitiumConfig(url="http://dns.test:5380", token=TOKEN))
    c._client = httpx.AsyncClient(
        base_url="http://dns.test:5380",
        transport=httpx.MockTransport(handler),
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    return c


async def test_token_sent_as_header_not_in_url():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"status": "ok", "response": {"zones": []}})

    c = _client(handler)
    await c.list_zones()
    await c.close()
    assert TOKEN not in seen["url"]  # never in the URL
    assert "token=" not in seen["url"]
    assert seen["auth"] == f"Bearer {TOKEN}"


async def test_http_error_message_has_no_token_or_url():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    c = _client(handler)
    with pytest.raises(TechnitiumError) as exc:
        await c._call("/api/zones/list")
    await c.close()
    message = str(exc.value)
    assert TOKEN not in message
    assert "http://dns.test" not in message
    assert "HTTP 500" in message


async def test_json_status_error_has_no_token():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "invalid-token"})

    c = _client(handler)
    with pytest.raises(TechnitiumError) as exc:
        await c._call("/api/zones/list")
    await c.close()
    assert TOKEN not in str(exc.value)


def test_redaction_scrubs_secrets():
    assert _redact(f"url?token={TOKEN}&x=1") == "url?token=***&x=1"
    assert TOKEN not in _redact(f"Authorization: Bearer {TOKEN}")
    assert _redact("password=hunter2") == "password=***"
    assert _redact("community: public") == "community: ***"
    # non-secret text is untouched
    assert _redact("just a normal message") == "just a normal message"


def test_redact_processor_cleans_event_dict():
    event = {"event": "sync failed", "error": f"GET /api?token={TOKEN} -> 500"}
    out = _redact_processor(None, None, event)
    assert TOKEN not in out["error"]
    assert out["event"] == "sync failed"
