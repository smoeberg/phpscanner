"""Regression tests for probe-level HTTP client network policy."""

import asyncio

import httpx

from app import main


def test_probe_disables_environment_proxies_and_does_not_follow_redirects(monkeypatch):
    observed = {"requests": [], "client_options": []}

    async def handler(request):
        observed["requests"].append(request)
        return httpx.Response(
            302,
            headers={"location": "https://redirect-target.example/"},
        )

    real_async_client = httpx.AsyncClient

    def client_with_recorded_options(*args, **kwargs):
        observed["client_options"].append(
            {
                "trust_env": kwargs.get("trust_env"),
                "follow_redirects": kwargs.get("follow_redirects"),
            }
        )
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    async def fake_resolve_public_ips(_domain):
        return ["8.8.8.8"]

    monkeypatch.setattr(main, "resolve_public_ips_async", fake_resolve_public_ips)
    monkeypatch.setattr(main.httpx, "AsyncClient", client_with_recorded_options)

    result = asyncio.run(main.probe("example.com"))

    assert observed["client_options"] == [
        {"trust_env": False, "follow_redirects": False}
    ]
    assert len(observed["requests"]) == 1
    assert str(observed["requests"][0].url) == "https://example.com/"
    assert result["status_code"] == 302
    assert result["final_url"] == "https://example.com/"
    assert "redirects følges ikke" in result["notes"]
