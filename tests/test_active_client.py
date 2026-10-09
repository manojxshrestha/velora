"""Active client unit tests: scope refusal, inert default, rate, budget, redaction.

All network is loopback (tests/blackbox_fixture.py) — no external hosts.
"""

from __future__ import annotations

import json

import pytest

from tests.blackbox_fixture import fixture_env
from velora.active.client import (
    BudgetExhausted,
    HttpClient,
    InertVerbRefused,
    ScopeRefused,
    format_reqresp,
    host_of,
    normalize_host,
    normalize_url,
    origin_of,
)


@pytest.fixture
def app():
    with fixture_env() as env:
        yield env


class TestNormalizeHelpers:
    def test_normalize_host_urls_and_bare(self):
        assert normalize_host("https://Example.COM:8443/path") == "example.com"
        assert normalize_host("example.com:8080") == "example.com"
        assert normalize_host("example.com") == "example.com"
        assert normalize_host("  ") == ""

    def test_host_of_and_origin(self):
        assert host_of("http://127.0.0.1:8080/x") == "127.0.0.1"
        assert origin_of("http://127.0.0.1:8080/x") == "http://127.0.0.1:8080"
        assert origin_of("https://a.test/p") == "https://a.test"

    def test_normalize_url_drops_fragment_and_normalizes(self):
        assert normalize_url("http://A.test/x#frag") == "http://a.test/x"
        assert normalize_url("http://a.test") == "http://a.test/"
        assert normalize_url("http://a.test:80/x") == "http://a.test/x"
        assert normalize_url("http://a.test/x?a=1#z") == "http://a.test/x?a=1"


class TestScopeEnforcement:
    def test_request_outside_allowlist_refused_before_send(self, app):
        client = HttpClient({"127.0.0.1"})
        with pytest.raises(ScopeRefused):
            client.get(f"http://localhost:{app.port}/")
        assert app.log == []  # nothing was sent

    def test_in_scope_request_allowed(self, app):
        client = HttpClient({"127.0.0.1"})
        resp = client.get(f"{app.base_url}/")
        assert resp.status == 200
        assert client.requests_made == 1

    def test_redirect_hop_off_allowlist_refused(self, app):
        client = HttpClient({"127.0.0.1"})
        with pytest.raises(ScopeRefused) as exc:
            client.get(f"{app.base_url}/offscope")
        # the first hop was sent; the localhost redirect never was
        assert app.paths.count("/offscope") == 1
        assert app.paths.count("/") == 0
        assert "localhost" in exc.value.url

    def test_same_origin_redirect_followed(self, app):
        client = HttpClient({"127.0.0.1"})
        resp = client.get(f"{app.base_url}/redir")
        assert resp.status == 200
        assert "redirected" in resp.final_url
        assert app.paths.count("/search") == 1


class TestInertDefault:
    def test_post_refused_without_active(self, app):
        client = HttpClient({"127.0.0.1"})
        with pytest.raises(InertVerbRefused):
            client.request("POST", f"{app.base_url}/login", data=b"a=b")
        assert "POST" not in app.methods

    def test_post_allowed_with_active(self, app):
        client = HttpClient({"127.0.0.1"}, allow_active=True)
        resp = client.request("POST", f"{app.base_url}/login", data=b"user=x")
        assert resp.status == 200
        assert "POST" in app.methods

    def test_inert_verbs_always_allowed(self, app):
        client = HttpClient({"127.0.0.1"})
        assert client.get(f"{app.base_url}/").status == 200
        assert client.request("HEAD", f"{app.base_url}/").status == 200
        assert client.request("OPTIONS", f"{app.base_url}/").status == 200


class TestBudgetAndRate:
    def test_budget_exhaustion_raises_after_limit(self, app):
        client = HttpClient({"127.0.0.1"}, budget=2)
        assert client.get(f"{app.base_url}/").status == 200
        assert client.get(f"{app.base_url}/robots.txt").status == 200
        with pytest.raises(BudgetExhausted):
            client.get(f"{app.base_url}/sitemap.xml")
        assert client.budget_exhausted is True
        assert client.remaining_budget() == 0

    def test_budget_counts_redirect_hops(self, app):
        client = HttpClient({"127.0.0.1"}, budget=1)
        with pytest.raises(BudgetExhausted):
            client.get(f"{app.base_url}/redir")  # hop 2 exceeds budget=1

    def test_default_budget_is_the_plan_cap(self, app):
        from velora.active.client import DEFAULT_BUDGET

        assert DEFAULT_BUDGET == 500

    def test_rate_cap_spaces_requests(self, app):
        t = [0.0]
        sleeps = []

        def fake_sleep(seconds):
            sleeps.append(seconds)
            t[0] += seconds

        client = HttpClient(
            {"127.0.0.1"}, rate=10, sleep=fake_sleep, clock=lambda: t[0],
        )
        client.get(f"{app.base_url}/")
        client.get(f"{app.base_url}/robots.txt")
        assert sleeps, "second request must wait for the rate limiter"
        assert sleeps[0] == pytest.approx(0.1, abs=0.001)

    def test_rate_zero_disables_sleep(self, app):
        client = HttpClient({"127.0.0.1"}, rate=0)
        client.get(f"{app.base_url}/")
        client.get(f"{app.base_url}/")
        assert client.requests_made == 2


class TestEvidenceAndRedaction:
    def test_authorization_value_never_recorded(self, app):
        client = HttpClient(
            {"127.0.0.1"}, headers={"Authorization": "Bearer sekret-token-42"}
        )
        client.get(f"{app.base_url}/")
        entry = client.evidence[0]
        assert entry["request_headers"]["Authorization"] == "***"
        dumped = json.dumps(client.export_evidence())
        assert "sekret-token-42" not in dumped

    def test_set_cookie_value_redacted_but_flags_kept(self, app):
        client = HttpClient({"127.0.0.1"})
        client.get(f"{app.base_url}/login")
        entry = client.evidence[-1]
        cookie = entry["response_headers"]["set-cookie"]
        assert "fixture-secret-abc" not in cookie
        assert "***" in cookie
        assert "Path=/" in cookie
        assert "fixture-secret-abc" not in json.dumps(client.export_evidence())

    def test_error_response_is_not_an_exception(self, app):
        client = HttpClient({"127.0.0.1"})
        resp = client.get(f"{app.base_url}/swagger.json")
        assert resp.status == 404
        assert resp.ok is False

    def test_network_error_captured_not_raised(self):
        client = HttpClient({"127.0.0.1"}, budget=500)
        resp = client.get("http://127.0.0.1:1/")  # closed port
        assert resp.status == 0
        assert resp.error


class TestFormatReqresp:
    def test_formats_request_and_response_strings(self, app):
        client = HttpClient({"127.0.0.1"})
        client.get(f"{app.base_url}/robots.txt")
        req, resp = format_reqresp(client.evidence[0])
        assert req.startswith("GET http://127.0.0.1")
        assert "HTTP 200" in resp
        assert "Disallow" in resp
