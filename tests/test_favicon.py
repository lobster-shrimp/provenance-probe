"""Favicon route (#favicon): serves the lie-detector SVG as a real endpoint so
pages NOT rendered through ui.doc() (e.g. the agent flight-recorder report) and
direct browser /favicon.ico requests resolve it instead of 404-ing.
"""
from __future__ import annotations

import pytest

from provenance_probe import serve, ui


@pytest.mark.unit
@pytest.mark.parametrize("path", ["/favicon.ico", "/favicon.svg"])
def test_favicon_route_serves_the_svg(path):
    r = serve.app.test_client().get(path)
    assert r.status_code == 200
    assert r.mimetype == "image/svg+xml"
    body = r.get_data(as_text=True)
    assert body == ui.FAVICON_SVG
    assert body.startswith("<svg") and "#D2483F" in body  # coral polygraph stroke


@pytest.mark.unit
def test_favicon_is_still_behind_the_auth_gate_when_enabled(monkeypatch):
    # The route is NOT allowlisted out of the basic-auth gate: with auth on, an
    # unauthenticated favicon request 401s like any other route (an authenticated
    # browser sends its cached creds and gets 200).
    monkeypatch.setattr(serve, "_BASIC_AUTH", ("u", "p"))
    r = serve.app.test_client().get("/favicon.ico")
    assert r.status_code == 401
