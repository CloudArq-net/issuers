"""Checks on scripts/drift.py, the daily re-fetch, run against a census of its
own and a fetch that records every URL it is asked for instead of reaching the
network.

They sit beside the package's tests because ``make test`` runs this directory.
The source distribution leaves this file out (pyproject.toml): it needs
scripts/drift.py, which the distribution does not carry.
"""

import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

DISCOVERY = "https://issuer.example/.well-known/openid-configuration"
JWKS = "https://issuer.example/jwks"


def load_drift():
    spec = importlib.util.spec_from_file_location("drift", REPO / "scripts" / "drift.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def census(tmp_path):
    """A census of one verified entry, and a drift module that reads it and
    fetches through `served`, a map from URL to (status, document)."""
    entry = {"name": "Example CI", "discovery_status": "ok", "discovery_url": DISCOVERY,
             "jwks_uri": JWKS, "jwks_status": "ok", "claims_advertised": ["sub", "aud"]}
    (tmp_path / "issuers.json").write_text(json.dumps({"issuers": [entry]}), encoding="utf-8")
    drift = load_drift()
    drift.ROOT = tmp_path
    fetched = []

    def serve(served):
        def fetch(url):
            fetched.append(url)
            status, doc = served.get(url, (404, None))
            return status, None if doc is None else json.dumps(doc).encode()
        drift.fetch = fetch
        return drift

    return serve, fetched


def test_the_recorded_jwks_uri_is_the_one_fetched(census, capsys):
    serve, fetched = census
    drift = serve({DISCOVERY: (200, {"jwks_uri": JWKS, "claims_supported": ["sub", "aud"]}), JWKS: (200, {"keys": []})})
    assert drift.main() == 0
    assert fetched == [DISCOVERY, JWKS]
    assert "no drift" in capsys.readouterr().out


def test_a_moved_jwks_uri_is_reported_and_never_fetched(census, capsys):
    """The discovery document is the issuer's to change, and a runner holding
    an issues: write token fetches only what the census recorded."""
    serve, fetched = census
    moved = "https://elsewhere.example/keys"
    drift = serve({DISCOVERY: (200, {"jwks_uri": moved, "claims_supported": ["sub", "aud"]}), JWKS: (200, {"keys": []}),
                   moved: (200, {"keys": []})})
    assert drift.main() == 1
    assert moved not in fetched, f"fetched {fetched}"
    assert fetched == [DISCOVERY, JWKS]
    out = capsys.readouterr().out
    assert "jwks_uri moved" in out and moved in out


def test_what_an_issuer_serves_reaches_the_issue_as_plain_text(census, capsys):
    """The drift report becomes the body of an issue inside a code fence. A
    value the issuer serves carrying a backtick could close the fence and a
    control character could rewrite a terminal, so neither is passed on."""
    serve, fetched = census
    hostile = "https://x.example/```\n[click](https://x.example)\x1b[2K\u009b31m"
    drift = serve({DISCOVERY: (200, {"jwks_uri": hostile, "claims_supported": ["sub", "aud", "a`b", "c\nd"]}),
                   JWKS: (200, {"keys": []})})
    assert drift.main() == 1
    out = capsys.readouterr().out
    assert "`" not in out, out
    controls = sorted({hex(ord(c)) for c in out if c != "\n" and (ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F)})
    assert not controls, f"control characters {controls} in:\n{out}"
    assert not any(line.startswith("[click]") for line in out.splitlines()), out
