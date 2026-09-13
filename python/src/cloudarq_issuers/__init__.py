"""A census of the OIDC issuers a cloud will federate to for workload identity.

No dependencies, no network calls. The data is a snapshot taken on
``CENSUS_DATE``; it is not a live view.

Four fields are not published anywhere else, and three of them exist because the
obvious reading of the data is wrong:

``aud_controlled_by``
    Who picks the ``aud`` value. When it is ``"workload"``, ``aud`` is not a
    boundary: anyone who can run a job on that platform can request a token
    carrying your audience. Sixteen entries here are in that state, GitHub
    Actions among them.

``vendor_example_verdict``
    What the vendor's own documented example actually admits, because a
    documentation example is what ends up deployed.

``control_test``
    What a deliberately bogus tenant returned. AWS serves a complete,
    well-formed discovery document for a UUID invented at random; only the JWKS
    refuses it. A discovery document is not proof a tenant exists.

``immutable_id_claims``
    Empty for most entries, which means every subject written against them is a
    recyclable name.

Anything nobody confirmed says ``"unverified"``. That never means ``"absent"``.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping, Optional

__all__ = [
    "CENSUS_DATE",
    "issuers",
    "get",
    "multi_tenant_hosts",
    "audience_is_boundary",
    "subjects_are_recyclable",
    "host_of",
]

__version__ = "0.1.0"

_DATA = Path(__file__).with_name("issuers.json")


@lru_cache(maxsize=1)
def _census() -> Mapping[str, Any]:
    with _DATA.open(encoding="utf-8") as fh:
        return json.load(fh)


def host_of(issuer_or_url: str) -> str:
    """The bare hostname of an issuer URL: no scheme, no path, lowercased."""
    h = issuer_or_url.removeprefix("https://").removeprefix("http://")
    return h.split("/", 1)[0].lower()


@lru_cache(maxsize=1)
def _by_host() -> Mapping[str, Mapping[str, Any]]:
    out = {}
    for e in _census()["issuers"]:
        u = e.get("issuer") or e.get("issuer_pattern") or ""
        if u:
            out[host_of(u)] = e
    return out


CENSUS_DATE: str = _census()["census_date"]


def issuers() -> tuple[Mapping[str, Any], ...]:
    """Every entry in the census."""
    return tuple(_census()["issuers"])


def get(host_or_url: str) -> Optional[Mapping[str, Any]]:
    """Look an issuer up by hostname or by full issuer URL.

    Returns ``None`` when the host is not in the census, which means nobody has
    surveyed it. It does not mean the host is safe.
    """
    return _by_host().get(host_of(host_or_url))


def multi_tenant_hosts() -> frozenset[str]:
    """Hostnames of issuers shared between the tenants of one vendor.

    A token from any tenant of these carries the same ``iss``, so conditioning on
    the issuer alone does not identify a tenant. Drop-in for a hard-coded set of
    the same shape.
    """
    return frozenset(
        host_of(e.get("issuer") or e.get("issuer_pattern") or "")
        for e in _census()["issuers"]
        if e.get("tenancy_model") in ("shared", "per_tenant_path")
        and (e.get("issuer") or e.get("issuer_pattern"))
    )


def audience_is_boundary(host_or_url: str) -> Optional[bool]:
    """Does conditioning on ``aud`` constrain anything for this issuer?

    ``True``  -- the relying party or the issuer fixes it.
    ``False`` -- the workload picks it, so ``aud`` constrains nothing.
    ``None``  -- nobody confirmed it, or the host is not in the census.

    ``None`` must not be read as ``True``. A caller that treats an unknown as a
    boundary has widened its own trust without noticing.
    """
    e = get(host_or_url)
    if e is None:
        return None
    v = e.get("aud_controlled_by")
    if v == "workload":
        return False
    if v in ("relying_party", "issuer"):
        return True
    return None


def subjects_are_recyclable(host_or_url: str) -> Optional[bool]:
    """Does this issuer offer no immutable identifier at all?

    When ``True``, every subject written against it is a name that can be
    released and re-registered by someone else. ``None`` when the host is not in
    the census.
    """
    e = get(host_or_url)
    if e is None:
        return None
    return not e.get("immutable_id_claims")
