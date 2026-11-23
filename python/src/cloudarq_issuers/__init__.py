"""A census of the OIDC issuers a cloud will federate to for workload identity.

No dependencies, no network calls. The data is a snapshot taken on
``CENSUS_DATE``; it is not a live view. Facts added later carry their own
``verified_at``.

Four fields carry most of the weight, and three of them exist because the obvious
reading of the data is wrong:

``aud_controlled_by``
    Who picks the ``aud`` value. When it is ``"workload"``, ``aud`` is not a
    boundary: anyone who can run a job on that platform can request a token
    carrying your audience. Seventeen entries here are in that state, GitHub
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

The tenancy fields answer who can hold a token an issuer mints: whether it
mints them to people with no account (``anonymous_tokens``), which claims and
subject forms name a tenant (``tenancy_claims``, ``subject_forms``,
``owner_charset``, ``repository_charset``), which claims look like tenants and
are not (``not_tenancy``), and, for an issuer whose URL names the tenant, how
to read it (``match``, ``tenant_membership``). ``aws_condition_keys`` and
``aws_identity_provider_controls`` say how AWS reads a trust policy that trusts
the issuer. Each value rests on vendor sentences kept beside it, with their
source and the date they were read. ``match()`` finds an
issuer's entry and its tenant.

Anything nobody confirmed says ``"unverified"``. In a tenancy field it means
exactly that no vendor sentence establishes the value in this release, whatever
the reason, and ``researched`` says whether this release looked at all. It
never means ``"absent"``.
"""

from __future__ import annotations

import copy
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping, NamedTuple, Optional

from . import _tenancy

__all__ = [
    "CENSUS_DATE",
    "Answer",
    "issuers",
    "get",
    "match",
    "tenancy",
    "multi_tenant_hosts",
    "audience_is_boundary",
    "subjects_are_recyclable",
    "issues_anonymous_tokens",
    "controlled_tenant",
    "tenant_is_recyclable",
    "claim_is_recyclable",
    "aws_maps_condition_key",
    "aws_condition_key",
    "aws_condition_key_is_multivalued",
    "claim_is_multi_valued",
    "owner_name_may_contain",
    "repository_name_may_contain",
    "names_compare_without_case",
    "host_of",
]

__version__ = "0.2.0"

_DATA = Path(__file__).with_name("issuers.json")


@lru_cache(maxsize=1)
def _census() -> Mapping[str, Any]:
    with _DATA.open(encoding="utf-8") as fh:
        return json.load(fh)


def host_of(issuer_or_url: str) -> str:
    """The bare hostname of an issuer URL: no scheme, no path, its ASCII
    letters lowercased. Only ASCII letters fold, as in the Go package:
    ``str.lower`` also folds the Kelvin sign onto ``k``, which would let a
    look-alike host pass for a census host."""
    h = issuer_or_url.removeprefix("https://").removeprefix("http://")
    return _tenancy.lower_ascii(h.split("/", 1)[0])


def _entry_host(e: Mapping[str, Any]) -> str:
    """An entry's host, lowercased, or ``""`` when its issuer field holds a note
    such as ``"unverified"`` rather than an issuer."""
    h = _tenancy.host_of_issuer(e.get("issuer") or "") or _tenancy.host_of_issuer(e.get("issuer_pattern") or "")
    return _tenancy.lower_ascii(h)


def _owns_host(e: Mapping[str, Any]) -> bool:
    """Whether the entry's issuer is its host alone, with no path."""
    u = (e.get("issuer") or "").removeprefix("https://")
    return u != "" and "/" not in u.removesuffix("/")


@lru_cache(maxsize=1)
def _by_host() -> Mapping[str, Mapping[str, Any]]:
    # Several entries can share a host, told apart by path. A lookup by host
    # alone answers with the host's own issuer, as it did before any host had
    # two entries, and otherwise with the first.
    out: dict = {}
    for e in _census()["issuers"]:
        h = _entry_host(e)
        if h and (h not in out or not _owns_host(out[h]) and _owns_host(e)):
            out[h] = e
    return out


@lru_cache(maxsize=1)
def _matcher() -> _tenancy.Matcher:
    items = []
    for e in _census()["issuers"]:
        rule = _tenancy.rule_of(e)
        if rule is not None:
            items.append((e, *rule))
    return _tenancy.compile_rules(items)


CENSUS_DATE: str = _census()["census_date"]


def issuers() -> tuple[Mapping[str, Any], ...]:
    """Every entry in the census, in census order.

    Every answer this module gives is the caller's own copy: edit it however
    deep, and the next answer is still the census's."""
    return tuple(copy.deepcopy(e) for e in _census()["issuers"])


def get(host_or_url: str) -> Optional[Mapping[str, Any]]:
    """Look an issuer up by hostname or by full issuer URL.

    Returns ``None`` when the host is not in the census, which means nobody has
    surveyed it. It does not mean the host is safe. When several entries share
    the host, it returns the one whose issuer is the host itself; ``match``
    reads the path as well.
    """
    e = _by_host().get(host_of(host_or_url))
    return None if e is None else copy.deepcopy(e)


def match(issuer: str) -> Optional[tuple[Mapping[str, Any], str]]:
    """Find the census entry for an issuer URL, as a token's ``iss`` or a trust
    policy's provider carries it, and the tenant the URL names (``""`` for an
    issuer that names none).

    Returns ``None`` when no entry matches, which means nobody surveyed that
    issuer: never that it is safe.

    An issuer is read with ``https://`` or with no scheme, its host compared
    without ASCII case and its path exactly, one trailing slash ignored. An
    exact issuer matches only itself. A pattern matches when every placeholder
    holds one non-empty host label of letters, digits and dashes, or one path
    segment of letters, digits, dashes and underscores, in the tenant's syntax
    where the census records one. Of several matching entries, the one with the
    most characters outside placeholders wins, and of those the first in census
    order. These are the Go ``tenancy.Match`` rules, held to the same cases.
    """
    got = _matcher().match(issuer)
    return None if got is None else (copy.deepcopy(got[0]), got[1])


def tenancy(entry: Mapping[str, Any]) -> dict:
    """The entry as a classifier reads it: the values a vendor sentence
    settles, and nothing unverified, multi-valued or of unknown cardinality, so
    that absent reads the cautious way. It is the Go ``Issuer.Tenancy`` and the
    data of the Go ``tenancy`` sub-package."""
    return _tenancy.projection(entry)


def multi_tenant_hosts() -> frozenset[str]:
    """Hostnames of issuers shared between the tenants of one vendor.

    A token from any tenant of these carries the same ``iss``, so conditioning on
    the issuer alone does not identify a tenant. Drop-in for a hard-coded set of
    the same shape. A host missing from the set is not thereby known to identify
    a tenant: its entry may be unverified, or not in the census at all.
    """
    return frozenset(
        _entry_host(e)
        for e in _census()["issuers"]
        if e.get("tenancy_model") in ("shared", "per_tenant_path") and _entry_host(e)
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


class Answer(NamedTuple):
    """A reader's answer and whether the census knows it, as the Go readers
    return them. When ``known`` is false, ``value`` is the cautious answer.

    An answer refuses to be read as true or false: a pair would be true
    whatever it says, which for a question whose cautious answer is false
    (is this tenant controlled?) is the wrong direction. Unpack it, or read
    ``value`` and ``known``.
    """

    value: bool
    known: bool

    def __bool__(self) -> bool:
        raise TypeError("an Answer is a (value, known) pair: unpack it, or read .value and .known")


def _yes_no(value: Any, cautious: bool) -> Answer:
    if value == "yes":
        return Answer(True, True)
    if value == "no":
        return Answer(False, True)
    return Answer(cautious, False)


def issues_anonymous_tokens(entry: Mapping[str, Any]) -> Answer:
    """Whether the issuer mints tokens to people with no account anywhere.
    Not known when the census has not verified it, and the answer beside it is
    then the cautious one, ``True``: an unverified issuer may."""
    return _yes_no(tenancy(entry).get("anonymous_tokens"), True)


def controlled_tenant(entry: Mapping[str, Any], tenant: str) -> Answer:
    """Whether the owner of ``tenant``, as ``match`` names it, controls who
    obtains tokens naming it. Known and false for a tenant the census lists as
    open to anyone, which its own sentence settles whatever the issuer's
    membership; not known for any other tenant when the census has not
    verified the issuer's membership."""
    t = tenancy(entry)
    if not tenant:
        return Answer(False, False)
    for open_tenant in t.get("not_a_controlled_tenant", []):
        # The listed tenants are GUIDs, whose letters are hex digits that name
        # the same tenant in either case.
        if _tenancy.lower_ascii(open_tenant) == _tenancy.lower_ascii(tenant):
            return Answer(False, True)
    if t.get("tenant_membership") != "controlled":
        return Answer(False, False)
    return Answer(True, True)


def tenant_is_recyclable(entry: Mapping[str, Any]) -> Answer:
    """Whether the tenant a matching issuer URL names can be released and
    taken by another customer, which would put that customer's tokens behind
    the same issuer. Not known when no vendor sentence settles it, and the
    answer beside it is then the cautious one, ``True``."""
    return _yes_no(tenancy(entry).get("tenant_recyclable"), True)


def claim_is_recyclable(entry: Mapping[str, Any], claim: str) -> Answer:
    """Whether a value of ``claim`` can be released and pass to someone else,
    which would put their tokens behind a trust that names it. Not known when
    no vendor sentence settles it, or when the entry does not list the claim
    as naming a tenant, and the answer beside it is then the cautious one,
    ``True``, whatever the claim's kind."""
    for c in tenancy(entry).get("tenancy_claims", []):
        if c["claim"] == claim:
            if c.get("immutable") == "yes":
                return Answer(False, True)
            if c.get("immutable") == "no":
                return Answer(True, True)
            break
    return Answer(True, False)


def aws_maps_condition_key(entry: Mapping[str, Any], key: str) -> Answer:
    """Whether AWS documents ``key`` as a condition key for this issuer, which
    is what puts a claim in the request context that a trust policy's
    condition on ``<provider>:<key>`` reads. Keys compare without ASCII case,
    as AWS reads them: "Context key names are not case-sensitive."
    (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html).
    Not known when the census does not record AWS's keys for the issuer, and
    the answer beside it is then the cautious one, ``False``: a condition on a
    key not known to be mapped is read as unread, which never pins and never
    narrows."""
    if not tenancy(entry).get("aws_condition_keys"):
        return Answer(False, False)
    return Answer(aws_condition_key(entry, key) is not None, True)


def aws_condition_key(entry: Mapping[str, Any], key: str) -> Optional[dict]:
    """AWS's record of ``key`` for this issuer: ``{"key", "claim"}``, with
    ``"fallback_claim"`` where AWS reads that claim when the token sets no
    value for ``"claim"``. The claim is not always the key's own name: on
    AWS's Default tab ``oaud`` reads ``aud``, and ``aud`` reads ``azp``, or
    ``aud`` when the token sets no ``azp``. It is written as AWS's table
    writes it, which for Login with Amazon and Facebook is a phrase such as
    ``"User ID"``. A record with no ``"claim"`` is a key whose claim no
    sentence says the issuer's tokens carry as AWS spells it, and
    ``"table_claim"`` holds that spelling: Google's reference nests the number
    AWS spells ``google:organization_number`` inside a ``google`` claim, so
    what a token carries for the key is not known. ``"multivalued": "yes"``
    marks a key AWS's sentence calls multivalued, read by
    ``aws_condition_key_is_multivalued``. Keys compare without ASCII
    case, as in ``aws_maps_condition_key``. ``None`` when AWS documents no
    such key for the issuer, or when the census does not record its keys:
    ``aws_maps_condition_key`` tells the two apart."""
    folded = _tenancy.lower_ascii(key)
    for k in tenancy(entry).get("aws_condition_keys", []):
        if _tenancy.lower_ascii(k["key"]) == folded:
            return k
    return None


def aws_condition_key_is_multivalued(entry: Mapping[str, Any], key: str) -> Answer:
    """Whether a request may carry several values for ``key``, as AWS says of
    amr: "The key is multivalued, meaning that you test it in a policy using
    condition set operators." An authenticated user's amr holds
    ``authenticated`` and the provider the user signed in with. Not known
    unless AWS's sentence says the key is multivalued: the census records no
    sentence saying a key holds one value, so an unknown answer is the
    cautious one, ``True``, since a key AWS has not said holds one value may
    hold several. Keys compare without ASCII case, as in
    ``aws_maps_condition_key``; a key AWS does not document for the issuer,
    or any key of an issuer whose keys are not recorded, is not known."""
    record = aws_condition_key(entry, key)
    return Answer(True, record is not None and record.get("multivalued") == "yes")


def claim_is_multi_valued(entry: Mapping[str, Any], claim: str) -> Answer:
    """Whether the issuer's tokens may carry several values in ``claim``, as
    Kubernetes says of a service account token's audience: "May be repeated
    to request a token valid for multiple audiences." Not known unless a
    sentence the census holds says they may, and the answer beside it is then
    the cautious one, ``True``. Claim names compare as written, as a token's
    do."""
    return Answer(True, claim in tenancy(entry).get("multi_valued_claims", []))


def names_compare_without_case(entry: Mapping[str, Any]) -> Answer:
    """Whether two owner names that differ only in case name one owner. When
    the census has not verified it, names compare exactly, which can only
    leave a name unmatched."""
    return _yes_no(tenancy(entry).get("names_unique_regardless_of_case"), False)


def owner_name_may_contain(entry: Mapping[str, Any], character: str) -> bool:
    """Whether ``character`` can occur in an owner name. With no recorded
    character set, or one this package cannot read, any character may. It
    reads what the Go package reads, one ASCII character or a range of them
    such as ``a-z``: Go counts bytes, and outside ASCII a character is more
    than one."""
    return _may_contain(tenancy(entry).get("owner_name_characters"), character)


def repository_name_may_contain(entry: Mapping[str, Any], character: str) -> bool:
    """Whether ``character`` can occur in a repository's name. With no
    recorded character set, or one this package cannot read, any character
    may. It reads the set as ``owner_name_may_contain`` reads an owner's."""
    return _may_contain(tenancy(entry).get("repository_name_characters"), character)


def _may_contain(chars: Any, character: str) -> bool:
    if len(character) != 1:
        raise ValueError(f"one character, not {character!r}")
    if not chars:
        return True
    found = False
    for c in chars:
        if len(c) == 1 and c.isascii():
            found = found or c == character
        elif len(c) == 3 and c.isascii() and c[1] == "-" and c[0] < c[2]:
            found = found or c[0] <= character <= c[2]
        else:
            return True
    return found
