"""The census read the way a trust-policy classifier reads it.

Two things live here, each the Python twin of the Go ``tenancy`` package: the
matcher, which finds the census entry an issuer URL is and the tenant the URL
names, and the projection, which keeps only the values a classifier may rely
on. ``scripts/build.py`` writes the Go sub-package's data with this projection,
so the two languages are held to one rule, and both are held to the same match
cases (``tests/match_cases.json``).

The matcher parses; it never runs a regular expression. An issuer comes from a
customer's configuration, and a backtracking pattern over it is a denial of
service waiting for its input.

This module imports nothing from the package, so the build can load it before
the package's data exists.
"""

from __future__ import annotations

from typing import Any, Mapping, NamedTuple, Optional, Sequence

_ASCII_UPPER = {ord(c): ord(c) + 32 for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
_LABEL = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_SEGMENT = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
_HEX = frozenset("0123456789abcdefABCDEF")


def lower_ascii(s: str) -> str:
    """Fold ASCII letters only. ``str.lower`` also folds letters such as the
    Kelvin sign onto ``k``, which would let a look-alike host pass for a census
    host; Go's matcher folds ASCII only, and so does this one."""
    return s.translate(_ASCII_UPPER)


def host_of_issuer(issuer: str) -> str:
    """The host of an issuer URL or bare host, or ``""`` when the census's
    issuer field holds a note such as ``"unverified"``: a note has whitespace
    in it or no dot."""
    u = issuer.removeprefix("https://").removeprefix("http://")
    u = u.split("/", 1)[0]
    if "." not in u or any(c in u for c in " \t\n"):
        return ""
    return u


class Segment(NamedTuple):
    """A host label or path segment of a rule: a literal, or a whole
    placeholder when ``name`` is set."""
    literal: str
    name: str


class Rule(NamedTuple):
    entry: Any
    key: str
    host: tuple
    path: tuple
    # literals counts the UTF-8 bytes outside placeholders, as Go counts them;
    # of two rules that match one issuer, the one with more is the more
    # specific.
    literals: int
    tenant: tuple
    syntax: str


def split(issuer: str) -> Optional[tuple]:
    """Read an issuer the way the census writes one: ``https://`` or no
    scheme, one trailing slash dropped, every host label and path segment
    non-empty. Case is left alone; the caller folds the host."""
    s = issuer
    n = s.find("://")
    if n >= 0:
        if lower_ascii(s[:n]) != "https":
            return None
        s = s[n + 3:]
    if s.endswith("/"):
        s = s[:-1]
    h, sep, p = s.partition("/")
    host = h.split(".")
    path = p.split("/") if sep else []
    if "" in host or "" in path:
        return None
    return host, path


def _is_placeholder(s: str) -> bool:
    return len(s) >= 3 and s[0] == "<" and s[-1] == ">" and all(c in _SEGMENT for c in s[1:-1])


def _is_guid(s: str) -> bool:
    """8-4-4-4-12 hex digits, the form Microsoft documents for a tenant id."""
    if len(s) != 36:
        return False
    for i, c in enumerate(s):
        if i in (8, 13, 18, 23):
            if c != "-":
                return False
        elif c not in _HEX:
            return False
    return True


def _template(s: str, names: set) -> tuple:
    """Read a tenant such as ``<project>/<location>/<cluster>`` into literal
    text and the placeholders it is spelled from, each of them the
    pattern's."""
    out, placeholders = [], 0
    while s:
        start = s.find("<")
        if start < 0:
            out.append(Segment(s, ""))
            break
        if start > 0:
            out.append(Segment(s[:start], ""))
        end = s.find(">", start)
        if end < 0:
            raise ValueError(f"the tenant {s!r} has an unclosed placeholder")
        p = s[start:end + 1]
        if not _is_placeholder(p) or p not in names:
            raise ValueError(f"the tenant's {p} is not one of the pattern's placeholders")
        out.append(Segment("", p))
        placeholders += 1
        s = s[end + 1:]
    if placeholders == 0:
        raise ValueError("a pattern needs a tenant spelled from its placeholders")
    return tuple(out)


def compile_rule(entry: Any, key: str, tenant_placeholder: str = "", tenant_syntax: str = "") -> Rule:
    """Read one census issuer, exact or a pattern, into a rule, refusing
    anything malformed: a malformed pattern read loosely would match issuers
    the census never described."""
    is_pattern = "<" in key or ">" in key
    if is_pattern and not (len(key) > len("https://") and lower_ascii(key[:len("https://")]) == "https://"):
        raise ValueError(f"{key!r}: a pattern must be an https URL")
    parts = split(key)
    if parts is None:
        raise ValueError(f"{key!r}: not an issuer URL")
    host, path = parts
    names: set = set()
    literals = len(host) - 1 + len(path)

    def read(items: Sequence[str], fold) -> tuple:
        nonlocal literals
        out = []
        for p in items:
            if _is_placeholder(p):
                if p in names:
                    raise ValueError(f"{key!r}: the placeholder {p} appears twice")
                names.add(p)
                out.append(Segment("", p))
            elif "<" in p or ">" in p:
                raise ValueError(f"{key!r}: {p!r} mixes a placeholder with literal text")
            else:
                out.append(Segment(fold(p), ""))
                literals += len(p.encode())
        return tuple(out)

    rule_host = read(host, lower_ascii)
    rule_path = read(path, lambda s: s)
    folded = ".".join(s.literal + s.name for s in rule_host)
    if rule_path:
        folded += "/" + "/".join(s.literal + s.name for s in rule_path)
    if not is_pattern:
        if tenant_placeholder or tenant_syntax:
            raise ValueError(f"{key!r}: an exact issuer names no tenant")
        return Rule(entry, folded, rule_host, rule_path, literals, (), "")
    tenant = _template(tenant_placeholder, names)
    if tenant_syntax not in ("", "guid"):
        raise ValueError(f"{key!r}: unknown tenant syntax {tenant_syntax!r}")
    if tenant_syntax == "guid" and (len(tenant) != 1 or not tenant[0].name):
        raise ValueError(f"{key!r}: a tenant syntax needs a tenant that is one placeholder")
    return Rule(entry, folded, rule_host, rule_path, literals, tenant, tenant_syntax)


class Matcher:
    """Compiled census rules, in census order."""

    def __init__(self, rules: Sequence[Rule]):
        self.rules = tuple(rules)

    def match(self, issuer: str) -> Optional[tuple]:
        """The entry an issuer matches and the tenant it names, or ``None``.
        Of several matching rules the one with the most literal characters
        wins, and of those the first in census order."""
        parts = split(issuer)
        if parts is None:
            return None
        host = [lower_ascii(h) for h in parts[0]]
        path = parts[1]
        best: Optional[Rule] = None
        tenant = ""
        for r in self.rules:
            values = _bind(r, host, path)
            if values is None or best is not None and r.literals <= best.literals:
                continue
            best, tenant = r, "".join(values[s.name] if s.name else s.literal for s in r.tenant)
        if best is None:
            return None
        return best.entry, tenant


def _bind(r: Rule, host: Sequence[str], path: Sequence[str]) -> Optional[dict]:
    if len(host) != len(r.host) or len(path) != len(r.path):
        return None
    values: dict = {}
    for segments, given, allowed in ((r.host, host, _LABEL), (r.path, path, _SEGMENT)):
        for s, v in zip(segments, given):
            if not s.name:
                if v != s.literal:
                    return None
            elif not v or any(c not in allowed for c in v):
                return None
            else:
                values[s.name] = v
    if r.syntax == "guid" and not _is_guid(values[r.tenant[0].name]):
        return None
    return values


def compile_rules(items: Sequence[tuple]) -> Matcher:
    """Compile ``(entry, key, tenant_placeholder, tenant_syntax)`` items,
    refusing two entries that one issuer string would match the same way."""
    rules, seen = [], {}
    for entry, key, tenant_placeholder, tenant_syntax in items:
        r = compile_rule(entry, key, tenant_placeholder, tenant_syntax)
        if r.key in seen:
            raise ValueError(f"{seen[r.key]!r} and {key!r} are the same issuer")
        seen[r.key] = key
        rules.append(r)
    return Matcher(rules)


def rule_of(entry: Mapping[str, Any]) -> Optional[tuple]:
    """The census's rule for which entries an issuer can match, as
    ``(key, tenant_placeholder, tenant_syntax)``: a verified issuer pattern,
    or an exact issuer that is a URL or host rather than a note or an
    unverified pattern. ``None`` for every other entry."""
    m = entry.get("match") or {}
    if m.get("value") == "verified":
        return m["issuer_pattern"], m["tenant_placeholder"], m.get("tenant_syntax", "")
    issuer = entry.get("issuer") or ""
    if not host_of_issuer(issuer) or "<" in issuer or ">" in issuer:
        return None
    return issuer, "", ""


def settled(value: Any) -> Optional[str]:
    """A yes-or-no value as the projection keeps it: ``"yes"`` and ``"no"``
    stay, and anything else is left out, which reads as unverified."""
    return value if value in ("yes", "no") else None


def projection(entry: Mapping[str, Any]) -> dict:
    """The entry as the Go tenancy sub-package carries it: the values a
    classifier reads, with every unverified value, multi-valued claim and claim
    of unknown cardinality left out, so that absent reads the cautious way.
    Go's ``Issuer.Tenancy`` is held to the same rule, entry by entry."""
    t: dict = {"name": entry["name"], "issuer": entry.get("issuer", "")}
    m = entry.get("match") or {}
    if m.get("value") == "verified":
        t["issuer"] = m["issuer_pattern"]
        t["tenant_placeholder"] = m["tenant_placeholder"]
        t["tenant_kind"] = m["tenant_kind"]
        if m.get("tenant_syntax"):
            t["tenant_syntax"] = m["tenant_syntax"]
        if settled(m.get("tenant_recyclable")):
            t["tenant_recyclable"] = m["tenant_recyclable"]
    if (entry.get("tenant_membership") or {}).get("value") == "controlled":
        t["tenant_membership"] = "controlled"
    if m.get("value") == "verified" and m.get("not_a_controlled_tenant"):
        t["not_a_controlled_tenant"] = [x["tenant"] for x in m["not_a_controlled_tenant"]]
    if settled((entry.get("anonymous_tokens") or {}).get("value")):
        t["anonymous_tokens"] = entry["anonymous_tokens"]["value"]
    tc = entry.get("tenancy_claims") or {}
    if tc.get("value") == "verified":
        claims = []
        for c in tc["claims"]:
            if c["multi_valued"] != "no":
                continue
            claim = {"claim": c["claim"], "kind": c["kind"], "scope": c["scope"]}
            if settled(c["immutable"]):
                claim["immutable"] = c["immutable"]
            claims.append(claim)
        if claims:
            t["tenancy_claims"] = claims
    nt = entry.get("not_tenancy") or {}
    if nt.get("value") == "verified" and nt.get("claims"):
        t["not_tenancy"] = [c["claim"] for c in nt["claims"]]
    sf = entry.get("subject_forms") or {}
    if sf.get("value") == "verified" and sf.get("forms"):
        forms = []
        for f in sf["forms"]:
            form: dict = {"leading_literal": f["leading_literal"]}
            for side in ("owner_parts", "repository_parts"):
                if f.get(side):
                    form[side] = [{"kind": p["kind"], "delimiter_after": p["delimiter_after"]} for p in f[side]]
            forms.append(form)
        t["subject_forms"] = forms
    if sf.get("value") == "verified" and sf.get("never_pin"):
        t["never_pin"] = [n["leading_literal"] for n in sf["never_pin"]]
    oc = entry.get("owner_charset") or {}
    if oc.get("value") == "verified" and oc.get("characters"):
        t["owner_name_characters"] = list(oc["characters"])
    if settled((entry.get("names_unique_regardless_of_case") or {}).get("value")):
        t["names_unique_regardless_of_case"] = entry["names_unique_regardless_of_case"]["value"]
    ac = entry.get("accounts") or {}
    if ac.get("value") == "verified":
        t["platform"] = ac["platform"]
        if ac.get("declaration_namespace"):
            t["declaration_namespace"] = ac["declaration_namespace"]
    return t
