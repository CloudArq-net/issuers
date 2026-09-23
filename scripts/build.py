#!/usr/bin/env python3
"""Generate the census's JSON, and the tenancy sub-package's data, from issuers.yaml.

The YAML is the source of truth and carries the comments. The JSON is what both
packages embed, so neither needs a YAML parser at runtime -- which is the whole
reason this package has no dependencies, and the reason a scanner can adopt it
without adding one.

Every tenancy value rests on vendor sentences recorded beside it, and this script
refuses a census that breaks that: a fact with no source or no quote, a value
outside its vocabulary, a settled value with nothing behind it, or two entries one
issuer could match with nothing to choose between them. An entry this release did
not research is written with every tenancy field unverified.

It writes the files below, and CI fails when running it changes any of them:

  issuers.json, python/src/cloudarq_issuers/issuers.json   the census
  tenancy/tenancy.json                                     what a classifier reads
  python/tests/match_cases.json, python/tests/answers.json the cases Go and Python share
"""
import datetime
import importlib.util
import itertools
import json
import pathlib
import re
import shutil
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load_tenancy_module():
    """The Python package's matcher and projection, loaded by path: the census
    is checked by the matcher the package ships, and the Go sub-package's data
    is written by the projection the package ships, so Python has one of each."""
    path = ROOT / 'python' / 'src' / 'cloudarq_issuers' / '_tenancy.py'
    spec = importlib.util.spec_from_file_location('_cloudarq_issuers_tenancy', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tenancy = _load_tenancy_module()

KEEP = ['name', 'vendor', 'category', 'issuer', 'issuer_pattern', 'tenancy_model',
        'tenancy_claim', 'control_test', 'control_test_result', 'discovery_url', 'discovery_status', 'jwks_uri',
        'jwks_status', 'subject_format', 'sub_grammar', 'subject_examples', 'claims',
        'claims_advertised', 'claims_advertised_fetched_at', 'immutable_id_claims', 'token_lifetime_s', 'aud_controlled_by', 'aud_default',
        'aud_evidence', 'vendor_example_verdict', 'vendor_example', 'vendor_example_note',
        'correct_condition', 'known_defect', 'self_hosted_variant', 'docs_url',
        'verified_at', 'notes', 'source']

# The fields this release adds. Every entry carries each of them in the JSON; an
# entry the YAML does not mark `researched: in_release` holds none of them in the
# YAML, and each is written unverified.
TENANCY_FIELDS = ['anonymous_tokens', 'tenancy_claims', 'not_tenancy', 'subject_forms', 'owner_charset',
                  'names_unique_regardless_of_case', 'match', 'tenant_membership', 'built_in']

# A field must have one shape across every entry. A field that is a string on
# one entry and a map on another silently breaks any typed consumer -- Go
# refuses to unmarshal the file at all, and that is the good outcome. An empty
# list is fine; a different kind of thing is not.
SHAPES = {
    'sub_grammar': dict, 'correct_condition': dict,
    'claims': list, 'claims_advertised': list, 'immutable_id_claims': list,
    'subject_examples': list, 'token_lifetime_s': int,
    'researched': str, 'research': dict,
    **{field: dict for field in TENANCY_FIELDS},
}

AUD = {'relying_party', 'issuer', 'workload', 'unverified'}
VERDICT = {'scoped', 'admits_whole_org', 'admits_any_repo', 'admits_any_principal',
           'no_subject_constraint', 'unverified'}
TENANCY = {'shared', 'per_tenant_host', 'per_tenant_path', 'unverified'}
RESEARCHED = {'in_release', 'not_in_this_release'}
YES_NO = {'yes', 'no', 'unverified'}
LISTED = {'verified', 'unverified'}
KIND = {'name', 'id'}
SCOPE = {'owner', 'repository', 'enterprise'}

FACT = {'source', 'quote', 'verified_at', 'role'}
OBSERVATION = {'observed', 'method', 'at', 'result'}
DATE = re.compile(r'\d{4}-\d{2}-\d{2}')


def clean(v):
    if isinstance(v, (datetime.date, datetime.datetime)):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: clean(x) for k, x in v.items()}
    if isinstance(v, list):
        return [clean(x) for x in v]
    return v


class Checker:
    """Collects everything wrong with one entry, each message naming where."""

    def __init__(self, name):
        self.name = name
        self.errors = []

    def fail(self, where, what):
        self.errors.append(f"{self.name}: {where}: {what}")

    def one_of(self, where, value, allowed):
        if not (isinstance(value, str) and value in allowed):
            self.fail(where, f"{value!r} is not one of {', '.join(sorted(allowed))}")

    def keys(self, where, mapping, allowed, required=()):
        if not isinstance(mapping, dict):
            self.fail(where, f"must be a mapping, not {type(mapping).__name__}")
            return False
        for k in sorted(mapping.keys() - set(allowed)):
            self.fail(where, f"unknown key {k!r}")
        for k in required:
            if k not in mapping:
                self.fail(where, f"missing {k!r}")
        return True

    def text(self, where, value):
        if not (isinstance(value, str) and value.strip()):
            self.fail(where, "must be non-empty text")

    def urls(self, where, value):
        if not isinstance(value, list) or not value:
            self.fail(where, "must be a non-empty list of URLs")
            return
        for i, u in enumerate(value):
            if not (isinstance(u, str) and u.startswith('https://')):
                self.fail(f"{where}[{i}]", f"{u!r} is not an https URL")

    def fact(self, where, f):
        """A vendor's sentence with its page and the date it was read, or an
        observation of a live endpoint with how and when it was made. A fact
        with no source or no quote is not a fact."""
        if not isinstance(f, dict):
            self.fail(where, f"a fact must be a mapping, not {type(f).__name__}")
            return
        if 'observed' in f:
            self.keys(where, f, OBSERVATION, OBSERVATION)
            for k in OBSERVATION & f.keys():
                self.text(f"{where}.{k}", f[k])
            return
        self.keys(where, f, FACT)
        if not (isinstance(f.get('source'), str) and f['source'].startswith('https://')):
            self.fail(where, "a fact needs its source, an https URL")
        if not (isinstance(f.get('quote'), str) and f['quote'].strip()):
            self.fail(where, "a fact needs its quote")
        if not (isinstance(f.get('verified_at'), str) and DATE.fullmatch(f['verified_at'])):
            self.fail(where, "a fact needs the date it was read, as verified_at: YYYY-MM-DD")
        if 'role' in f:
            self.text(f"{where}.role", f['role'])

    def facts(self, where, value, required=False):
        if value is None and not required:
            return
        if not isinstance(value, list) or (required and not value):
            self.fail(where, "must be a non-empty list of facts" if required else "must be a list of facts")
            return
        for i, f in enumerate(value):
            self.fact(f"{where}[{i}]", f)

    def research(self, where, value):
        """Everything under research that looks like a fact is held to the fact
        rule, however deep it sits: a mapping with a source or a quote in it,
        or an observation. (A key named `observed` whose value is a mapping or
        a list names a group, not an observation.)"""
        if isinstance(value, dict):
            observed = value.get('observed')
            if 'source' in value or 'quote' in value or observed is not None and not isinstance(observed, (dict, list)):
                self.fact(where, value)
                return
            for k, v in value.items():
                self.research(f"{where}.{k}", v)
        elif isinstance(value, list):
            for i, v in enumerate(value):
                self.research(f"{where}[{i}]", v)


def check_anonymous_tokens(c, a):
    if not c.keys('anonymous_tokens', a, {'value', 'basis', 'evidence', 'chain', 'context', 'note',
                                          'why_unverified', 'looked_in'}, ['value']):
        return
    c.one_of('anonymous_tokens.value', a['value'], YES_NO)
    for k in ('evidence', 'chain', 'context'):
        c.facts(f"anonymous_tokens.{k}", a.get(k))
    if 'looked_in' in a:
        c.urls('anonymous_tokens.looked_in', a['looked_in'])
    if a['value'] in ('yes', 'no'):
        if not a.get('evidence') and not a.get('chain'):
            c.fail('anonymous_tokens', f"{a['value']!r} with no evidence and no chain")
        if 'why_unverified' in a:
            c.fail('anonymous_tokens', "why_unverified beside a settled value")
    elif a['value'] == 'unverified':
        c.text('anonymous_tokens.why_unverified', a.get('why_unverified'))
        for k in ('basis', 'evidence', 'chain'):
            if k in a:
                c.fail('anonymous_tokens', f"an unverified value carries {k}; what was read goes in context")
    if 'basis' in a:
        c.one_of('anonymous_tokens.basis', a['basis'], {'chain'})
        if not a.get('chain'):
            c.fail('anonymous_tokens', "basis: chain with no chain")


def check_tenancy_claims(c, t):
    if not c.keys('tenancy_claims', t, {'value', 'claims'}, ['value']):
        return set()
    c.one_of('tenancy_claims.value', t['value'], LISTED)
    claims = t.get('claims')
    if t['value'] != 'verified':
        if claims is not None:
            c.fail('tenancy_claims', "an unverified list carries claims")
        return set()
    if not isinstance(claims, list) or not claims:
        c.fail('tenancy_claims.claims', "a verified list needs its claims")
        return set()
    seen = set()
    for i, x in enumerate(claims):
        w = f"tenancy_claims.claims[{i}]"
        if not c.keys(w, x, {'claim', 'kind', 'scope', 'multi_valued', 'immutable', 'evidence',
                             'immutable_evidence', 'context', 'note', 'looked_in'},
                      ['claim', 'kind', 'scope', 'multi_valued', 'immutable', 'evidence']):
            continue
        c.text(f"{w}.claim", x['claim'])
        if x['claim'] in seen:
            c.fail(w, f"{x['claim']!r} is listed twice")
        seen.add(x['claim'])
        c.one_of(f"{w}.kind", x['kind'], KIND)
        c.one_of(f"{w}.scope", x['scope'], SCOPE)
        c.one_of(f"{w}.multi_valued", x['multi_valued'], YES_NO)
        c.one_of(f"{w}.immutable", x['immutable'], YES_NO)
        c.fact(f"{w}.evidence", x['evidence'])
        c.facts(f"{w}.immutable_evidence", x.get('immutable_evidence'))
        c.facts(f"{w}.context", x.get('context'))
        if x['immutable'] in ('yes', 'no') and not x.get('immutable_evidence'):
            c.fail(w, f"immutable {x['immutable']!r} with no immutable_evidence")
        if 'looked_in' in x:
            c.urls(f"{w}.looked_in", x['looked_in'])
    return seen


def check_not_tenancy(c, t, tenancy_claims):
    if not c.keys('not_tenancy', t, {'value', 'claims'}, ['value']):
        return
    c.one_of('not_tenancy.value', t['value'], LISTED)
    claims = t.get('claims')
    if t['value'] != 'verified':
        if claims is not None:
            c.fail('not_tenancy', "an unverified list carries claims")
        return
    if not isinstance(claims, list) or not claims:
        c.fail('not_tenancy.claims', "a verified list needs its claims")
        return
    seen = set()
    for i, x in enumerate(claims):
        w = f"not_tenancy.claims[{i}]"
        if not c.keys(w, x, {'claim', 'why', 'evidence', 'context'}, ['claim', 'why', 'evidence']):
            continue
        c.text(f"{w}.claim", x['claim'])
        c.text(f"{w}.why", x['why'])
        c.fact(f"{w}.evidence", x['evidence'])
        c.facts(f"{w}.context", x.get('context'))
        if x['claim'] in seen or x['claim'] in tenancy_claims:
            c.fail(w, f"{x['claim']!r} is listed twice, or is also a tenancy claim")
        seen.add(x['claim'])


def check_subject_forms(c, s):
    if not c.keys('subject_forms', s, {'value', 'forms', 'never_pin', 'chosen_by', 'customisable', 'evidence',
                                       'note', 'looked_in'}, ['value']):
        return
    c.one_of('subject_forms.value', s['value'], LISTED)
    if s['value'] != 'verified':
        for k in ('forms', 'never_pin'):
            if k in s:
                c.fail('subject_forms', f"an unverified list carries {k}")
        return
    forms = s.get('forms')
    if not isinstance(forms, list):
        c.fail('subject_forms.forms', "a verified list needs its forms, [] when sub names no tenant")
        return
    if not forms and not s.get('evidence'):
        c.fail('subject_forms', "no form names a tenant, with no evidence that sub names none")
    c.facts('subject_forms.evidence', s.get('evidence'))
    c.facts('subject_forms.chosen_by', s.get('chosen_by'))
    if 'customisable' in s:
        c.one_of('subject_forms.customisable', s['customisable'], YES_NO)
    if 'looked_in' in s:
        c.urls('subject_forms.looked_in', s['looked_in'])
    literals = set()
    for i, f in enumerate(forms):
        w = f"subject_forms.forms[{i}]"
        if not c.keys(w, f, {'form', 'leading_literal', 'shape', 'owner_parts', 'repository_parts', 'evidence',
                             'issued_for', 'note'}, ['form', 'leading_literal', 'evidence']):
            continue
        c.text(f"{w}.form", f['form'])
        c.text(f"{w}.leading_literal", f['leading_literal'])
        literals.add(f['leading_literal'])
        c.fact(f"{w}.evidence", f['evidence'])
        c.facts(f"{w}.issued_for", f.get('issued_for'))
        total = 0
        for side in ('owner_parts', 'repository_parts'):
            ps = f.get(side, [])
            if not isinstance(ps, list):
                c.fail(f"{w}.{side}", "must be a list")
                continue
            for j, p in enumerate(ps):
                pw = f"{w}.{side}[{j}]"
                total += 1
                if c.keys(pw, p, {'kind', 'delimiter_after'}, ['kind', 'delimiter_after']):
                    c.one_of(f"{pw}.kind", p['kind'], KIND)
                    if not (isinstance(p['delimiter_after'], str) and len(p['delimiter_after']) == 1):
                        c.fail(f"{pw}.delimiter_after", "must be one character")
        if total == 0:
            c.fail(w, "a form names its tenant by at least one part")
    for i, n in enumerate(s.get('never_pin') or []):
        w = f"subject_forms.never_pin[{i}]"
        if c.keys(w, n, {'leading_literal', 'why', 'evidence'}, ['leading_literal', 'why', 'evidence']):
            c.text(f"{w}.leading_literal", n['leading_literal'])
            c.text(f"{w}.why", n['why'])
            c.fact(f"{w}.evidence", n['evidence'])
            if n['leading_literal'] in literals:
                c.fail(w, f"{n['leading_literal']!r} both leads a form and never pins")


def check_owner_charset(c, o):
    if not c.keys('owner_charset', o, {'value', 'characters', 'description', 'evidence', 'context'}, ['value']):
        return
    c.one_of('owner_charset.value', o['value'], LISTED)
    if o['value'] != 'verified':
        if 'characters' in o:
            c.fail('owner_charset', "an unverified set carries characters")
        return
    chars = o.get('characters')
    if not isinstance(chars, list) or not chars:
        c.fail('owner_charset.characters', "a verified set needs its characters")
    else:
        for i, x in enumerate(chars):
            ok = isinstance(x, str) and (len(x) == 1 or len(x) == 3 and x[1] == '-' and x[0] < x[2])
            if not ok:
                c.fail(f"owner_charset.characters[{i}]", f"{x!r} is neither one character nor a range such as a-z")
    c.text('owner_charset.description', o.get('description'))
    c.facts('owner_charset.evidence', o.get('evidence'), required=True)
    c.facts('owner_charset.context', o.get('context'))


def check_name_case(c, n):
    w = 'names_unique_regardless_of_case'
    if not c.keys(w, n, {'value', 'evidence', 'context', 'note', 'looked_in'}, ['value']):
        return
    c.one_of(f"{w}.value", n['value'], YES_NO)
    c.facts(f"{w}.evidence", n.get('evidence'), required=n['value'] in ('yes', 'no'))
    c.facts(f"{w}.context", n.get('context'))
    if 'looked_in' in n:
        c.urls(f"{w}.looked_in", n['looked_in'])


def check_match(c, m, issuer):
    if not c.keys('match', m, {'value', 'issuer_pattern', 'tenant_placeholder', 'tenant_kind', 'tenant_syntax',
                               'tenant_syntax_evidence', 'tenant_immutable', 'tenant_immutable_evidence',
                               'tenant_recyclable', 'tenant_recyclable_evidence', 'not_a_controlled_tenant',
                               'evidence', 'context', 'note'}, ['value']):
        return
    c.one_of('match.value', m['value'], LISTED)
    if m['value'] != 'verified':
        if len(m) > 1:
            c.fail('match', "an unverified rule carries nothing else")
        return
    for k in ('issuer_pattern', 'tenant_placeholder', 'tenant_kind', 'tenant_recyclable', 'evidence'):
        if k not in m:
            c.fail('match', f"a verified rule needs {k}")
    if m.get('issuer_pattern') != issuer:
        c.fail('match.issuer_pattern', f"{m.get('issuer_pattern')!r} is not the entry's issuer {issuer!r}")
    try:
        tenancy.compile_rule(None, m.get('issuer_pattern', ''), m.get('tenant_placeholder', ''),
                             m.get('tenant_syntax', ''))
    except ValueError as e:
        c.fail('match', f"the pattern does not compile: {e}")
    if '<' not in m.get('issuer_pattern', '<'):
        c.fail('match.issuer_pattern', "a verified rule is a pattern; an exact issuer matches without one")
    c.one_of('match.tenant_kind', m.get('tenant_kind'), KIND)
    c.facts('match.evidence', m.get('evidence'), required=True)
    c.facts('match.context', m.get('context'))
    if 'tenant_syntax' in m:
        c.facts('match.tenant_syntax_evidence', m.get('tenant_syntax_evidence'), required=True)
    for k in ('tenant_immutable', 'tenant_recyclable'):
        if k in m:
            c.one_of(f"match.{k}", m[k], YES_NO)
            c.facts(f"match.{k}_evidence", m.get(f"{k}_evidence"), required=m[k] in ('yes', 'no'))
    for i, x in enumerate(m.get('not_a_controlled_tenant') or []):
        w = f"match.not_a_controlled_tenant[{i}]"
        if c.keys(w, x, {'tenant', 'why', 'evidence'}, ['tenant', 'why', 'evidence']):
            c.text(f"{w}.tenant", x['tenant'])
            c.text(f"{w}.why", x['why'])
            c.fact(f"{w}.evidence", x['evidence'])


def check_tenant_membership(c, t, match):
    w = 'tenant_membership'
    if not c.keys(w, t, {'value', 'evidence', 'context', 'notes', 'unverified', 'looked_in'}, ['value']):
        return
    c.one_of(f"{w}.value", t['value'], {'controlled', 'unverified'})
    c.facts(f"{w}.evidence", t.get('evidence'), required=t['value'] == 'controlled')
    c.facts(f"{w}.context", t.get('context'))
    for k in ('notes', 'unverified'):
        for i, x in enumerate(t.get(k) or []):
            c.text(f"{w}.{k}[{i}]", x)
    if 'looked_in' in t:
        c.urls(f"{w}.looked_in", t['looked_in'])
    if t['value'] == 'controlled' and (match or {}).get('value') != 'verified':
        c.fail(w, "a controlled membership belongs to a verified pattern: it is a tenant's")


def check_built_in(c, b):
    if not c.keys('built_in', b, {'value', 'principal', 'evidence', 'discrepancy', 'note'}, ['value']):
        return
    c.one_of('built_in.value', b['value'], {'yes', 'unverified'})
    if b['value'] == 'yes':
        c.text('built_in.principal', b.get('principal'))
    c.facts('built_in.evidence', b.get('evidence'), required=b['value'] == 'yes')
    c.facts('built_in.discrepancy', b.get('discrepancy'))


def check_entry(e):
    """Everything wrong with one entry of the YAML."""
    c = Checker(e.get('name', '<unnamed>'))
    c.one_of('aud_controlled_by', e.get('aud_controlled_by'), AUD)
    c.one_of('vendor_example_verdict', e.get('vendor_example_verdict'), VERDICT)
    c.one_of('tenancy_model', e.get('tenancy_model'), TENANCY)
    for field, want in SHAPES.items():
        if field in e and not isinstance(e[field], want):
            c.fail(field, f"is {type(e[field]).__name__}, every entry must have it as {want.__name__}")
    if not (e.get('issuer') or e.get('issuer_pattern')):
        c.fail('issuer', "neither issuer nor issuer_pattern")
    claim = e.get('tenancy_claim')
    if isinstance(claim, str) and claim.lower() == 'unverified' and claim != 'unverified':
        c.fail('tenancy_claim', f"{claim!r} is spelled unverified")
    if c.errors:
        return c.errors

    researched = e.get('researched', 'not_in_this_release')
    c.one_of('researched', researched, RESEARCHED)
    carried = [f for f in TENANCY_FIELDS + ['research'] if f in e]
    if researched != 'in_release':
        for f in carried:
            c.fail(f, "an entry this release did not research carries no tenancy field")
        return c.errors
    if not carried:
        c.fail('researched', "in_release, with no tenancy field")
    if 'anonymous_tokens' in e:
        check_anonymous_tokens(c, e['anonymous_tokens'])
    claims = check_tenancy_claims(c, e['tenancy_claims']) if 'tenancy_claims' in e else set()
    if 'not_tenancy' in e:
        check_not_tenancy(c, e['not_tenancy'], claims)
    if 'subject_forms' in e:
        check_subject_forms(c, e['subject_forms'])
    if 'owner_charset' in e:
        check_owner_charset(c, e['owner_charset'])
    if 'names_unique_regardless_of_case' in e:
        check_name_case(c, e['names_unique_regardless_of_case'])
    if 'match' in e:
        check_match(c, e['match'], e.get('issuer'))
    if 'tenant_membership' in e:
        check_tenant_membership(c, e['tenant_membership'], e.get('match'))
    if 'built_in' in e:
        check_built_in(c, e['built_in'])
    if 'research' in e:
        c.research('research', e['research'])
    return c.errors


def render(e):
    """The entry as the JSON carries it: the fields both packages read, with
    `researched` and every tenancy field written out, unverified where the YAML
    holds none."""
    out = {k: clean(e[k]) for k in KEEP if k in e and e[k] not in (None, '')}
    out['researched'] = e.get('researched', 'not_in_this_release')
    for field in TENANCY_FIELDS:
        out[field] = clean(e[field]) if field in e else {'value': 'unverified'}
    if 'research' in e:
        out['research'] = clean(e['research'])
    return out


def overlap(a, b):
    """Whether some issuer could match both rules: the same number of labels and
    segments, and at each position a placeholder on either side or the same
    literal. Placeholders are taken to hold anything, so a pair this reports is
    at worst a pair that only looks ambiguous."""
    if len(a.host) != len(b.host) or len(a.path) != len(b.path):
        return False
    return all(x.name or y.name or x.literal == y.literal
               for x, y in itertools.chain(zip(a.host, b.host), zip(a.path, b.path)))


def shape(e):
    """The entry's issuer with its host folded, one trailing slash dropped and
    every placeholder's name erased, or None for a note: two entries with one
    shape describe one issuer, whatever their placeholders are called."""
    u = e.get('issuer') if tenancy.host_of_issuer(e.get('issuer') or '') else e.get('issuer_pattern')
    if not u or not tenancy.host_of_issuer(u):
        return None
    u = u.removeprefix('https://').removesuffix('/')
    host, sep, path = u.partition('/')
    return re.sub(r'<[^<>]*>', '<>', tenancy.lower_ascii(host) + sep + path)


def check_census(entries):
    """What is wrong across entries: one issuer, one entry, and no two patterns
    an issuer could match with nothing to choose between them. Several entries
    may share a host, told apart by path."""
    errs, rules, shapes = [], [], {}
    for e in entries:
        s = shape(e)
        if s is not None:
            if s in shapes:
                errs.append(f"{e['name']}: the same issuer as {shapes[s]}, {s!r}")
            shapes.setdefault(s, e['name'])
        rule = tenancy.rule_of(e)
        if rule is not None:
            key, placeholder, syntax = rule
            try:
                rules.append(tenancy.compile_rule(e['name'], key, placeholder, syntax))
            except ValueError as x:
                errs.append(f"{e['name']}: {x}")
    seen = {}
    for r in rules:
        if r.key in seen:
            errs.append(f"{r.entry}: matched by the same issuer as {seen[r.key]}, {r.key!r}")
        seen.setdefault(r.key, r.entry)
    for a, b in itertools.combinations(rules, 2):
        if a.key != b.key and a.literals == b.literals and overlap(a, b):
            errs.append(f"{a.entry} and {b.entry}: one issuer can match both, and neither is more specific")
    return errs


def main():
    doc = clean(yaml.safe_load((ROOT / 'issuers.yaml').read_text()))
    entries = doc['issuers']
    errs = [x for e in entries for x in check_entry(e)]
    census = [render(e) for e in entries]
    if not errs:
        errs = check_census(census)
    if errs:
        print("issuers.yaml is invalid:", file=sys.stderr)
        for x in errs:
            print("  " + x, file=sys.stderr)
        return 1

    payload = {'census_date': str(doc['census_date']), 'issuers': census}
    text = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
    (ROOT / 'issuers.json').write_text(text)
    (ROOT / 'python' / 'src' / 'cloudarq_issuers' / 'issuers.json').write_text(text)

    sub = [tenancy.projection(e) for e in census if tenancy.rule_of(e) is not None]
    (ROOT / 'tenancy' / 'tenancy.json').write_text(
        json.dumps({'census_date': payload['census_date'], 'issuers': sub}, ensure_ascii=False, separators=(',', ':')))
    researched = sum(1 for e in census if e['researched'] == 'in_release')
    print(f"issuers.json: {len(census)} entries, {researched} researched in this release; "
          f"tenancy/tenancy.json: {len(sub)} entries an issuer can match")

    # The Python tests read their own copies, so the source distribution runs
    # them without the Go tree. answers.json is written by the Go tests, from
    # the census just built, when they run with -update.
    for shared in ('match_cases.json', 'answers.json'):
        source = ROOT / 'tenancy' / 'testdata' / shared
        if not source.exists():
            print(f"{source.relative_to(ROOT)} is missing: run `go test . -run TestGoAndPythonAgree -update`, "
                  "then build again", file=sys.stderr)
            return 1
        shutil.copyfile(source, ROOT / 'python' / 'tests' / shared)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
