#!/usr/bin/env python3
"""Generate the census's JSON, and the tenancy sub-package's data, from issuers.yaml.

The YAML is the source of truth and carries the comments. The JSON is what both
packages embed, so neither needs a YAML parser at runtime -- which is the whole
reason this package has no dependencies, and the reason a scanner can adopt it
without adding one.

Every tenancy value rests on vendor sentences recorded beside it, and this script
refuses a census that breaks that: a fact with no source or no quote, a value
settled by an observation rather than a sentence, a value outside its
vocabulary, a settled value with nothing behind it, a key given twice, or two
entries one issuer could match with nothing to choose between them. An entry
this release did not research is written with every tenancy field unverified.

It reads and writes UTF-8 whatever the machine's locale, and writes the files
below; CI fails when running it changes any of them:

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
import urllib.parse

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


class CensusLoader(yaml.SafeLoader):
    """PyYAML's safe loader, except that it refuses a key given twice in one
    mapping. The safe loader keeps the last value and drops the first without a
    word, so a second block under a key would replace a settled value and the
    census would still build."""


def _mapping_without_repeats(loader, node):
    seen = set()
    for key_node, _ in node.value:
        if isinstance(key_node, yaml.ScalarNode) and key_node.tag != 'tag:yaml.org,2002:merge':
            key = loader.construct_object(key_node)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"the key {key!r} is given twice in one mapping", key_node.start_mark)
            seen.add(key)
    return loader.construct_mapping(node, deep=True)


CensusLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping_without_repeats)

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
                  'names_unique_regardless_of_case', 'match', 'tenant_membership', 'built_in', 'accounts',
                  'aws_condition_keys']

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
DISCOVERY = {'ok', 'not_found', 'error', 'unverified'}
JWKS = {'ok', 'error', 'unverified'}
CATEGORY = {'ci', 'iac', 'runtime', 'cloud', 'ai-agent-platform', 'platform'}
CONTROL_TEST = {'passed', 'failed', 'inconclusive', 'unverified'}
RESEARCHED = {'in_release', 'not_in_this_release'}
YES_NO = {'yes', 'no', 'unverified'}
LISTED = {'verified', 'unverified'}
KIND = {'name', 'id'}
SCOPE = {'owner', 'repository', 'enterprise'}

# What an issuer field holds when it holds no issuer. An entry whose issuer is
# NOT_AN_ISSUER has no key set to fetch, which is what its jwks_status n/a says.
NOT_AN_ISSUER = 'not an OIDC issuer'
NOTES = {'unverified', NOT_AN_ISSUER}

# A declaration namespace is written the way a consumer types it before the
# colon, as in github:acme.
NAMESPACE = re.compile(r'[a-z]+')

FACT = {'source', 'quote', 'verified_at', 'role'}
OBSERVATION = {'observed', 'method', 'at', 'result'}
DATE = re.compile(r'\d{4}-\d{2}-\d{2}')
TIMESTAMP = re.compile(r'(\d{4}-\d{2}-\d{2})(?:T([01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?Z)?')


def clean(v):
    if isinstance(v, (datetime.date, datetime.datetime)):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: clean(x) for k, x in v.items()}
    if isinstance(v, list):
        return [clean(x) for x in v]
    return v


def is_date(value):
    """Whether value is a day on the calendar, written YYYY-MM-DD."""
    if not (isinstance(value, str) and DATE.fullmatch(value)):
        return False
    try:
        datetime.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def is_timestamp(value):
    """Whether value is a day, or a day and a UTC time, as an observation
    records when it was made: YYYY-MM-DD or YYYY-MM-DDTHH:MM[:SS]Z."""
    m = TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    return bool(m) and is_date(m.group(1))


def is_page(value):
    """Whether value is an https URL that names a host, which is what the
    source of a vendor's sentence must be."""
    if not (isinstance(value, str) and value.startswith('https://')) or any(c.isspace() for c in value):
        return False
    try:
        host = urllib.parse.urlsplit(value).hostname or ''
    except ValueError:
        return False
    return '.' in host.strip('.')


def issuer_problem(value, notes_allowed):
    """Why value is not an issuer as the census writes one, or None when it is:
    https:// in lower case or no scheme at all, one host of at least two labels
    or a single placeholder, no empty label or path segment, no whitespace.
    Anything else would escape the check that one issuer has one entry, because
    the packages would read it as a note."""
    if notes_allowed and value in NOTES:
        return None
    notes = ', '.join(repr(n) for n in sorted(NOTES))
    if not isinstance(value, str) or not value or any(c.isspace() for c in value):
        return f"{value!r} is neither an issuer URL, a bare host nor one of the notes {notes}"
    scheme, sep, _ = value.partition('://')
    if sep and scheme != 'https':
        return f"{value!r}: an issuer is written with https:// in lower case, or with no scheme"
    if ('<' in value or '>' in value) and not sep:
        return f"{value!r}: a pattern is written as an https:// URL"
    parts = tenancy.split(value)
    host = parts[0] if parts else []
    if not parts or len(host) < 2 and not (host[0].startswith('<') and host[0].endswith('>')):
        return f"{value!r} is neither an issuer URL, a bare host nor one of the notes {notes}"
    return None


def misspelt_unverified(value, where):
    """Every place under value, with what it holds, that spells unverified
    other than in lower case, which no reader in either package recognises as
    unverified."""
    if isinstance(value, str):
        return [(where, value)] if value.strip().lower() == 'unverified' and value != 'unverified' else []
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in misspelt_unverified(v, f"{where}.{k}")]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in misspelt_unverified(v, f"{where}[{i}]")]
    return []


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
        """Whether mapping is a mapping holding every required key, recording
        each thing wrong with it. A caller reads the required keys only when
        this says yes, so a missing key is refused by name rather than crashing
        the build before the rest is checked."""
        if not isinstance(mapping, dict):
            self.fail(where, f"must be a mapping, not {type(mapping).__name__}")
            return False
        for k in sorted(mapping.keys() - set(allowed), key=repr):
            self.fail(where, f"unknown key {k!r}")
        missing = [k for k in required if k not in mapping]
        for k in missing:
            self.fail(where, f"missing {k!r}")
        return not missing

    def text(self, where, value):
        if not (isinstance(value, str) and value.strip()):
            self.fail(where, "must be non-empty text")

    def urls(self, where, value):
        if not isinstance(value, list) or not value:
            self.fail(where, "must be a non-empty list of URLs")
            return
        for i, u in enumerate(value):
            if not is_page(u):
                self.fail(f"{where}[{i}]", f"{u!r} is not an https URL")

    def fact(self, where, f, settles=True):
        """A vendor's sentence with its page and the date it was read, or an
        observation of a live endpoint with how and when it was made. A fact
        with no source or no quote is not a fact.

        Where the fact settles a value (settles), only a sentence will do:
        unverified means that no vendor sentence establishes the value, so a
        value an observation alone supports is unverified. An observation may
        stand as context, in research, and behind a claim or a leading literal
        that never pins, which cannot move a grant inward."""
        if not isinstance(f, dict):
            self.fail(where, f"a fact must be a mapping, not {type(f).__name__}")
            return
        if 'observed' in f:
            if settles:
                self.fail(where, "an observation settles no value: it needs the vendor's sentence, "
                                 "with its source, quote and verified_at")
            if self.keys(where, f, OBSERVATION, OBSERVATION):
                for k in ('observed', 'method', 'result'):
                    self.text(f"{where}.{k}", f[k])
                if not is_timestamp(f['at']):
                    self.fail(f"{where}.at", f"{f['at']!r} is not a date, as YYYY-MM-DD or YYYY-MM-DDTHH:MMZ")
            return
        self.keys(where, f, FACT)
        if not is_page(f.get('source')):
            self.fail(where, "a fact needs its source, an https URL of a page")
        if not (isinstance(f.get('quote'), str) and f['quote'].strip()):
            self.fail(where, "a fact needs its quote")
        if not is_date(f.get('verified_at')):
            self.fail(where, "a fact needs the date it was read, as verified_at: YYYY-MM-DD")
        if 'role' in f:
            self.text(f"{where}.role", f['role'])

    def facts(self, where, value, required=False, settles=True):
        if value is None and not required:
            return
        if not isinstance(value, list) or (required and not value):
            self.fail(where, "must be a non-empty list of facts" if required else "must be a list of facts")
            return
        for i, f in enumerate(value):
            self.fact(f"{where}[{i}]", f, settles)

    def context(self, where, value):
        """Sentences or observations read beside a value that do not establish it."""
        self.facts(where, value, settles=False)

    def research(self, where, value):
        """Everything under research that looks like a fact is held to the fact
        rule, however deep it sits: a mapping carrying any key a fact or an
        observation has, so a fact written under other names is refused rather
        than walked past. (A key named `observed` whose value is a mapping or a
        list names a group, not an observation.)"""
        if isinstance(value, dict):
            if any(k in FACT | OBSERVATION and not isinstance(v, (dict, list)) for k, v in value.items()):
                self.fact(where, value, settles=False)
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
    for k in ('evidence', 'chain'):
        c.facts(f"anonymous_tokens.{k}", a.get(k))
    c.context('anonymous_tokens.context', a.get('context'))
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
        c.context(f"{w}.context", x.get('context'))
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
        if not c.keys(w, x, {'claim', 'why', 'evidence', 'context', 'looked_in'}, ['claim', 'why', 'evidence']):
            continue
        c.text(f"{w}.claim", x['claim'])
        c.text(f"{w}.why", x['why'])
        # A claim listed here never pins, as one listed nowhere never does.
        c.fact(f"{w}.evidence", x['evidence'], settles=False)
        c.context(f"{w}.context", x.get('context'))
        if 'looked_in' in x:
            c.urls(f"{w}.looked_in", x['looked_in'])
        # A name ending in * stands for every claim that begins with the rest.
        covers = [t for t in tenancy_claims
                  if t == x['claim'] or x['claim'].endswith('*') and t.startswith(x['claim'][:-1])]
        if x['claim'] in seen or covers:
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
                             'basis', 'chain', 'issued_for', 'note'}, ['form', 'leading_literal']):
            continue
        c.text(f"{w}.form", f['form'])
        c.text(f"{w}.leading_literal", f['leading_literal'])
        literals.add(f['leading_literal'])
        # A form rests on a subject the vendor prints, or, where it prints
        # none, on a chain of its sentences marked as one.
        if 'evidence' in f:
            c.fact(f"{w}.evidence", f['evidence'])
        c.facts(f"{w}.chain", f.get('chain'))
        if 'evidence' not in f and not f.get('chain'):
            c.fail(w, "a form with no evidence and no chain")
        if 'basis' in f:
            c.one_of(f"{w}.basis", f['basis'], {'chain'})
            if not f.get('chain'):
                c.fail(w, "basis: chain with no chain")
        elif f.get('chain'):
            c.fail(w, "a chain with no basis: chain to say the form rests on it")
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
    never = s.get('never_pin') or []
    if not isinstance(never, list):
        c.fail('subject_forms.never_pin', "must be a list")
        never = []
    for i, n in enumerate(never):
        w = f"subject_forms.never_pin[{i}]"
        if c.keys(w, n, {'leading_literal', 'why', 'evidence'}, ['leading_literal', 'why', 'evidence']):
            c.text(f"{w}.leading_literal", n['leading_literal'])
            c.text(f"{w}.why", n['why'])
            # A subject led by this literal never pins, as one led by a literal
            # the entry does not list never does.
            c.fact(f"{w}.evidence", n['evidence'], settles=False)
            lit = n['leading_literal']
            if lit in literals:
                c.fail(w, f"{lit!r} both leads a form and never pins")
            # A subject led by the longer of the two would be read by the form
            # and refused by the literal, or the reverse: the census would say
            # two things about one subject.
            for lead in sorted(literals):
                if lit != lead and (lit.startswith(lead) or lead.startswith(lit)):
                    c.fail(w, f"{lit!r} and the lead {lead!r}: one begins the other, so one subject would both "
                              f"pin and never pin")


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
            # Printable ASCII only: the Go reader counts bytes where Python
            # counts characters, and on ASCII the two counts are one.
            ok = isinstance(x, str) and x.isascii() and x.isprintable() and (
                len(x) == 1 or len(x) == 3 and x[1] == '-' and x[0] < x[2])
            if not ok:
                c.fail(f"owner_charset.characters[{i}]",
                       f"{x!r} is neither one character nor a range such as a-z, in printable ASCII")
    c.text('owner_charset.description', o.get('description'))
    c.facts('owner_charset.evidence', o.get('evidence'), required=True)
    c.context('owner_charset.context', o.get('context'))


def check_name_case(c, n):
    w = 'names_unique_regardless_of_case'
    if not c.keys(w, n, {'value', 'evidence', 'context', 'note', 'looked_in'}, ['value']):
        return
    c.one_of(f"{w}.value", n['value'], YES_NO)
    c.facts(f"{w}.evidence", n.get('evidence'), required=n['value'] in ('yes', 'no'))
    c.context(f"{w}.context", n.get('context'))
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
    except (ValueError, TypeError, AttributeError) as e:
        c.fail('match', f"the pattern does not compile: {e}")
    if '<' not in str(m.get('issuer_pattern', '<')):
        c.fail('match.issuer_pattern', "a verified rule is a pattern; an exact issuer matches without one")
    c.one_of('match.tenant_kind', m.get('tenant_kind'), KIND)
    c.facts('match.evidence', m.get('evidence'), required=True)
    c.context('match.context', m.get('context'))
    if 'tenant_syntax' in m:
        c.facts('match.tenant_syntax_evidence', m.get('tenant_syntax_evidence'), required=True)
    for k in ('tenant_immutable', 'tenant_recyclable'):
        if k in m:
            c.one_of(f"match.{k}", m[k], YES_NO)
            c.facts(f"match.{k}_evidence", m.get(f"{k}_evidence"), required=m[k] in ('yes', 'no'))
    open_tenants = m.get('not_a_controlled_tenant') or []
    if not isinstance(open_tenants, list):
        c.fail('match.not_a_controlled_tenant', "must be a list")
        open_tenants = []
    for i, x in enumerate(open_tenants):
        w = f"match.not_a_controlled_tenant[{i}]"
        if c.keys(w, x, {'tenant', 'why', 'evidence', 'context'}, ['tenant', 'why', 'evidence']):
            c.text(f"{w}.tenant", x['tenant'])
            c.text(f"{w}.why", x['why'])
            c.fact(f"{w}.evidence", x['evidence'])
            c.context(f"{w}.context", x.get('context'))


def check_tenant_membership(c, t, match):
    """Controlled rests on a sentence that says the owner decides, or on a
    chain of sentences marked as one; unverified carries what was read as
    context only, so nothing beside it passes for support."""
    w = 'tenant_membership'
    if not c.keys(w, t, {'value', 'basis', 'evidence', 'chain', 'context', 'notes', 'unverified', 'looked_in'},
                  ['value']):
        return
    c.one_of(f"{w}.value", t['value'], {'controlled', 'unverified'})
    for k in ('evidence', 'chain'):
        c.facts(f"{w}.{k}", t.get(k))
    c.context(f"{w}.context", t.get('context'))
    for k in ('notes', 'unverified'):
        items = t.get(k) or []
        if not isinstance(items, list):
            c.fail(f"{w}.{k}", "must be a list of text")
            continue
        for i, x in enumerate(items):
            c.text(f"{w}.{k}[{i}]", x)
    if 'looked_in' in t:
        c.urls(f"{w}.looked_in", t['looked_in'])
    if t['value'] == 'controlled':
        if not t.get('evidence') and not t.get('chain'):
            c.fail(w, "'controlled' with no evidence and no chain")
        if (match or {}).get('value') != 'verified':
            c.fail(w, "a controlled membership belongs to a verified pattern: it is a tenant's")
    else:
        for k in ('basis', 'evidence', 'chain'):
            if k in t:
                c.fail(w, f"an unverified value carries {k}; what was read goes in context")
    if 'basis' in t:
        c.one_of(f"{w}.basis", t['basis'], {'chain'})
        if not t.get('chain'):
            c.fail(w, "basis: chain with no chain")


def check_built_in(c, b):
    if not c.keys('built_in', b, {'value', 'principal', 'evidence', 'discrepancy', 'note'}, ['value']):
        return
    c.one_of('built_in.value', b['value'], {'yes', 'unverified'})
    if b['value'] == 'yes':
        c.text('built_in.principal', b.get('principal'))
    c.facts('built_in.evidence', b.get('evidence'), required=b['value'] == 'yes')
    c.facts('built_in.discrepancy', b.get('discrepancy'))


def check_accounts(c, a, names_owners):
    """The platform whose accounts hold the issuer's tenants, as the vendor's
    sentence names it, and the namespace a consumer declares its owners in,
    which only an issuer whose claims name owners has."""
    w = 'accounts'
    if not c.keys(w, a, {'value', 'platform', 'declaration_namespace', 'evidence', 'note'}, ['value']):
        return
    c.one_of(f"{w}.value", a['value'], LISTED)
    if a['value'] != 'verified':
        if len(a) > 1:
            c.fail(w, "an unverified block carries nothing else")
        return
    if not (isinstance(a.get('platform'), str) and a['platform'].strip()):
        c.fail(w, "a verified block names no platform")
    c.facts(f"{w}.evidence", a.get('evidence'), required=True)
    ns = a.get('declaration_namespace')
    if ns is not None:
        if not (isinstance(ns, str) and NAMESPACE.fullmatch(ns)):
            c.fail(f"{w}.declaration_namespace", f"{ns!r} is not lower-case ASCII letters")
        if not names_owners:
            c.fail(f"{w}.declaration_namespace", "the issuer names no owner by a verified claim, so it has none to "
                                                 "declare")


def check_aws_condition_keys(c, a, pinned):
    """The condition keys AWS documents for the issuer, each with the claim
    AWS reads it from, tied to the table row that maps it as the page renders
    it. A key AWS writes out in an example policy with no row names no claim,
    so it is not listed: a reader would have to take the key's name for its
    claim. A claim written unverified is one no page says the issuer's tokens
    carry as AWS's table spells it: the key keeps that spelling in
    table_claim, tied to the row, and says why. A fallback claim, which AWS
    reads when the token sets no value for the claim, rests on AWS's sentence
    saying so. A key that names a tenancy claim, or sub where the issuer's
    subject names a tenant, must carry that claim under its own name, or a pin
    would read another claim's value."""
    w = 'aws_condition_keys'
    if not c.keys(w, a, {'value', 'basis', 'keys', 'evidence', 'chain', 'context', 'note'}, ['value']):
        return
    c.one_of(f"{w}.value", a['value'], LISTED)
    if a['value'] != 'verified':
        for k in ('keys', 'basis', 'evidence', 'chain'):
            if k in a:
                c.fail(w, f"an unverified list carries {k}")
        return
    for k in ('evidence', 'chain'):
        c.facts(f"{w}.{k}", a.get(k))
    c.context(f"{w}.context", a.get('context'))
    if not a.get('evidence') and not a.get('chain'):
        c.fail(w, "a verified list with no evidence and no chain")
    if 'basis' in a:
        c.one_of(f"{w}.basis", a['basis'], {'chain'})
        if not a.get('chain'):
            c.fail(w, "basis: chain with no chain")
    keys = a.get('keys')
    if not isinstance(keys, list) or not keys:
        c.fail(f"{w}.keys", "a verified list needs its keys")
        return
    quotes = [f['quote'] for f in (a.get('evidence') or []) + (a.get('chain') or [])
              if isinstance(f, dict) and isinstance(f.get('quote'), str)]
    seen = set()
    for i, k in enumerate(keys):
        kw = f"{w}.keys[{i}]"
        unread = isinstance(k, dict) and k.get('claim') == 'unverified'
        if not c.keys(kw, k, {'key', 'claim', 'fallback_claim', 'table_claim', 'why'},
                      ['key', 'claim'] + (['table_claim', 'why'] if unread else [])):
            continue
        for part in ('key', 'claim', 'fallback_claim', 'table_claim', 'why'):
            if part in k:
                c.text(f"{kw}.{part}", k[part])
        if k['key'] in seen:
            c.fail(kw, f"{k['key']!r} is listed twice")
        seen.add(k['key'])
        spelling = k['table_claim'] if unread else k['claim']
        if not any(f"{k['key']} {spelling}" in q for q in quotes):
            c.fail(kw, f"no quoted row shows {k['key']!r} carrying {spelling!r}")
        if not unread and ('table_claim' in k or 'why' in k):
            c.fail(kw, "table_claim and why are written only beside an unverified claim")
        if unread and 'fallback_claim' in k:
            c.fail(kw, "a fallback claim is read only in place of a claim, and this key's claim is unverified")
        elif 'fallback_claim' in k and not any(
                f"If no value is set for {k['claim']}, the {k['key']} condition key maps to the "
                f"{k['fallback_claim']} claim." in q for q in quotes):
            c.fail(kw, f"no quoted sentence says {k['key']!r} reads {k['fallback_claim']!r} when the token sets no "
                       f"{k['claim']!r}")
        if k['key'] in pinned and k['claim'] != k['key']:
            c.fail(kw, f"{k['key']!r} pins a tenant, and AWS carries it under another claim's name")


def check_entry(e):
    """Everything wrong with one entry of the YAML."""
    if not isinstance(e, dict):
        return [f"an entry must be a mapping, not {type(e).__name__}"]
    c = Checker(e.get('name', '<unnamed>'))
    c.text('name', e.get('name'))
    c.one_of('aud_controlled_by', e.get('aud_controlled_by'), AUD)
    c.one_of('vendor_example_verdict', e.get('vendor_example_verdict'), VERDICT)
    c.one_of('tenancy_model', e.get('tenancy_model'), TENANCY)
    c.one_of('discovery_status', e.get('discovery_status'), DISCOVERY)
    c.one_of('jwks_status', e.get('jwks_status'), JWKS | ({'n/a'} if e.get('issuer') == NOT_AN_ISSUER else set()))
    if 'category' in e:
        c.one_of('category', e['category'], CATEGORY)
    if 'control_test_result' in e:
        c.one_of('control_test_result', e['control_test_result'], CONTROL_TEST)
    for field, want in SHAPES.items():
        if field in e and not isinstance(e[field], want):
            c.fail(field, f"is {type(e[field]).__name__}, every entry must have it as {want.__name__}")
    if not (e.get('issuer') or e.get('issuer_pattern')):
        c.fail('issuer', "neither issuer nor issuer_pattern")
    for field, notes_allowed in (('issuer', True), ('issuer_pattern', False)):
        if field in e:
            problem = issuer_problem(e[field], notes_allowed)
            if problem:
                c.fail(field, problem)
    for where, value in misspelt_unverified(e, 'entry'):
        c.fail(where.removeprefix('entry.'), f"{value!r} is spelled unverified; the census writes it in lower case")
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
    if 'accounts' in e:
        tc = e.get('tenancy_claims') or {}
        names_owners = tc.get('value') == 'verified' and any(
            isinstance(x, dict) and x.get('scope') == 'owner' for x in tc.get('claims') or [])
        check_accounts(c, e['accounts'], names_owners)
    if 'aws_condition_keys' in e:
        tc, sf = e.get('tenancy_claims') or {}, e.get('subject_forms') or {}
        pinned = {x.get('claim') for x in tc.get('claims') or [] if isinstance(x, dict)} \
            if tc.get('value') == 'verified' else set()
        if sf.get('value') == 'verified' and sf.get('forms'):
            pinned.add('sub')
        check_aws_condition_keys(c, e['aws_condition_keys'], pinned)
    if 'research' in e:
        c.research('research', e['research'])
    return c.errors


def check_document(doc):
    """What is wrong with the document around the entries."""
    if not isinstance(doc, dict):
        return [f"the census must be a mapping, not {type(doc).__name__}"]
    errs = []
    if not is_date(doc.get('census_date')):
        errs.append(f"census_date: {doc.get('census_date')!r} is not a date, as YYYY-MM-DD")
    if not isinstance(doc.get('issuers'), list) or not doc['issuers']:
        errs.append("issuers: the census needs a non-empty list of entries")
    return errs


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
    declared = {}
    for e in entries:
        ns = (e.get('accounts') or {}).get('declaration_namespace')
        if ns in declared:
            errs.append(f"{e['name']} and {declared[ns]} both declare owners under {ns!r}: a declaration there "
                        f"would make an owner of either one's")
        elif ns:
            declared[ns] = e['name']
    seen = {}
    for r in rules:
        if r.key in seen:
            errs.append(f"{r.entry}: matched by the same issuer as {seen[r.key]}, {r.key!r}")
        seen.setdefault(r.key, r.entry)
    for a, b in itertools.combinations(rules, 2):
        if a.key != b.key and a.literals == b.literals and overlap(a, b):
            errs.append(f"{a.entry} and {b.entry}: one issuer can match both, and neither is more specific")
    return errs


def refuse(errs):
    print("issuers.yaml is invalid:", file=sys.stderr)
    for x in errs:
        print("  " + x, file=sys.stderr)
    return 1


def main():
    try:
        doc = clean(yaml.load((ROOT / 'issuers.yaml').read_text(encoding='utf-8'), Loader=CensusLoader))
    except yaml.YAMLError as e:
        return refuse([str(e)])
    errs = check_document(doc)
    if errs:
        return refuse(errs)
    entries = doc['issuers']
    errs = [x for e in entries for x in check_entry(e)]
    if errs:
        return refuse(errs)
    census = [render(e) for e in entries]
    errs = check_census(census)
    if errs:
        return refuse(errs)

    payload = {'census_date': str(doc['census_date']), 'issuers': census}
    text = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
    (ROOT / 'issuers.json').write_text(text, encoding='utf-8')
    (ROOT / 'python' / 'src' / 'cloudarq_issuers' / 'issuers.json').write_text(text, encoding='utf-8')

    sub = [tenancy.projection(e) for e in census if tenancy.rule_of(e) is not None]
    (ROOT / 'tenancy' / 'tenancy.json').write_text(
        json.dumps({'census_date': payload['census_date'], 'issuers': sub}, ensure_ascii=False, separators=(',', ':')),
        encoding='utf-8')
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
