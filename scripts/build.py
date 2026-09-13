#!/usr/bin/env python3
"""Generate issuers.json from issuers.yaml.

The YAML is the source of truth and carries the comments. The JSON is what both
packages embed, so neither needs a YAML parser at runtime -- which is the whole
reason this package has no dependencies, and the reason a scanner can adopt it
without adding one.
"""
import datetime
import json
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent

KEEP = ['name', 'vendor', 'category', 'issuer', 'issuer_pattern', 'tenancy_model',
        'tenancy_claim', 'control_test', 'control_test_result', 'discovery_url', 'discovery_status', 'jwks_uri',
        'jwks_status', 'subject_format', 'sub_grammar', 'subject_examples', 'claims',
        'claims_advertised', 'claims_advertised_fetched_at', 'immutable_id_claims', 'token_lifetime_s', 'aud_controlled_by', 'aud_default',
        'aud_evidence', 'vendor_example_verdict', 'vendor_example', 'vendor_example_note',
        'correct_condition', 'known_defect', 'self_hosted_variant', 'docs_url',
        'verified_at', 'notes']

# A field must have one shape across every entry. A field that is a string on
# one entry and a map on another silently breaks any typed consumer -- Go
# refuses to unmarshal the file at all, and that is the good outcome. An empty
# list is fine; a different kind of thing is not.
SHAPES = {
    'sub_grammar': dict, 'correct_condition': dict,
    'claims': list, 'claims_advertised': list, 'immutable_id_claims': list,
    'subject_examples': list, 'token_lifetime_s': int,
}

AUD = {'relying_party', 'issuer', 'workload', 'unverified'}
VERDICT = {'scoped', 'admits_whole_org', 'admits_any_repo', 'admits_any_principal',
           'no_subject_constraint', 'unverified'}
TENANCY = {'shared', 'per_tenant_host', 'per_tenant_path', 'unverified'}


def clean(v):
    if isinstance(v, (datetime.date, datetime.datetime)):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: clean(x) for k, x in v.items()}
    if isinstance(v, list):
        return [clean(x) for x in v]
    return v


def host_of(u):
    return u.replace('https://', '').replace('http://', '').split('/', 1)[0].lower()


def main():
    doc = yaml.safe_load((ROOT / 'issuers.yaml').read_text())
    entries = doc['issuers']
    errs, seen = [], {}

    for e in entries:
        n = e.get('name', '<unnamed>')
        if e.get('aud_controlled_by') not in AUD:
            errs.append(f"{n}: aud_controlled_by={e.get('aud_controlled_by')!r}")
        if e.get('vendor_example_verdict') not in VERDICT:
            errs.append(f"{n}: vendor_example_verdict={e.get('vendor_example_verdict')!r}")
        if e.get('tenancy_model') not in TENANCY:
            errs.append(f"{n}: tenancy_model={e.get('tenancy_model')!r}")
        for field, want in SHAPES.items():
            if field in e and not isinstance(e[field], want):
                errs.append(f"{n}: {field} is {type(e[field]).__name__}, "
                            f"every entry must have it as {want.__name__}")

        u = e.get('issuer') or e.get('issuer_pattern')
        if not u:
            errs.append(f"{n}: neither issuer nor issuer_pattern")
            continue
        # One host, one entry. Two entries on one host silently shadow each other in
        # every lookup built on this file -- which is how two duplicates survived the
        # first merge, differing only in the name of a <placeholder>.
        h = host_of(u)
        if h in seen:
            errs.append(f"{n}: host {h!r} already used by {seen[h]!r}")
        seen[h] = n

    if errs:
        print("issuers.yaml is invalid:", file=sys.stderr)
        for x in errs:
            print("  " + x, file=sys.stderr)
        return 1

    out = [{k: clean(e[k]) for k in KEEP if k in e and e[k] not in (None, '')} for e in entries]
    payload = {'census_date': str(doc['census_date']), 'issuers': out}
    (ROOT / 'issuers.json').write_text(
        json.dumps(payload, ensure_ascii=False, separators=(',', ':')))
    print(f"issuers.json: {len(out)} entries, {len(seen)} distinct hosts")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
