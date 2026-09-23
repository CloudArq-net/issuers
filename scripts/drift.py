#!/usr/bin/env python3
"""Re-fetch every discovery document and JWKS, and report what moved.

Issuers change under you. Azure DevOps's vstoken issuer retires 2027-07-01; AWS
became an issuer in its own right during 2026. A census nobody re-checks is a
snapshot that quietly becomes wrong, which is what happened to the last public
one.

Exits 1 when anything drifted, so a scheduled job can open an issue.

It only fetches URLs already recorded in the census, and only public unauthenticated
metadata. It never follows a host derived from anywhere else.
"""
import json
import pathlib
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
UA = 'cloudarq-issuers-drift/0.1 (+https://github.com/CloudArq-net/issuers)'
TIMEOUT = 20


def fetch(url):
    """Return (status, body_or_None). Status is an int, or a string for a transport error."""
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:                      # noqa: BLE001 - transport, not HTTP
        return type(e).__name__, None


def main():
    census = json.loads((ROOT / 'issuers.json').read_text(encoding='utf-8'))
    drift, checked, skipped = [], 0, 0

    for e in census['issuers']:
        name = e['name']

        # Only entries we previously confirmed are re-checked. An entry that was
        # never verified cannot drift -- there is nothing to drift from -- and a
        # per-tenant URL still carrying a <placeholder> is not fetchable at all.
        if e.get('discovery_status') != 'ok':
            skipped += 1
            continue
        url = e.get('discovery_url', '')
        if not url or '<' in url:
            skipped += 1
            continue

        checked += 1
        status, body = fetch(url)
        if status != 200:
            drift.append(f"{name}: discovery {url} was ok, now {status}")
            continue

        try:
            doc = json.loads(body)
        except Exception:
            drift.append(f"{name}: discovery document is no longer valid JSON")
            continue

        recorded = e.get('jwks_uri')
        live = doc.get('jwks_uri')
        if recorded and live and recorded != live:
            drift.append(f"{name}: jwks_uri moved\n    was {recorded}\n    now {live}")

        # Compare only against what the discovery document advertised when the
        # census was taken. Comparing against `claims` would be comparing two
        # different things: GitLab's discovery document advertises its human
        # sign-in claims while its CI job token carries project_id and friends,
        # so that check reports drift every single day and gets muted inside a
        # week -- after which real drift goes unnoticed too.
        recorded_adv = set(e.get('claims_advertised') or [])
        live_claims = set(doc.get('claims_supported') or [])
        if recorded_adv and live_claims:
            added, gone = live_claims - recorded_adv, recorded_adv - live_claims
            if added:
                drift.append(f"{name}: claims_supported added: {', '.join(sorted(added))}")
            if gone:
                drift.append(f"{name}: claims_supported REMOVED: {', '.join(sorted(gone))}")

        if e.get('jwks_status') == 'ok' and live:
            jstatus, _ = fetch(live)
            if jstatus != 200:
                drift.append(f"{name}: JWKS {live} was ok, now {jstatus}")

    print(f"checked {checked}, skipped {skipped} (unverified or per-tenant)")
    if not drift:
        print("no drift")
        return 0
    print(f"\n{len(drift)} change(s):\n")
    for d in drift:
        print("  - " + d)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
