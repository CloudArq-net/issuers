"""Checks on the repository's workflows: every action pinned to a commit, every
token starting with no permission, and the release publishing by trusted
publishing from v* tags only.

They sit beside the package's tests because ``make test`` runs this directory.
The source distribution leaves this file out (pyproject.toml): it needs
.github/workflows, which the distribution does not carry.
"""

import re
from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"


def workflows():
    files = sorted(WORKFLOWS.glob("*.yml"))
    assert {f.name for f in files} >= {"ci.yml", "drift.yml", "release.yml"}, files
    return files


def triggers(doc):
    # YAML 1.1 reads the key `on` as the boolean true.
    return doc.get("on", doc.get(True))


PINNED = re.compile(r"^\s*(?:-\s+)?uses:\s+([\w.-]+/[\w.-]+(?:/[\w./-]+)?)@([0-9a-f]{40}) # (v\d+\.\d+\.\d+)\s*$")


def test_every_action_is_pinned_to_a_commit_with_its_tag_beside_it():
    examined = 0
    for path in workflows():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.match(r"^\s*(?:-\s+)?uses:", line):
                examined += 1
                assert PINNED.match(line), f"{path.name}:{n}: {line.strip()} is not pinned to a commit with its tag"
    assert examined >= 10, f"examined {examined} uses: lines"


def test_every_workflow_starts_with_no_permission_and_each_job_asks():
    for path in workflows():
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert doc.get("permissions") == {}, f"{path.name}: permissions {doc.get('permissions')!r} at the top"
        for job_id, job in doc["jobs"].items():
            assert isinstance(job.get("permissions"), dict), f"{path.name}: job {job_id} does not say what it needs"


def test_only_the_publishing_job_mints_an_id_token_and_only_drift_writes():
    writes = {}
    for path in workflows():
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_id, job in doc["jobs"].items():
            for scope, level in job["permissions"].items():
                assert level in ("read", "write"), (path.name, job_id, scope, level)
                if level == "write":
                    writes.setdefault(f"{path.name}:{job_id}", set()).add(scope)
    assert writes == {"drift.yml:drift": {"issues"}, "release.yml:publish": {"id-token"}}


def test_the_release_publishes_from_v_tags_in_the_pypi_environment_with_attestations():
    doc = yaml.safe_load((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    assert triggers(doc) == {"push": {"tags": ["v*"]}}
    publish = doc["jobs"]["publish"]
    assert publish["needs"] == "build"
    assert publish["environment"]["name"] == "pypi"
    steps = [s for s in publish["steps"] if s.get("uses", "").startswith("pypa/gh-action-pypi-publish@")]
    assert len(steps) == 1 and steps[0]["with"]["attestations"] is True
    assert "password" not in steps[0]["with"], "trusted publishing stores no token"


def test_checkout_keeps_no_credential():
    examined = 0
    for path in workflows():
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in doc["jobs"].values():
            for step in job["steps"]:
                if step.get("uses", "").startswith("actions/checkout@"):
                    examined += 1
                    assert step.get("with", {}).get("persist-credentials") is False, path.name
    assert examined >= 3
