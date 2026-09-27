"""Checks on the repository's workflows: every action pinned to the commit its
tag named, every token starting with no permission and each job holding exactly
what it uses, each workflow running on exactly its triggers, the build proving
the committed files in step before anything is tested, and the release
publishing by trusted publishing from v* tags only.

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

# The commit each release tag named, resolved with git ls-remote on 2026-09-23
# (the peeled commit where the tag is annotated). A pin cannot be checked
# against its tag without the network, so a new pin changes this table and the
# workflow in one commit, and a reviewer sees both.
PINS = {
    "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1"),
    "actions/setup-go": ("b7ad1dad31e06c5925ef5d2fc7ad053ef454303e", "v7.0.0"),
    "actions/setup-python": ("5fda3b95a4ea91299a34e894583c3862153e4b97", "v7.0.0"),
    "actions/github-script": ("3a2844b7e9c422d3c10d287c895573f7108da1b3", "v9.0.0"),
    "actions/upload-artifact": ("043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", "v7.0.1"),
    "actions/download-artifact": ("3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", "v8.0.1"),
    "pypa/gh-action-pypi-publish": ("dc37677b2e1c63e2034f94d8a5b11f265b73ba33", "v1.14.2"),
}

# What each job may do with its token. Anything more is a scope the job does not
# use, and a scope unused is one a compromised step can still use.
PERMISSIONS = {
    "ci.yml": {"check": {"contents": "read"}},
    "drift.yml": {"drift": {"contents": "read", "issues": "write"}},
    "release.yml": {"build": {"contents": "read"}, "publish": {"id-token": "write"}},
}

# When each workflow runs. pull_request_target and workflow_run would run with
# the base repository's token on code a fork wrote, so neither appears.
TRIGGERS = {
    "ci.yml": {"push": {"branches": ["main"]}, "pull_request": None},
    "drift.yml": {"schedule": [{"cron": "23 6 * * *"}], "workflow_dispatch": None},
    "release.yml": {"push": {"tags": ["v*"]}},
}

# The step that proves the committed JSON, the sub-package's data and the Python
# tests' copies are what issuers.yaml builds: run the build, then fail if it
# changed or added anything.
IN_STEP = ["python3 scripts/build.py", "git diff --exit-code", 'test -z "$(git status --porcelain)"']
RUNS_TESTS = re.compile(r"(^|&&\s*)(go test|(PYTHONPATH=\S+\s+)?python3 -m pytest)\b")


def test_every_action_is_pinned_to_a_commit_with_its_tag_beside_it():
    examined = 0
    for path in workflows():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.match(r"^\s*(?:-\s+)?uses:", line):
                examined += 1
                assert PINNED.match(line), f"{path.name}:{n}: {line.strip()} is not pinned to a commit with its tag"
    assert examined >= 10, f"examined {examined} uses: lines"


def test_every_action_is_the_commit_its_tag_named():
    used = set()
    for path in workflows():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = PINNED.match(line)
            if m:
                action, sha, tag = m.groups()
                used.add(action)
                assert PINS.get(action) == (sha, tag), f"{path.name}:{n}: {action}@{sha} # {tag} is not a pin in PINS"
    assert used == set(PINS), f"PINS lists actions no workflow uses, or the reverse: {sorted(used ^ set(PINS))}"


def test_every_workflow_starts_with_no_permission_and_each_job_holds_what_it_uses():
    for path in workflows():
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert doc.get("permissions") == {}, f"{path.name}: permissions {doc.get('permissions')!r} at the top"
        held = {job_id: job.get("permissions") for job_id, job in doc["jobs"].items()}
        assert held == PERMISSIONS[path.name], f"{path.name}: jobs hold {held}"


def test_every_workflow_runs_on_exactly_its_triggers():
    for path in workflows():
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert triggers(doc) == TRIGGERS[path.name], f"{path.name}: triggers {triggers(doc)!r}"


def run_lines(step):
    return [line.strip() for line in step.get("run", "").splitlines() if line.strip()]


def test_the_build_must_change_nothing_before_anything_is_tested():
    """In CI and in the release, the build runs and the job fails if it wrote
    anything the commit does not hold; only then do the tests run, so what they
    test is what was committed."""
    for name, job_id in (("ci.yml", "check"), ("release.yml", "build")):
        steps = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))["jobs"][job_id]["steps"]
        in_step = [i for i, s in enumerate(steps) if run_lines(s) == IN_STEP]
        assert len(in_step) == 1, f"{name}: {len(in_step)} steps run exactly {IN_STEP}"
        tests = [i for i, s in enumerate(steps) if any(RUNS_TESTS.search(l) for l in run_lines(s))]
        assert tests and in_step[0] < min(tests), f"{name}: the tests run at steps {tests}, the in-step check at {in_step}"


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


# The Python tools CI and the release install: one file that pins every
# distribution, dependencies included, to a version and its hashes, generated
# by pip-compile --generate-hashes from requirements.in beside it.
REQUIREMENTS = ".github/requirements.txt"
PIP_INSTALL = f"pip install --require-hashes --no-deps -r {REQUIREMENTS}"
REQUIREMENT = re.compile(r"^([A-Za-z0-9._-]+)==([^\s\\]+)")


def test_every_pip_install_takes_the_hash_pinned_file():
    """Every action is pinned to a commit, and the tools that build and test
    the released wheel are pinned as hard: a version alone leaves the file
    behind it, and every unpinned dependency, to whatever the index serves."""
    installs = 0
    for path in workflows():
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in doc["jobs"].values():
            for step in job["steps"]:
                for line in run_lines(step):
                    if re.search(r"\bpip3?\b.*\binstall\b", line):
                        installs += 1
                        assert line == PIP_INSTALL, f"{path.name}: {line!r}; install as {PIP_INSTALL!r}"
    assert installs >= 2, f"examined {installs} pip installs"


def test_the_requirements_pin_every_distribution_to_its_hashes():
    text = (WORKFLOWS.parent / "requirements.txt").read_text(encoding="utf-8")
    entries = re.split(r"\n(?=[A-Za-z0-9])", text.split("\n", 1)[1] if text.startswith("#") else text)
    pinned = {}
    for entry in entries:
        m = REQUIREMENT.match(entry)
        if not m:
            continue
        name, version = m.group(1).lower().replace("_", "-"), m.group(2)
        hashes = re.findall(r"--hash=sha256:[0-9a-f]{64}", entry)
        assert hashes, f"{name}=={version} has no sha256 hash"
        pinned[name] = version
    for tool, version in {"build": "1.6.1", "hatchling": "1.32.4", "pyyaml": "6.0.3", "pytest": "9.1.1"}.items():
        assert pinned.get(tool) == version, f"{tool} is pinned to {pinned.get(tool)}, want {version}"
    assert len(pinned) >= 8, f"examined {len(pinned)} pinned distributions; the tools' dependencies are pinned too"
