"""Checks on what the repository and the Python distribution carry beside the
census: the licence, word for word, and the notice that names whose sentences
the census quotes.

They sit beside the package's tests because ``make test`` runs this directory.
The source distribution leaves this file out (pyproject.toml): it compares the
package's copies with the repository's own, which the distribution does not
carry.
"""

import hashlib
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PACKAGE = REPO / "python"

# The SHA-256 of https://www.apache.org/licenses/LICENSE-2.0.txt, which is also
# the LICENSE of kubernetes/kubernetes, byte for byte. A licence file that
# differs by a word is a modified licence, and license detection reports it as
# NOASSERTION.
APACHE_2_0_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"


def test_the_licence_is_the_apache_2_0_text_word_for_word():
    for path in (REPO / "LICENSE", PACKAGE / "LICENSE"):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == APACHE_2_0_SHA256, f"{path.relative_to(REPO)}: sha256 {digest}"


def test_the_notice_names_the_holder_and_the_package_carries_the_repository_s():
    notice = (REPO / "NOTICE").read_text(encoding="utf-8")
    assert "Copyright 2026 Abdallah Khaldi" in notice
    assert (PACKAGE / "NOTICE").read_bytes() == (REPO / "NOTICE").read_bytes()


def test_the_notice_names_every_publisher_the_census_quotes():
    """Every page a fact cites is on a host the notice names, so a quotation
    never ships without its publisher in the notice."""
    notice = (REPO / "NOTICE").read_text(encoding="utf-8")
    hosts = set(re.findall(r"^\s*-?\s*source: https://([^/\s]+)/", (REPO / "issuers.yaml").read_text(encoding="utf-8"),
                           re.M))
    assert len(hosts) >= 10, f"examined {len(hosts)} hosts"
    missing = sorted(h for h in hosts if h not in notice)
    assert not missing, f"the notice does not name {missing}"


def test_the_distribution_declares_the_licence_and_the_notice():
    pyproject = (PACKAGE / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^license-files = \["LICENSE", "NOTICE"\]$', pyproject, re.M), "license-files"
    sdist = re.search(r"^\[tool\.hatch\.build\.targets\.sdist\]\ninclude = \[([^\]]*)\]", pyproject, re.M)
    assert sdist and {'"LICENSE"', '"NOTICE"'} <= {s.strip() for s in sdist.group(1).split(",")}, "sdist include"
    assert re.search(r'^exclude = \[[^\]]*"tests/test_distribution.py"', pyproject, re.M), \
        "the source distribution carries no repository checks"
