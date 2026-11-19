"""Every labelled sample must produce its expected verdict and findings (see samples/expected.json)."""

from __future__ import annotations

import json

import pytest
from conftest import SAMPLES

from phishcheck.checks import analyse
from phishcheck.parser import iter_file

EXPECTED = json.loads((SAMPLES / "expected.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", sorted(EXPECTED))
def test_sample(path, catalog):
    (email,) = list(iter_file(SAMPLES / path))
    analysis = analyse(email, catalog)
    expected = EXPECTED[path]
    found = {f.check for f in analysis.findings}
    missing = set(expected["findings"]) - found
    assert not missing, f"{path}: missing {missing}; got {sorted(found)}"
    assert analysis.verdict == expected["verdict"], f"{path}: score {analysis.score}, findings {sorted(found)}"


def test_every_sample_is_labelled_as_a_test():
    for path in EXPECTED:
        (email,) = list(iter_file(SAMPLES / path))
        assert email.subject.startswith("[TEST SAMPLE]")
        assert "[TEST SAMPLE]" in email.text


def test_clean_samples_have_no_medium_or_high_findings(catalog):
    for path in (p for p in EXPECTED if p.startswith("clean/")):
        (email,) = list(iter_file(SAMPLES / path))
        severities = {f.severity for f in analyse(email, catalog).findings}
        assert severities <= {"info", "low"}, path
